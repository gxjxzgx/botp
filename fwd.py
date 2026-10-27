#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
转发模块 (从 app.py 拆出, 与 app.py 放在同一目录)

包含两部分:
  1. Python SOCKS5 出站: Xray 默认出站经 127.0.0.1:EGRESS_PORT 由 Python 代连(TCP + UDP ASSOCIATE)
  2. 边缘转发器: cloudflared 经 127.0.0.1:17844~17847 由 Python 连 CF 边缘, 支持 EDGE_PROXY / EDGE_PROXY_FILE

开关和代理配置都在下面的 FORWARD_CONF 里, app.py 不再有任何转发配置。

用法(app.py 已经写好):
    import forward as fwd
    fwd.setup(enable_argo=..., log=log, log_error=log_error, always_log=always_log)
    fwd.start_py_egress()          # 生成 Xray 配置之前
    fwd.start_edge_forwarder()     # 启动 cloudflared 之前, 之后用 fwd.edge_local_addrs 拼 --edge
会被改写的状态一律用 fwd.XXX 读(EGRESS_MODE / EGRESS_PORT / EDGE_PROXY / edge_local_addrs),
不要 from forward import XXX, 否则拿到的是旧值。
"""
import os
import sys
import re
import json
import time
import base64
import socket
import selectors
import errno
import ipaddress
import ssl
import threading
from pathlib import Path
from urllib.parse import urlparse, unquote

# ==================== 转发配置(只在这里改, 环境变量同名可覆盖) ====================
# app.py 发现同目录有本文件就直接启用转发; 临时关闭可设环境变量 USE_FORWARD=false
FORWARD_CONF = {
    'EDGE_PROXY': '',          # cloudflared 连 CF 边缘走的代理, 如 http://user:pass@host:3128 或 socks5://...; 留空读 HTTPS_PROXY/ALL_PROXY/HTTP_PROXY; 读到就走代理(不通再试直连), 读不到直连; 填 0 永不走代理
    'EDGE_PROXY_FILE': '',     # 可选: 代理地址文件(一行, 如 http://user:pass@host:3128)。填了就以文件为准, 代理认证失败(407)时自动重读, 密码轮换不用重启
}

# =========================== 由 setup() 注入 / 计算 ===========================
ENABLE_ARGO = True

def log(msg):
    pass

def log_error(msg):
    pass

def always_log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()

# =========================== 环境变量工具(与 app.py 相同) ===========================
def _env_raw(key, default):
    v = os.environ.get(key)
    if v is None or not str(v).strip():
        return default
    return v

def _env_int(key, default):
    try:
        return int(str(_env_raw(key, default)).strip())
    except (TypeError, ValueError):
        return int(default)

def _env_float(key, default):
    try:
        return float(str(_env_raw(key, default)).strip())
    except (TypeError, ValueError):
        return float(default)

def _env_bool(key, default):
    return str(_env_raw(key, default)).strip().lower() not in ('false', '0', 'no', 'off', 'disable')

# =========================== Python SOCKS5 出站 (Xray 自己出不了站时由 Python 代连) ===========================
EGRESS_MODE = 'direct'                       # setup() 后 = python(经 Python 代连); 出站起不来时退回 direct(Xray 自己直连)
EGRESS_PORT = _env_int('EGRESS_PORT', '10087')          # 本机 SOCKS5 监听端口
BLOCK_QUIC = False         # setup() 后为 True: 走 Python 出站时屏蔽 udp/443(QUIC); 退回 direct 时配置里也不会加这条规则

MAX_CONN = _env_int('MAX_CONN', '512')   # Python 转发(S5 出站 + 边缘转发)同时处理的连接上限, 超出的新连接直接断开, 防线程被打爆
_conn_sem = threading.BoundedSemaphore(max(MAX_CONN, 8))
_conn_full_log = [0.0]

def _guarded(handler, c, extra):
    try:
        handler(c, *extra)
    finally:
        _conn_sem.release()

def _accept_loop(ls, handler, tag, *extra):
    """accept 循环: fd 用尽 / 线程起不来等临时错误只等一下重试, 不让监听线程退出(否则整个出站就断了)"""
    while True:
        try:
            c, _ = ls.accept()
        except OSError as e:
            if e.errno in (errno.EBADF, errno.EINVAL):   # 监听 socket 被关闭
                return
            log_error(f'[{tag}] accept error: {e}')
            time.sleep(0.2)
            continue
        if not _conn_sem.acquire(blocking=False):
            if time.time() - _conn_full_log[0] > 30:
                _conn_full_log[0] = time.time()
                log_error(f'[{tag}] 并发连接已达上限 MAX_CONN={MAX_CONN}, 新连接被拒绝')
            try:
                c.close()
            except Exception:
                pass
            continue
        try:
            threading.Thread(target=_guarded, args=(handler, c, extra), daemon=True).start()
        except Exception as e:
            _conn_sem.release()
            log_error(f'[{tag}] cannot start thread: {e}')
            try:
                c.close()
            except Exception:
                pass
            time.sleep(0.2)

def _s5_recv(sock, n):
    buf = b''
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise ConnectionError('closed')
        buf += d
    return buf

_s5_dns_cache = {}
_s5_dns_lock = threading.Lock()
_s5_dns_refreshing = set()
DNS_CACHE_TTL = _env_int('DNS_CACHE_TTL', '300')          # DNS 缓存秒数
DNS_STALE_MAX = _env_int('DNS_STALE_MAX', '300')         # 过期多久以内仍可先用旧记录

def _s5_lookup(host):
    infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
    ips = []
    for fam, _, _, _, addr in infos:
        if (fam, addr[0]) not in ips:
            ips.append((fam, addr[0]))
    ips.sort(key=lambda x: x[0] != socket.AF_INET)   # IPv4 优先
    with _s5_dns_lock:
        if len(_s5_dns_cache) > 2000:
            _s5_dns_cache.clear()
        _s5_dns_cache[host] = (time.time() + DNS_CACHE_TTL, ips)
    return ips

def _s5_bg_refresh(host):
    try:
        _s5_lookup(host)
    except Exception:
        pass
    finally:
        with _s5_dns_lock:
            _s5_dns_refreshing.discard(host)

def _s5_resolve(host):
    """返回 [(family, ip)]。命中缓存直接返回; 过期但不太旧时先返回旧记录, 后台刷新(不让用户等 DNS)"""
    try:
        ipaddress.ip_address(host)
        return [(socket.AF_INET6 if ':' in host else socket.AF_INET, host)]
    except ValueError:
        pass
    now = time.time()
    with _s5_dns_lock:
        hit = _s5_dns_cache.get(host)
        if hit:
            if hit[0] > now:
                return hit[1]
            if now - hit[0] < DNS_STALE_MAX:
                if host not in _s5_dns_refreshing:
                    _s5_dns_refreshing.add(host)
                    try:
                        threading.Thread(target=_s5_bg_refresh, args=(host,), daemon=True).start()
                    except RuntimeError:
                        _s5_dns_refreshing.discard(host)   # 线程数到上限, 下次再刷新
                return hit[1]
    return _s5_lookup(host)

# ---------- Happy Eyeballs 并行连接 (RFC 8305 简化版) ----------
CONNECT_TIMEOUT = _env_float('CONNECT_TIMEOUT', '5')       # 总连接超时(秒)
CONNECT_STAGGER = _env_float('CONNECT_STAGGER', '0.25')    # 多久没连上就并行尝试下一个 IP

def _happy_connect(ips, port, timeout=None, stagger=None):
    """依次错开 stagger 秒发起连接, 谁先连上用谁, 其余关闭。全部失败抛异常"""
    timeout = CONNECT_TIMEOUT if timeout is None else timeout
    stagger = CONNECT_STAGGER if stagger is None else stagger
    deadline = time.time() + timeout
    pending = {}            # sock -> ip
    sel = selectors.DefaultSelector()   # epoll, 不受 select() 的 fd<1024 限制
    queue = list(ips[:6])
    last_err = None
    next_start = 0.0
    try:
        while True:
            now = time.time()
            if queue and (now >= next_start or not pending):
                fam, ip = queue.pop(0)
                try:
                    sk = socket.socket(fam, socket.SOCK_STREAM)   # 没 IPv6 协议栈 / fd 用尽时会抛错, 换下一个地址
                except OSError as e:
                    last_err = e
                    continue
                sk.setblocking(False)
                addr = (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0)
                rc = sk.connect_ex(addr)
                if rc == 0:
                    sk.setblocking(True)
                    return sk
                if rc not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN):
                    last_err = OSError(rc, os.strerror(rc))
                    sk.close()
                    continue
                pending[sk] = ip
                sel.register(sk, selectors.EVENT_WRITE)
                next_start = now + stagger
            if not pending:
                if not queue:
                    raise last_err or OSError('no address')
                continue
            now = time.time()
            if now >= deadline:
                raise last_err or socket.timeout('connect timeout')
            wait = deadline - now
            if queue:
                wait = min(wait, max(0.0, next_start - now))
            for key, _ in sel.select(wait):
                sk = key.fileobj
                sel.unregister(sk)
                pending.pop(sk, None)
                err = sk.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    sk.setblocking(True)
                    return sk
                last_err = OSError(err, os.strerror(err))
                sk.close()
    finally:
        sel.close()
        for sk in pending:
            try:
                sk.close()
            except Exception:
                pass

def _s5_handle(cli):
    up = None
    relayed = False
    try:
        cli.settimeout(15)
        ver, nm = _s5_recv(cli, 2)
        _s5_recv(cli, nm)
        cli.sendall(b'\x05\x00')
        ver, cmd, _, atyp = _s5_recv(cli, 4)
        if cmd not in (1, 3):   # 1=CONNECT, 3=UDP ASSOCIATE
            cli.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        if atyp == 1:
            host = socket.inet_ntoa(_s5_recv(cli, 4))
        elif atyp == 3:
            host = _s5_recv(cli, _s5_recv(cli, 1)[0]).decode('utf-8', 'ignore')
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, _s5_recv(cli, 16))
        else:
            return
        port = int.from_bytes(_s5_recv(cli, 2), 'big')
        if cmd == 3:
            relayed = True
            _s5_udp_associate(cli)   # 自己负责关闭 cli
            return
        try:
            if EDGE_PROXY:
                # 代理模式: 域名直接塞进 CONNECT, 让代理去解析(绕开本地 DNS sinkhole); 只管 TCP, UDP 不走代理
                up = _edge_proxy_open(host, port, CONNECT_TIMEOUT)
            else:
                ips = _s5_resolve(host)
                try:
                    up = _happy_connect(ips, port)
                except Exception:
                    with _s5_dns_lock:
                        _s5_dns_cache.pop(host, None)   # 可能是旧记录失效, 清掉下次重新解析
                    raise
        except Exception:
            cli.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            return
        cli.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        cli.settimeout(None)
        up.settimeout(None)
        relayed = True
        _relay(cli, up)   # _relay 自己负责关闭两端
        return
    except Exception:
        pass
    finally:
        if not relayed:
            for s in (cli, up):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

# ---------- SOCKS5 UDP ASSOCIATE (RFC 1928 §7) ----------
UDP_IDLE_TIMEOUT = _env_int('UDP_IDLE_TIMEOUT', '60')   # UDP 关联空闲多少秒后回收
UDP_MAX_ASSOC = _env_int('UDP_MAX_ASSOC', '256')        # 同时存在的 UDP 关联上限
_udp_assoc_count = 0
_udp_assoc_lock = threading.Lock()

def _s5_pack_addr(ip, port):
    """把 (ip, port) 编成 SOCKS5 地址段 ATYP+ADDR+PORT"""
    try:
        return b'\x01' + socket.inet_pton(socket.AF_INET, ip) + port.to_bytes(2, 'big')
    except OSError:
        return b'\x04' + socket.inet_pton(socket.AF_INET6, ip) + port.to_bytes(2, 'big')

def _s5_parse_udp(data):
    """解析客户端发来的 UDP 包, 返回 (host, port, addr_bytes, payload); 分片包或格式错误返回 None"""
    if len(data) < 4 or data[2] != 0:      # FRAG != 0 一律丢弃(几乎没有客户端用分片)
        return None
    atyp = data[3]
    i = 4
    if atyp == 1:
        if len(data) < i + 6:
            return None
        host = socket.inet_ntoa(data[i:i + 4])
        i += 4
    elif atyp == 3:
        if len(data) < i + 1:
            return None
        n = data[i]
        i += 1
        if len(data) < i + n + 2:
            return None
        host = data[i:i + n].decode('utf-8', 'ignore')
        i += n
    elif atyp == 4:
        if len(data) < i + 18:
            return None
        host = socket.inet_ntop(socket.AF_INET6, data[i:i + 16])
        i += 16
    else:
        return None
    port = int.from_bytes(data[i:i + 2], 'big')
    return host, port, data[3:i + 2], data[i + 2:]

def _s5_udp_associate(cli):
    global _udp_assoc_count
    with _udp_assoc_lock:
        if _udp_assoc_count >= UDP_MAX_ASSOC:
            full = True
        else:
            full = False
            _udp_assoc_count += 1
    if full:
        try:
            cli.sendall(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        except Exception:
            pass
        try:
            cli.close()
        except Exception:
            pass
        return

    relay = up4 = up6 = None
    sel = selectors.DefaultSelector()
    try:
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.bind(('127.0.0.1', 0))            # 只对本机开放, 不会变成公网 UDP 开放代理
        rport = relay.getsockname()[1]
        cli.sendall(b'\x05\x00\x00\x01' + socket.inet_aton('127.0.0.1') + rport.to_bytes(2, 'big'))
        cli.settimeout(None)

        up4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up4.bind(('0.0.0.0', 0))
        try:
            up6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            up6.bind(('::', 0))
        except OSError:
            up6 = None                          # 机器没 IPv6 就只走 v4

        client_addr = None
        reply_hdr = {}                          # (ip, port) -> 回包时使用的原始地址段(保留域名形式)
        for s in (cli, relay, up4, up6):
            if s:
                sel.register(s, selectors.EVENT_READ)
        last = time.time()

        while True:
            r = {key.fileobj for key, _ in sel.select(5)}
            now = time.time()
            if not r:
                if now - last > UDP_IDLE_TIMEOUT:
                    break
                continue
            last = now
            if cli in r:
                try:
                    if not cli.recv(1):         # TCP 控制连接关闭 = 关联结束
                        break
                except OSError:
                    break
            if relay in r:
                try:
                    data, src = relay.recvfrom(65535)
                except OSError:
                    continue
                if src[0] != '127.0.0.1':
                    continue
                if client_addr is None:
                    client_addr = src
                elif src != client_addr:
                    continue
                parsed = _s5_parse_udp(data)
                if not parsed:
                    continue
                host, port, addr_bytes, payload = parsed
                try:
                    cands = _s5_resolve(host)
                except Exception:
                    continue
                sock = ip = None
                for fam, cip in cands:          # 选第一个本机有对应协议栈的地址(没 IPv6 就用 IPv4)
                    s_ = up4 if fam == socket.AF_INET else up6
                    if s_ is not None:
                        sock, ip = s_, cip
                        break
                if sock is None:
                    continue
                if len(reply_hdr) > 4096:
                    reply_hdr.clear()
                reply_hdr[(ip, port)] = addr_bytes
                try:
                    sock.sendto(payload, (ip, port))
                except OSError:
                    pass
            for sock in (up4, up6):
                if sock and sock in r and client_addr:
                    try:
                        payload, src = sock.recvfrom(65535)
                    except OSError:
                        continue
                    key = (src[0], src[1])
                    hdr = reply_hdr.get(key) or _s5_pack_addr(src[0], src[1])
                    try:
                        relay.sendto(b'\x00\x00\x00' + hdr + payload, client_addr)
                    except OSError:
                        pass
    except Exception as e:
        log(f'[egress-udp] association error: {type(e).__name__}: {e}')
    finally:
        try:
            sel.close()
        except Exception:
            pass
        for s in (cli, relay, up4, up6):
            try:
                if s:
                    s.close()
            except Exception:
                pass
        with _udp_assoc_lock:
            _udp_assoc_count -= 1

def start_py_egress():
    """必须在 generate_xray_config() 之前调用: 端口被占用时自动换端口,
    全部失败则退回 direct 模式, 保证 Xray 配置里的出站端口一定是我们自己在监听的"""
    global EGRESS_PORT, EGRESS_MODE
    if EGRESS_MODE != 'python':
        return
    ls = None
    for port in [EGRESS_PORT] + list(range(EGRESS_PORT + 1, EGRESS_PORT + 3)) + [0]:   # 0 = 让系统分配空闲端口
        try:
            s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s_.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s_.bind(('127.0.0.1', port))
            s_.listen(256)
            ls = s_
            break
        except Exception as e:
            try:
                s_.close()
            except Exception:
                pass
            log_error(f'[egress] bind 127.0.0.1:{port} failed: {e}')
    if ls is None:
        always_log('[egress] 无法监听任何本地端口, 自动退回 direct 模式')
        EGRESS_MODE = 'direct'
        return
    actual = ls.getsockname()[1]
    if actual != EGRESS_PORT:
        always_log(f'[egress] 端口 {EGRESS_PORT} 被占用, 改用 {actual}')
        EGRESS_PORT = actual
    threading.Thread(target=_accept_loop, args=(ls, _s5_handle, 'egress'), daemon=True).start()
    log(f'[egress] python socks5 on 127.0.0.1:{EGRESS_PORT}')

# =========================== 边缘转发器 (让 cloudflared 经 Python 出站) ===========================
# EDGE_PROXY: cloudflared 连 CF 边缘时经代理 (主机只能走代理出网时用), 支持 http:// 和 socks5:// (可带 user:pass@)
# 留空时依次读 HTTPS_PROXY / ALL_PROXY / HTTP_PROXY (大小写都认)
# 读到代理就先走代理, 代理不通再试直连; 读不到就直连; 填 0/false/none/off 永不走代理
def _sys_proxy():
    for k in ('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy'):
        v = str(os.environ.get(k) or '').strip()
        if v:
            return v
    return ''

def _norm_proxy(v):
    v = str(v or '').strip()
    if v and '://' not in v:
        v = 'http://' + v
    return v

EDGE_PROXY_FILE = ''                         # setup() 里赋值
EDGE_PROXY = ''                              # 当前实际使用的代理(直连兜底时为空), setup() 里赋值
_edge_proxy_cfg = ''                         # 配置的代理(可被 EDGE_PROXY_FILE 重读更新)
EDGE_FWD = False                             # setup() 后为 True

def _read_proxy_file():
    """读 EDGE_PROXY_FILE: 取第一行非空、非 # 开头的内容; 读不到返回空"""
    if not EDGE_PROXY_FILE:
        return ''
    try:
        for ln in Path(EDGE_PROXY_FILE).read_text(encoding='utf-8', errors='replace').splitlines():
            ln = ln.strip()
            if ln and not ln.startswith('#'):
                return _norm_proxy(ln)
    except Exception as e:
        log_error(f'[edge-fwd] 读 EDGE_PROXY_FILE 失败: {e}')
    return ''
EDGE_LOCAL_BASE = _env_int('EDGE_LOCAL_BASE', '17844')   # 本地监听起始端口, 共 4 个
EDGE_REMOTE_PORT = _env_int('EDGE_REMOTE_PORT', '7844')
edge_local_addrs = []

_SPLICE_OK = hasattr(os, 'splice') and sys.platform.startswith('linux')
RELAY_SPLICE = _env_bool('RELAY_SPLICE', 'true')

class _NoSplice(Exception):
    """splice 用不了且还没搬过任何数据, 可以安全退回普通拷贝"""
    pass

_NOSPLICE_ERRNO = (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, errno.EMFILE, errno.ENFILE)

def _pump_splice(src, dst):
    """Linux 零拷贝: socket -> pipe -> socket, 数据不进 Python 内存。
    pipe 建不了(fd 耗尽)或内核不支持时抛 _NoSplice; 已经搬过数据后的错误照常抛出"""
    try:
        pr, pw = os.pipe()        # 用默认 64KB 管道: 不调 F_SETPIPE_SZ, 免得连接多了触发 pipe-user-pages 限额
    except OSError as e:
        raise _NoSplice() from e
    moved = False
    try:
        sfd, dfd = src.fileno(), dst.fileno()
        # 注意: 绝不能加 SPLICE_F_MORE, 它等同 TCP_CORK, 小包会被内核攒约 200ms 再发, 延迟暴涨
        flags = getattr(os, 'SPLICE_F_MOVE', 1)
        while True:
            try:
                n = os.splice(sfd, pw, 1 << 18, flags=flags)
            except OSError as e:
                if not moved and e.errno in _NOSPLICE_ERRNO:
                    raise _NoSplice() from e
                raise
            if n == 0:
                return
            moved = True
            while n > 0:
                m = os.splice(pr, dfd, n, flags=flags)
                if m <= 0:
                    raise ConnectionError('splice write 0')
                n -= m
    finally:
        os.close(pr)
        os.close(pw)

RELAY_HALF_CLOSE_TIMEOUT = _env_int('RELAY_HALF_CLOSE_TIMEOUT', '120')   # 一个方向结束后, 另一方向最多再等多少秒
TCP_KEEPALIVE_IDLE = _env_int('TCP_KEEPALIVE_IDLE', '60')                # 空闲多少秒开始发保活探测

def _tune_sock(sk):
    """TCP_NODELAY 降低小包延迟; keepalive + TCP_USER_TIMEOUT 让对端消失(断网/NAT 丢表)的连接最终被内核断开, 线程不会永远卡住"""
    opts = [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)]
    ka_opts = [('TCP_KEEPIDLE', TCP_KEEPALIVE_IDLE), ('TCP_KEEPINTVL', 15), ('TCP_KEEPCNT', 4),
               ('TCP_USER_TIMEOUT', (TCP_KEEPALIVE_IDLE + 60) * 1000)]
    for name, val in ka_opts:
        if hasattr(socket, name):
            opts.append((socket.IPPROTO_TCP, getattr(socket, name), val))
    for lvl, opt, val in opts:
        try:
            sk.setsockopt(lvl, opt, val)
        except Exception:
            pass

def _relay(a, b):
    """双向转发 a<->b: 一侧发完(EOF)只关闭对侧写端; 另一方向在 RELAY_HALF_CLOSE_TIMEOUT 内没结束就强制断开; 出错则整体断开"""
    for sk in (a, b):
        _tune_sock(sk)
    finished = {a: threading.Event(), b: threading.Event()}   # key = 该方向的源 socket

    def _kill():
        for sk in (a, b):
            try:
                sk.shutdown(socket.SHUT_RDWR)   # 能唤醒另一线程里阻塞的 recv/splice
            except Exception:
                pass

    def pump(src, dst):
        _pump_once(src, dst)
        finished[src].set()
        other = b if src is a else a
        if not finished[other].wait(RELAY_HALF_CLOSE_TIMEOUT):
            _kill()

    def _pump_once(src, dst):
        try:
            done = False
            if _SPLICE_OK and RELAY_SPLICE:
                try:
                    _pump_splice(src, dst)
                    done = True
                except _NoSplice:
                    pass               # 不支持或 fd 不够, 退回普通拷贝
            while not done:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass
        except Exception:
            for sk in (src, dst):
                try:
                    sk.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass

    t = threading.Thread(target=pump, args=(a, b), daemon=True)
    t.start()
    pump(b, a)
    t.join()
    for sk in (a, b):
        try:
            sk.close()
        except Exception:
            pass

EDGE_CONNECT_TIMEOUT = _env_float('EDGE_CONNECT_TIMEOUT', '3')     # 连单个边缘 IP 的超时(秒)
EDGE_REFRESH_INTERVAL = _env_int('EDGE_REFRESH_INTERVAL', '300')    # 多久重新解析+探测一次边缘 IP(秒), 失败指数退避(上限 1200), 0=不刷新
EDGE_START_BUDGET = _env_float('EDGE_START_BUDGET', '10')         # 启动时找可用边缘 IP 最多花多少秒(代理+直连合计)
EDGE_RETRY_INTERVAL = 30   # 启动时一个边缘都连不上: 后台每 30 秒重试, 连上后转为正常重探测
_edge_lock = threading.Lock()
_edge_ips = []        # 当前可用的边缘 IP 列表
_edge_primary = {}    # 本地端口 -> 当前主用 IP (粘性: 只有连不上或已不在解析结果里才换)

def _recv_exact(sk, n):
    buf = b''
    while len(buf) < n:
        ch = sk.recv(n - len(buf))
        if not ch:
            raise ConnectionError('proxy closed')
        buf += ch
    return buf

class ProxyAuthError(ConnectionError):
    pass

def _socks5_open(ps, pu, host, port):
    user = unquote(pu.username or '')
    pwd = unquote(pu.password or '')
    ps.sendall(b'\x05\x02\x00\x02' if user else b'\x05\x01\x00')
    ver, method = _recv_exact(ps, 2)
    if ver != 5 or method == 0xFF:
        raise ConnectionError('socks5 no acceptable auth')
    if method == 2:
        ub = user.encode()
        pb = pwd.encode()
        ps.sendall(b'\x01' + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        if _recv_exact(ps, 2)[1] != 0:
            raise ProxyAuthError('socks5 auth failed')
    try:
        addr = b'\x01' + socket.inet_aton(host)
    except OSError:
        hb = host.encode()
        addr = b'\x03' + bytes([len(hb)]) + hb
    ps.sendall(b'\x05\x01\x00' + addr + port.to_bytes(2, 'big'))
    rep = _recv_exact(ps, 4)
    if rep[1] != 0:
        raise ConnectionError(f'socks5 refused: code {rep[1]}')
    if rep[3] == 1:
        _recv_exact(ps, 6)
    elif rep[3] == 4:
        _recv_exact(ps, 18)
    else:
        _recv_exact(ps, _recv_exact(ps, 1)[0] + 2)

def _http_connect_open(ps, pu, host, port):
    hp = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'   # IPv6 字面量要加方括号
    req = f'CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\n'
    if pu.username:
        cred = f'{unquote(pu.username)}:{unquote(pu.password or "")}'
        req += 'Proxy-Authorization: Basic ' + base64.b64encode(cred.encode()).decode() + '\r\n'
    ps.sendall((req + '\r\n').encode())
    head = b''
    while b'\r\n\r\n' not in head:
        ch = ps.recv(1)    # 逐字节读, 不吞掉响应头后面的隧道数据
        if not ch:
            raise ConnectionError('proxy closed')
        head += ch
        if len(head) > 8192:
            raise ConnectionError('proxy header too long')
    first = head.split(b'\r\n', 1)[0].decode('latin-1', 'replace')
    if re.match(r'HTTP/1\.[01] 407', first):
        raise ProxyAuthError(f'proxy auth failed: {first[:80]}')
    if not re.match(r'HTTP/1\.[01] 200', first):
        raise ConnectionError(f'proxy refused: {first[:80]}')

_auth_state = {'until': 0.0, 'wait': 0.0}   # 代理认证失败后的退避: 期间不再拿旧密码打代理
_auth_lock = threading.Lock()

def _proxy_reload():
    """认证失败时重读 EDGE_PROXY_FILE; 读到新地址就换上并返回 True"""
    global EDGE_PROXY, _edge_proxy_cfg
    new = _read_proxy_file()
    with _auth_lock:
        if not new or new == _edge_proxy_cfg:
            return False
        _edge_proxy_cfg = new
        if EDGE_PROXY:
            EDGE_PROXY = new
        _auth_state['until'] = 0.0
        _auth_state['wait'] = 0.0
    always_log('[edge-fwd] 代理认证失败, 已从 EDGE_PROXY_FILE 读到新代理, 换用新密码')
    return True

def _edge_proxy_open(host, port, timeout):
    """经 EDGE_PROXY 连 host:port; 认证失败(407)先重读 EDGE_PROXY_FILE 重试一次, 仍失败就退避(5 秒起翻倍, 最多 300 秒)"""
    if time.time() < _auth_state['until'] and not _proxy_reload():
        raise ProxyAuthError('proxy auth failed (backoff)')
    try:
        ps = _edge_proxy_open_once(host, port, timeout)
    except ProxyAuthError:
        if not _proxy_reload():
            with _auth_lock:
                _auth_state['wait'] = min(max(_auth_state['wait'] * 2, 5), 300)
                _auth_state['until'] = time.time() + _auth_state['wait']
            log_error(f"[edge-fwd] 代理认证失败, {int(_auth_state['wait'])} 秒内不再重试" + ('' if EDGE_PROXY_FILE else ' (可设 EDGE_PROXY_FILE 让密码轮换后自动重读)'))
            raise
        try:
            ps = _edge_proxy_open_once(host, port, timeout)
        except ProxyAuthError:
            with _auth_lock:
                _auth_state['wait'] = min(max(_auth_state['wait'] * 2, 5), 300)
                _auth_state['until'] = time.time() + _auth_state['wait']
            log_error(f"[edge-fwd] 新代理密码也认证失败, {int(_auth_state['wait'])} 秒内不再重试")
            raise
    with _auth_lock:
        _auth_state['wait'] = 0.0
    return ps

def _edge_proxy_open_once(host, port, timeout):
    """经 EDGE_PROXY (http CONNECT 或 socks5) 连 host:port, 成功返回已打通的 socket"""
    pu = urlparse(EDGE_PROXY)
    is_socks = pu.scheme.lower().startswith('socks')
    ps = socket.create_connection((pu.hostname, pu.port or (1080 if is_socks else 3128)), timeout=timeout)
    try:
        if is_socks:
            _socks5_open(ps, pu, host, port)
        else:
            _http_connect_open(ps, pu, host, port)
        return ps
    except Exception:
        ps.close()
        raise

def _edge_open(ip, timeout):
    if EDGE_PROXY:
        return _edge_proxy_open(ip, EDGE_REMOTE_PORT, timeout)
    return socket.create_connection((ip, EDGE_REMOTE_PORT), timeout=timeout)

EDGE_HOSTS = ('region1.v2.argotunnel.com', 'region2.v2.argotunnel.com')

def _parallel(fn, items, wait):
    """并行跑 fn(item), 最多等 wait 秒, 超时的当失败; 返回 [(item, 结果或 None)]"""
    res = [None] * len(items)

    def _one(i, it):
        try:
            res[i] = fn(it)
        except Exception as e:
            log(f'[edge-fwd] {fn.__name__} {it} failed: {type(e).__name__}: {e}')

    ths = [threading.Thread(target=_one, args=(i, it), daemon=True) for i, it in enumerate(items)]
    for th in ths:
        th.start()
    end = time.time() + max(wait, 0.1)
    for th in ths:
        th.join(max(end - time.time(), 0))
    return list(zip(items, list(res)))

def _edge_doh(host):
    """经 EDGE_PROXY 用 DoH(1.1.1.1) 查 A 记录; 代理环境下本机 DNS 常常不通"""
    raw = _edge_proxy_open('1.1.1.1', 443, 4)
    raw.settimeout(5)
    ts = ssl.create_default_context().wrap_socket(raw, server_hostname='1.1.1.1')
    try:
        ts.sendall(f'GET /dns-query?name={host}&type=A HTTP/1.0\r\nHost: 1.1.1.1\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n'.encode())
        body = b''
        while True:
            ch = ts.recv(65536)
            if not ch:
                break
            body += ch
    finally:
        ts.close()
    head, _, payload = body.partition(b'\r\n\r\n')
    if not re.match(rb'HTTP/1\.[01] 200', head):
        raise ConnectionError(f'doh http: {repr(head[:40])}')
    data = json.loads(payload.decode())
    return [a['data'] for a in data.get('Answer', []) if a.get('type') == 1]

def _edge_dns(host):
    return [a[4][0] for a in socket.getaddrinfo(host, EDGE_REMOTE_PORT, socket.AF_INET, socket.SOCK_STREAM)]

def _edge_lookup(task):
    fn, host = task
    try:
        return fn(host)
    except Exception as e:
        log(f'[edge-fwd] {fn.__name__.strip("_")} {host} failed: {type(e).__name__}: {e}')
        return None

# 解析结果过滤: 回环/组播/保留地址永远不要; 走代理时内网和 fake-ip(198.18/15) 代理也连不到, 一并去掉
_EDGE_BAD_NETS = [ipaddress.ip_network(n) for n in ('0.0.0.0/8', '127.0.0.0/8', '224.0.0.0/3')]
_EDGE_BAD_NETS_PROXY = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '198.18.0.0/15')]

def _edge_ip_ok(ip):
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    nets = _EDGE_BAD_NETS + (_EDGE_BAD_NETS_PROXY if EDGE_PROXY else [])
    return not any(a in n for n in nets)

def _edge_resolve(wait=8):
    """两个域名同时解析, 最多等 wait 秒; 代理模式下 DoH 和本机 DNS 同时查, 优先用 DoH 的结果"""
    funcs = (_edge_doh, _edge_dns) if EDGE_PROXY else (_edge_dns,)
    tasks = [(fn, h) for fn in funcs for h in EDGE_HOSTS]
    done = _parallel(_edge_lookup, tasks, wait)
    for fn in funcs:
        ips = []
        bad = []
        for (f, _), r in done:
            if f is fn:
                for ip in r or []:
                    if not _edge_ip_ok(ip):
                        bad.append(ip)
                    elif ip not in ips:
                        ips.append(ip)
        if bad:
            log(f'[edge-fwd] 丢弃无效解析结果: {sorted(set(bad))[:6]}')
        if ips:
            return ips
    return []

_edge_rtt = {}        # 边缘 IP -> 最近一次探测的连接耗时(秒)
EDGE_PROBE_TLS = _env_raw('EDGE_PROBE_TLS', '1').strip().lower() not in ('0', 'false', 'no', 'off')   # 探测要完成 TLS 握手才算通(防网关假 SYN-ACK / 代理 200 后黑洞); 0=只看 TCP
EDGE_PROBE_SNI = 'probe.cftunnel.com'   # cloudflared 自己做连通性预检用的 SNI

def _edge_probe_one(ip):
    t = time.time()
    raw = _edge_open(ip, EDGE_CONNECT_TIMEOUT)
    try:
        if EDGE_PROBE_TLS:
            raw.settimeout(EDGE_CONNECT_TIMEOUT)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE     # cloudflared 用自带 CA 校验, 这里只确认对端真的会 TLS 握手
            ctx.wrap_socket(raw, server_hostname=EDGE_PROBE_SNI).close()
    finally:
        try:
            raw.close()
        except Exception:
            pass
    return time.time() - t

def _edge_probe(ips, wait):
    """并行探测, 最多等 wait 秒(7844 被封时只等一个超时); 返回能连上的 IP, 按连接耗时从快到慢排序"""
    res = sorted((rtt, ip) for ip, rtt in _parallel(_edge_probe_one, ips[:8], wait) if rtt is not None)
    with _edge_lock:
        for rtt, ip in res:
            _edge_rtt[ip] = rtt
    if res:
        log('[edge-fwd] 探测耗时: ' + ', '.join(f'{ip} {rtt * 1000:.0f}ms' for rtt, ip in res[:6]))
    return [ip for _, ip in res]

def _edge_serve(listener, port):
    _accept_loop(listener, _edge_conn, 'edge-fwd', port)

def _edge_conn(cli, port):
    """先连该端口的主用 IP; 失败才依次试其它 IP, 成功的那个成为新的主用 IP。已建立的连接不受影响"""
    with _edge_lock:
        primary = _edge_primary.get(port)
        cands = [primary] + [ip for ip in _edge_ips if ip != primary] if primary else list(_edge_ips)
    for ip in cands[:3]:      # 最多试 3 个, 免得代理慢时单个连接拖太久(cloudflared 自己也会重连)
        try:
            up = _edge_open(ip, EDGE_CONNECT_TIMEOUT)
            up.settimeout(None)
        except Exception as e:
            log(f'[edge-fwd] connect {ip}:{EDGE_REMOTE_PORT} failed: {type(e).__name__}: {e}')
            continue
        if ip != primary:
            with _edge_lock:
                _edge_primary[port] = ip
            always_log(f'[edge-fwd] 127.0.0.1:{port} 主用边缘 {primary or "(无)"} 不通, 切换到 {ip}')
        _relay(cli, up)
        return
    try:
        cli.close()
    except Exception:
        pass

def _edge_refresh_loop(retry):
    """后台重探测: 定期重新解析+探测, 不通的主用 IP 在线替换, 已建立的连接不受影响。
    失败指数退避(上限 1200 秒), 保留旧映射继续服务。retry=True 表示启动时一个都没连上, 先每 30 秒重试"""
    global _edge_ips, EDGE_PROXY
    fails = 0
    while retry or EDGE_REFRESH_INTERVAL > 0:
        if retry:
            time.sleep(EDGE_RETRY_INTERVAL)
        else:
            time.sleep(min(EDGE_REFRESH_INTERVAL * (2 ** fails), max(EDGE_REFRESH_INTERVAL, 1200)))
        try:
            ips = _edge_resolve(8)
            with _edge_lock:
                in_use = [ip for ip in _edge_primary.values() if ip]
            cands = list(dict.fromkeys(in_use + ips))
            working = _edge_probe(cands, EDGE_CONNECT_TIMEOUT * 2 + 1)
        except Exception as e:
            working = []
            log(f'[edge-fwd] reprobe error: {type(e).__name__}: {e}')
        if not working and _edge_proxy_cfg:
            # 当前方式(代理或直连)都不通: 试另一种, 通了就切过去(代理恢复后切回代理, 直连恢复后切回直连)
            saved = EDGE_PROXY
            EDGE_PROXY = '' if saved else _edge_proxy_cfg
            try:
                cands = _edge_resolve(8)
                working = _edge_probe(cands, EDGE_CONNECT_TIMEOUT * 2 + 1)
            except Exception:
                working = []
            if working:
                always_log('[edge-fwd] ' + ('代理不通, 直连可用, 改为直连' if saved else '直连不通, 代理可用, 改为走代理'))
                with _edge_lock:
                    for port in _edge_primary:
                        _edge_primary[port] = None   # 旧方式下的主用 IP 作废, 下面重新分配
            else:
                EDGE_PROXY = saved
        if not working:
            fails = min(fails + 1, 10)
            log(f'[edge-fwd] 重探测没找到可用边缘 IP (连续 {fails} 次), 保留旧映射')
            continue
        if retry:
            always_log(f'[edge-fwd] 已连上 CF 边缘: {working[:4]}')
        fails = 0
        retry = False
        with _edge_lock:
            _edge_ips = working + [ip for ip in cands if ip not in working]
            for i, port in enumerate(sorted(_edge_primary)):
                old = _edge_primary[port]
                if old in working:
                    used = set(_edge_primary.values())
                    free = [ip for ip in working if ip not in used]
                    # 主用 IP 还通但明显变慢(比最快的空闲 IP 慢一倍且多 50ms 以上), 新连接改用快的; 已建立的连接不受影响
                    if free and _edge_rtt.get(old, 0) > 2 * _edge_rtt.get(free[0], 0) + 0.05:
                        _edge_primary[port] = free[0]
                        always_log(f"[edge-fwd] 127.0.0.1:{port} {old} 变慢({_edge_rtt[old] * 1000:.0f}ms), 换成 {free[0]}({_edge_rtt[free[0]] * 1000:.0f}ms)")
                    continue
                used = set(_edge_primary.values())
                free = [ip for ip in working if ip not in used]
                _edge_primary[port] = free[0] if free else working[i % len(working)]
                if old:
                    always_log(f'[edge-fwd] 127.0.0.1:{port} {old} 探测不通, 换成 {_edge_primary[port]}')

def start_edge_forwarder():
    """用 Python 解析并连接 CF 边缘, 在本机 127.0.0.1 开 4 个端口; 返回 cloudflared 的 --edge 参数。
    有代理先走代理, 不通再试直连; 整个过程最多 EDGE_START_BUDGET 秒"""
    global edge_local_addrs, _edge_ips, EDGE_PROXY
    if not (ENABLE_ARGO and EDGE_FWD):
        return ''
    want = EDGE_PROXY
    t0 = time.time()
    ips = []
    working = []
    modes = [want, ''] if want else ['']
    for n, mode in enumerate(modes):
        EDGE_PROXY = _edge_proxy_cfg if mode else ''   # 代理阶段用最新的配置(期间可能已从 EDGE_PROXY_FILE 重读)
        # 有代理时代理阶段用 60% 预算, 留 40% 给直连兜底
        end = t0 + EDGE_START_BUDGET * (0.6 if (mode and n == 0) else 1.0)
        if end - time.time() < 1:
            break
        ips = _edge_resolve((end - time.time()) / 2)
        working = _edge_probe(ips, end - time.time())
        if working:
            break
        if mode:
            always_log('[edge-fwd] 经代理连不上 CF 边缘, 试直连')
    if working and want and not EDGE_PROXY:
        always_log('[edge-fwd] 代理不通但直连可用, 改为直连')
    retry = False
    if not working:
        if not want:
            log('[edge-fwd] no reachable edge IP, skip forwarder')
            return ''
        # 有代理的环境(如封闭沙盒)直连本来就不通: 先把转发端口开起来, 后台重试连上后 cloudflared 自动重连成功
        EDGE_PROXY = _edge_proxy_cfg
        retry = True
        always_log(f'[edge-fwd] 启动时代理和直连都连不上 CF 边缘, 先开转发端口, 后台每 {EDGE_RETRY_INTERVAL} 秒重试')
    with _edge_lock:
        _edge_ips = working + [ip for ip in ips if ip not in working]   # 探测通过的排前面, 其余留作备用
    edge_local_addrs = []
    for i in range(4):
        ip = working[i % len(working)] if working else None
        port = EDGE_LOCAL_BASE + i
        try:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind(('127.0.0.1', port))
            ls.listen(64)
        except Exception as e:
            log(f'[edge-fwd] bind 127.0.0.1:{port} failed: {e}')
            continue
        with _edge_lock:
            _edge_primary[port] = ip
        threading.Thread(target=_edge_serve, args=(ls, port), daemon=True).start()
        edge_local_addrs.append(f'127.0.0.1:{port}')
        log(f'[edge-fwd] 127.0.0.1:{port} -> {ip or "(待重试)"}:{EDGE_REMOTE_PORT}' + (' (via proxy)' if EDGE_PROXY else ''))
    if edge_local_addrs:
        threading.Thread(target=_edge_refresh_loop, args=(retry,), daemon=True).start()
    log(f'[edge-fwd] 启动耗时 {time.time() - t0:.1f}s')
    return ' '.join(f'--edge {a}' for a in edge_local_addrs)


# =========================== 初始化 ===========================
def setup(enable_argo=True, log=None, log_error=None, always_log=None):
    """由 app.py 在启动时调用一次: 传入 ENABLE_ARGO 和日志函数; 转发相关配置都读本文件的 FORWARD_CONF / 环境变量"""
    global ENABLE_ARGO, EGRESS_MODE, BLOCK_QUIC, EDGE_FWD
    global EDGE_PROXY, EDGE_PROXY_FILE, _edge_proxy_cfg
    g = globals()
    for name, fn in (('log', log), ('log_error', log_error), ('always_log', always_log)):
        if fn is not None:
            g[name] = fn
    ENABLE_ARGO = bool(enable_argo)
    EGRESS_MODE = 'python'
    BLOCK_QUIC = True   # 走 Python 出站时屏蔽 udp/443(QUIC)
    EDGE_FWD = True
    EDGE_PROXY_FILE = str(_env_raw('EDGE_PROXY_FILE', FORWARD_CONF['EDGE_PROXY_FILE'] or '')).strip()
    ep = str(_env_raw('EDGE_PROXY', FORWARD_CONF['EDGE_PROXY'] or '')).strip()
    if ep.lower() in ('0', 'false', 'none', 'off', 'no'):
        EDGE_PROXY = ''
    else:
        EDGE_PROXY = _read_proxy_file() or _norm_proxy(ep or _sys_proxy())
    _edge_proxy_cfg = EDGE_PROXY
    always_log('[forward] 检测到 forward.py, 已启用转发')

def reserved_ports():
    """自动分配端口时要避开的本地端口(出站 3 个候选 + 边缘转发 4 个)"""
    return [EGRESS_PORT, EGRESS_PORT + 1, EGRESS_PORT + 2] + [EDGE_LOCAL_BASE + i for i in range(4)]
