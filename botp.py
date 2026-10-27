# cf-probe (Python): CF-Server-Monitor 探针, 纯 Python 读 /proc 上报, 不需要 root/systemd/二进制。
# 本文件不含任何密钥或上报地址, 配置全部由调用方传入:
#   import probe; probe.start({'PROBE_ID': ..., 'PROBE_SECRET': ..., 'PROBE_URL': ...}, logger)
# 也可单独运行: PROBE_ID=xx PROBE_SECRET=xx PROBE_URL=https://.../update python3 probe.py
import os
import sys
import re
import json
import time
import socket
import platform
import threading
import subprocess
import urllib.request
import ipaddress
from urllib.parse import urlparse

try:
    import websocket as _ws_client  # websocket-client; 实时 WSS 上报, 缺失时自动安装
    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False

import logging

# ---- 默认配置(start() 传入的 cfg 覆盖; 单独运行时读同名环境变量) ----
def _env_int(key, default):
    try:
        return int(str(os.environ.get(key) or default).strip())
    except (TypeError, ValueError):
        return int(default)


def _env_float(key, default):
    try:
        return float(str(os.environ.get(key) or default).strip())
    except (TypeError, ValueError):
        return float(default)


PROBE_ID = os.environ.get('PROBE_ID', '')
PROBE_SECRET = os.environ.get('PROBE_SECRET', '')
PROBE_URL = os.environ.get('PROBE_URL', '')
PROBE_INTERVAL = _env_int('PROBE_INTERVAL', 60)
PROBE_CT = os.environ.get('PROBE_CT', 'gd-ct-dualstack.ip.zstaticcdn.com')
PROBE_CU = os.environ.get('PROBE_CU', 'gd-cu-dualstack.ip.zstaticcdn.com')
PROBE_CM = os.environ.get('PROBE_CM', 'gd-cm-dualstack.ip.zstaticcdn.com')
PROBE_PING_COUNT = _env_int('PROBE_PING_COUNT', 2)
PROBE_PING_TIMEOUT = _env_float('PROBE_PING_TIMEOUT', 1.0)
PROBE_IP_REFRESH_INTERVAL = _env_int('PROBE_IP_REFRESH_INTERVAL', 1800)
PROBE_WSS = os.environ.get('PROBE_WSS', 'true').lower() not in ('false', '0', 'no', 'disable')
PROBE_PING_CACHE_TTL = _env_int('PROBE_PING_CACHE_TTL', 120)
logger = logging.getLogger('cf-probe')

_CFG_KEYS = ('PROBE_ID', 'PROBE_SECRET', 'PROBE_URL', 'PROBE_INTERVAL', 'PROBE_CT', 'PROBE_CU', 'PROBE_CM',
             'PROBE_PING_COUNT', 'PROBE_PING_TIMEOUT', 'PROBE_IP_REFRESH_INTERVAL', 'PROBE_WSS',
             'PROBE_PING_CACHE_TTL', 'PROBE_AGENT_VERSION', 'PROBE_WATCHDOG', 'PROBE_WATCHDOG_MISS')

# 看门狗状态: gen 每次重启 +1, 旧循环发现 gen 变了就自行退出; last_ok 为最近一次上报成功时间
_wd = {'gen': 0, 'last_ok': 0.0, 'thread': None, 'ws': None, 'lock': threading.Lock(), 'restarts': 0}
PROBE_WATCHDOG = os.environ.get('PROBE_WATCHDOG', 'true').lower() not in ('false', '0', 'no', 'disable')  # 看门狗开关
PROBE_WATCHDOG_MISS = _env_int('PROBE_WATCHDOG_MISS', 5)  # 连续多少个上报周期没成功就重启上报循环
_ws_install_tried = False


def _wd_ok():
    _wd['last_ok'] = time.time()


def _wd_alive(gen):
    return _wd['gen'] == gen


def _wd_sleep(sec, gen):
    # 分段睡眠, 被看门狗换代后尽快退出
    end = time.time() + sec
    while _wd['gen'] == gen:
        left = end - time.time()
        if left <= 0:
            return True
        time.sleep(min(1.0, left))
    return False


_probe_ping_cache = {
    'ts': 0,
    'ping_ct': None, 'loss_ct': None,
    'ping_cu': None, 'loss_cu': None,
    'ping_cm': None, 'loss_cm': None,
}

# =========================== 探针 (CF-Server-Monitor) ===========================
def _http_get_text(url, timeout=3):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode('utf-8', 'ignore')

def _looks_like_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _fetch_public_ip_version(version='v4', timeout=3):
    host = 'ipv4.ip.sb' if version == 'v4' else 'ipv6.ip.sb'
    try:
        ip = _http_get_text(f'http://{host}', timeout).strip()
        if ip and _looks_like_ip(ip):
            return ip
    except Exception:
        pass
    return None

def _probe_read_cpu_times():
    with open('/proc/stat') as f:
        parts = f.readline().split()
    nums = list(map(int, parts[1:9]))
    idle = nums[3] + nums[4]
    total = sum(nums)
    return idle, total

def _probe_cpu_percent(prev_idle, prev_total):
    idle, total = _probe_read_cpu_times()
    d_idle = idle - prev_idle
    d_total = total - prev_total
    if d_total <= 0:
        return 0.0, idle, total
    usage = (1 - d_idle / d_total) * 100
    return round(max(0.0, min(100.0, usage)), 2), idle, total

def _probe_read_host_meminfo():
    info = {}
    with open('/proc/meminfo') as f:
        for line in f:
            key, val = line.split(':', 1)
            info[key.strip()] = int(val.strip().split()[0])
    ram_total = info.get('MemTotal', 0) // 1024
    ram_free = info.get('MemAvailable', info.get('MemFree', 0)) // 1024
    ram_used = max(0, ram_total - ram_free)
    swap_total = info.get('SwapTotal', 0) // 1024
    swap_free = info.get('SwapFree', 0) // 1024
    swap_used = max(0, swap_total - swap_free)
    return ram_total, ram_used, swap_total, swap_used

def _probe_read_cgroup_memory():
    try:
        with open('/sys/fs/cgroup/memory.current') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory.max') as f:
            raw = f.read().strip()
        limit = None if raw == 'max' else int(raw)
        swap_used = swap_total = 0
        try:
            with open('/sys/fs/cgroup/memory.swap.current') as f:
                swap_used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory.swap.max') as f:
                raw_sw = f.read().strip()
            swap_total = None if raw_sw == 'max' else int(raw_sw)
        except OSError:
            pass
        return used, limit, swap_used, swap_total
    except OSError:
        pass
    try:
        with open('/sys/fs/cgroup/memory/memory.usage_in_bytes') as f:
            used = int(f.read().strip())
        with open('/sys/fs/cgroup/memory/memory.limit_in_bytes') as f:
            limit = int(f.read().strip())
        if limit > (1 << 62):
            limit = None
        swap_used = swap_total = 0
        try:
            with open('/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes') as f:
                memsw_used = int(f.read().strip())
            with open('/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes') as f:
                memsw_limit = int(f.read().strip())
            swap_used = max(0, memsw_used - used)
            if memsw_limit <= (1 << 62) and limit is not None:
                swap_total = max(0, memsw_limit - limit)
        except OSError:
            pass
        return used, limit, swap_used, swap_total
    except OSError:
        pass
    return None, None, None, None

def _probe_read_meminfo():
    used, limit, swap_used, swap_total = _probe_read_cgroup_memory()
    if used is not None and limit:
        ram_total = limit // (1024 * 1024)
        ram_used = min(used // (1024 * 1024), ram_total)
        swap_total_mb = (swap_total or 0) // (1024 * 1024)
        swap_used_mb = min((swap_used or 0) // (1024 * 1024), swap_total_mb) if swap_total_mb else 0
        return ram_total, ram_used, swap_total_mb, swap_used_mb
    return _probe_read_host_meminfo()

def _probe_read_disk_usage(path='/'):
    st = os.statvfs(path)
    total = st.f_blocks * st.f_frsize
    free = st.f_bavail * st.f_frsize
    used = total - free
    return total // (1024 * 1024), used // (1024 * 1024)

def _probe_read_net_bytes():
    rx_total = tx_total = 0
    with open('/proc/net/dev') as f:
        lines = f.readlines()[2:]
    for line in lines:
        iface, rest = line.split(':', 1)
        if iface.strip() == 'lo':
            continue
        fields = rest.split()
        rx_total += int(fields[0])
        tx_total += int(fields[8])
    return rx_total, tx_total

def _probe_read_boot_time_ms():
    with open('/proc/stat') as f:
        for line in f:
            if line.startswith('btime'):
                return int(line.split()[1]) * 1000
    return 0

def _probe_read_os_name():
    try:
        info = {}
        with open('/etc/os-release') as f:
            for line in f:
                line = line.strip()
                if not line or '=' not in line:
                    continue
                key, val = line.split('=', 1)
                info[key] = val.strip('"')
        pretty = info.get('PRETTY_NAME')
        if pretty:
            return pretty
        name = info.get('NAME')
        version = info.get('VERSION') or info.get('VERSION_ID')
        if name:
            return f'{name} {version}'.strip() if version else name
    except OSError:
        pass
    return f'{platform.system()} {platform.release()}'

def _probe_read_cpu_info():
    model = ''
    try:
        with open('/proc/cpuinfo') as f:
            for line in f:
                if line.lower().startswith('model name'):
                    model = line.split(':', 1)[1].strip()
                    break
    except OSError:
        pass
    return model or platform.processor() or 'unknown'

def _probe_read_process_count():
    try:
        return sum(1 for p in os.listdir('/proc') if p.isdigit())
    except OSError:
        return 0

def _probe_read_conn_count(proto):
    # 同时统计 IPv4 和 IPv6 (tcp + tcp6 / udp + udp6)
    total = 0
    for name in (proto, proto + '6'):
        try:
            with open(f'/proc/net/{name}') as f:
                total += max(0, sum(1 for _ in f) - 1)
        except OSError:
            pass
    return total

def _probe_load_avg():
    la = os.getloadavg()
    return f'{la[0]:.2f} {la[1]:.2f} {la[2]:.2f}'

_probe_ip_cache = {'v4': '0', 'v6': '0', 'ts': 0}

def _probe_get_public_ips():
    now = time.time()
    if now - _probe_ip_cache['ts'] < PROBE_IP_REFRESH_INTERVAL and _probe_ip_cache['ts'] > 0:
        return _probe_ip_cache['v4'], _probe_ip_cache['v6']

    v4 = _fetch_public_ip_version('v4') or '0'
    v6 = _fetch_public_ip_version('v6') or '0'

    _probe_ip_cache['v4'] = v4
    _probe_ip_cache['v6'] = v6
    _probe_ip_cache['ts'] = now
    return v4, v6

def _probe_parse_host_port(target, default_port=80):
    target = (target or '').strip()
    if not target:
        return None, None
    if target.startswith('['):
        m = re.match(r'^\[([^\]]+)\](?::(\d+))?$', target)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else default_port
        return target.strip('[]'), default_port
    if ':' in target and target.count(':') == 1:
        host, port = target.split(':', 1)
        try:
            return host, int(port)
        except ValueError:
            return target, default_port
    return target, default_port

def _probe_tcp_ping(target, count=4, timeout=1.5):
    host, port = _probe_parse_host_port(target, default_port=443)
    if not host:
        return None, None
    times = []
    failures = 0
    for _ in range(max(1, count)):
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.time() - start) * 1000)
        except OSError:
            failures += 1
    total = max(1, count)
    loss = round(failures / total * 100, 2)
    if not times:
        return None, loss
    return round(sum(times) / len(times), 2), loss

def _probe_collect(prev_idle, prev_total, prev_rx, prev_tx, prev_ts):
    cpu, idle, total = _probe_cpu_percent(prev_idle, prev_total)
    ram_total, ram_used, swap_total, swap_used = _probe_read_meminfo()
    disk_total, disk_used = _probe_read_disk_usage('/')
    rx, tx = _probe_read_net_bytes()

    now = time.time()
    dt = max(1e-6, now - prev_ts)
    rx_speed = max(0, int((rx - prev_rx) / dt))
    tx_speed = max(0, int((tx - prev_tx) / dt))

    metrics = {
        'cpu': cpu,
        'ram_total': ram_total,
        'ram_used': ram_used,
        'swap_total': swap_total,
        'swap_used': swap_used,
        'disk_total': disk_total,
        'disk_used': disk_used,
        'load_avg': _probe_load_avg(),
        'boot_time': str(_probe_read_boot_time_ms()),
        'net_rx': str(rx),
        'net_tx': str(tx),
        'net_rx_monthly': str(rx),
        'net_tx_monthly': str(tx),
        'net_in_speed': str(rx_speed),
        'net_out_speed': str(tx_speed),
        'os': _probe_read_os_name(),
        'arch': platform.machine(),
        'kernel_version': platform.release(),
        'cpu_info': _probe_read_cpu_info(),
        'cpu_cores': str(os.cpu_count() or 1),
        'processes': str(_probe_read_process_count()),
        'tcp_conn': str(_probe_read_conn_count('tcp')),
        'udp_conn': str(_probe_read_conn_count('udp')),
        'version': PROBE_AGENT_VERSION,
        'agent_version': PROBE_AGENT_VERSION,
    }

    ip_v4, ip_v6 = _probe_get_public_ips()
    metrics['ip_v4'] = ip_v4
    metrics['ip_v6'] = ip_v6

    # 三网 ping 降频：缓存未过期则复用
    if now - _probe_ping_cache['ts'] >= PROBE_PING_CACHE_TTL:
        if PROBE_CT:
            ping_ct, loss_ct = _probe_tcp_ping(PROBE_CT, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_ct'] = ping_ct
            _probe_ping_cache['loss_ct'] = loss_ct
        if PROBE_CU:
            ping_cu, loss_cu = _probe_tcp_ping(PROBE_CU, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_cu'] = ping_cu
            _probe_ping_cache['loss_cu'] = loss_cu
        if PROBE_CM:
            ping_cm, loss_cm = _probe_tcp_ping(PROBE_CM, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)
            _probe_ping_cache['ping_cm'] = ping_cm
            _probe_ping_cache['loss_cm'] = loss_cm
        _probe_ping_cache['ts'] = now

    if PROBE_CT:
        metrics['ping_ct'] = _probe_ping_cache['ping_ct']
        metrics['loss_ct'] = _probe_ping_cache['loss_ct']
    if PROBE_CU:
        metrics['ping_cu'] = _probe_ping_cache['ping_cu']
        metrics['loss_cu'] = _probe_ping_cache['loss_cu']
    if PROBE_CM:
        metrics['ping_cm'] = _probe_ping_cache['ping_cm']
        metrics['loss_cm'] = _probe_ping_cache['loss_cm']

    return metrics, idle, total, rx, tx, now

PROBE_AGENT_VERSION = os.environ.get('PROBE_AGENT_VERSION', 'python')

def _probe_report(metrics):
    try:
        body = json.dumps({'id': PROBE_ID, 'secret': PROBE_SECRET, 'metrics': metrics}).encode()
        req = urllib.request.Request(PROBE_URL, data=body, method='POST', headers={
            'Content-Type': 'application/json',
            'X-Agent-Version': PROBE_AGENT_VERSION,
        })
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode('utf-8', 'ignore')
            logger.info(f'[probe] report -> HTTP {resp.status}' + (f': {text[:200]}' if text else ''))
            if 200 <= resp.status < 300:
                _wd_ok()
                return True
    except Exception as e:
        logger.error(f'[probe] report failed: {e}')
    return False

def start_probe_loop(gen=None):
    gen = _wd['gen'] if gen is None else gen

    def loop():
        idle, total = _probe_read_cpu_times()
        rx, tx = _probe_read_net_bytes()
        ts = time.time()
        logger.info(f'[probe] reporting to {PROBE_URL} every {PROBE_INTERVAL}s')
        while _wd_sleep(PROBE_INTERVAL, gen):
            try:
                metrics, idle_, total_, rx_, tx_, ts_ = _probe_collect(idle, total, rx, tx, ts)
                idle, total, rx, tx, ts = idle_, total_, rx_, tx_, ts_
                logger.debug(f'[probe] metrics: {json.dumps(metrics, ensure_ascii=False)}')
                _probe_report(metrics)
            except Exception as e:
                logger.error(f'[probe] collection failed: {e}')

    t = threading.Thread(target=loop, daemon=True, name=f'cf-probe-post-{gen}')
    _wd['thread'] = t
    t.start()

# =========================== 探针 WSS 实时上报 ===========================
def _pip_install(package):
    """用当前解释器的pip安装package,先尝试普通安装,PEP668环境(externally-managed-environment)
    再补--break-system-packages重试一次;返回(是否成功, 最后一次报错信息)"""
    py = sys.executable
    in_venv = sys.prefix != getattr(sys, 'base_prefix', sys.prefix)
    if in_venv:
        # 虚拟环境里 --user 必然报错, 直接装进 venv
        attempts = [[py, '-m', 'pip', 'install', '-q', package]]
    else:
        attempts = [
            [py, '-m', 'pip', 'install', '--user', '-q', package],
            [py, '-m', 'pip', 'install', '--user', '--break-system-packages', '-q', package],
        ]
    last_err = ''
    for cmd in attempts:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            if result.returncode == 0:
                return True, ''
            last_err = (result.stderr or result.stdout or '').strip()
        except Exception as e:
            last_err = str(e)
    return False, last_err

def _ensure_ws_client():
    """确保 websocket-client 可用;缺失时尝试自动pip安装并在当前进程内直接加载,无需重启"""
    global _ws_client, _WS_AVAILABLE, _ws_install_tried
    if _WS_AVAILABLE:
        return True
    if _ws_install_tried:  # 看门狗重启时不重复 pip 安装
        return False
    _ws_install_tried = True

    logger.info('[probe] websocket-client not found, attempting automatic install for real-time WSS reporting...')
    ok, err = _pip_install('websocket-client')
    if not ok:
        logger.error(f'[probe] automatic install failed, staying on POST polling: {err[:300]}')
        return False

    try:
        import site
        import importlib
        user_site = site.getusersitepackages()
        if user_site and user_site not in sys.path:
            sys.path.insert(0, user_site)
        importlib.invalidate_caches()
        import websocket as _wsmod
        _ws_client = _wsmod
        _WS_AVAILABLE = True
        logger.info('[probe] websocket-client installed and loaded, switching to real-time WSS reporting')
        return True
    except Exception as e:
        logger.error(f'[probe] websocket-client installed but failed to load in this process: {e}')
        return False

def _probe_ws_url():
    """把 PROBE_URL 的 http(s) 换成 ws(s),路径不变(官方协议同一路径区分POST和Upgrade)"""
    parsed = urlparse(PROBE_URL)
    scheme = 'wss' if parsed.scheme == 'https' else 'ws'
    return f'{scheme}://{parsed.netloc}{parsed.path}'

def start_probe_ws_loop(gen=None):
    """优先走WSS长连接实现秒级实时上报;websocket-client未安装、被禁用或连接持续失败时,
    自动退回start_probe_loop()的POST轮询(60秒一次),行为不会比原来差"""
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        logger.info('PROBE variable is empty, skipping probe')
        return

    gen = _wd['gen'] if gen is None else gen
    if not PROBE_WSS:
        logger.info('[probe] PROBE_WSS is false, using POST polling only')
        start_probe_loop(gen)
        return

    if not _WS_AVAILABLE and not _ensure_ws_client():
        logger.info('[probe] websocket-client unavailable, falling back to POST polling')
        start_probe_loop(gen)
        return

    ws_url = _probe_ws_url()

    def loop():
        idle, total = _probe_read_cpu_times()
        rx, tx = _probe_read_net_bytes()
        ts = time.time()
        backoff = 5
        consecutive_failures = 0
        logger.info(f'[probe] attempting WSS real-time reporting to {ws_url}')
        while _wd_alive(gen):
            ws = None
            try:
                ws = _ws_client.create_connection(
                    ws_url,
                    timeout=15,
                    header=[
                        f'X-Agent-Version: {PROBE_AGENT_VERSION}',
                        'User-Agent: cfsm',
                        'X-Agent-Config-Schema: 6',
                        'X-Agent-Config-Md5: none',
                    ],
                )
                _wd['ws'] = ws
                ws.settimeout(30)
                ws.recv()  # 消费握手后的 hello 帧
                logger.info('[probe] WSS connected')
                backoff = 5
                consecutive_failures = 0

                while _wd_alive(gen):
                    metrics, idle, total, rx, tx, ts = _probe_collect(idle, total, rx, tx, ts)
                    ws.send(json.dumps({'id': PROBE_ID, 'secret': PROBE_SECRET, 'metrics': metrics}))
                    logger.debug(f'[probe] WSS metrics sent: {json.dumps(metrics, ensure_ascii=False)}')

                    next_wait = PROBE_INTERVAL
                    try:
                        raw = ws.recv()
                        logger.debug(f'[probe] raw ack: {raw}')
                        resp = json.loads(raw)
                        if resp.get('type') == 'error':
                            logger.error(f"[probe] WSS error: {resp.get('error')} (code {resp.get('code')})")
                            raise RuntimeError('protocol error')
                        _wd_ok()
                        next_ms = resp.get('nextWssReportAfterMs')
                        if isinstance(next_ms, (int, float)) and next_ms > 0:
                            next_wait = max(1, next_ms / 1000)
                        logger.debug(f'[probe] next report in {next_wait}s')
                    except (ValueError, RuntimeError):
                        raise
                    except Exception:
                        pass  # ack解析失败不致命,按默认间隔继续

                    _wd_sleep(next_wait, gen)
                try:
                    ws.close()  # 被看门狗换代, 退出前关掉连接
                except Exception:
                    pass
            except Exception as e:
                if not _wd_alive(gen):
                    break
                consecutive_failures += 1
                logger.error(f'[probe] WSS connection issue: {e}')
                try:
                    if ws:
                        ws.close()
                except Exception:
                    pass
                # 连续失败多次就先退回POST轮询上报几轮,同时仍会定期重试WSS
                if consecutive_failures >= 5:
                    logger.error('[probe] WSS repeatedly failing, falling back to POST polling for this cycle')
                    try:
                        metrics, idle, total, rx, tx, ts = _probe_collect(idle, total, rx, tx, ts)
                        _probe_report(metrics)
                    except Exception as e2:
                        logger.error(f'[probe] fallback POST also failed: {e2}')
                    _wd_sleep(PROBE_INTERVAL, gen)
                else:
                    _wd_sleep(backoff, gen)
                    backoff = min(backoff * 2, 120)

    t = threading.Thread(target=loop, daemon=True, name=f'cf-probe-wss-{gen}')
    _wd['thread'] = t
    t.start()


# =========================== 看门狗 ===========================
def _wd_restart(reason):
    with _wd['lock']:
        _wd['gen'] += 1
        _wd['restarts'] += 1
        gen = _wd['gen']
        ws = _wd['ws']
        _wd['ws'] = None
    logger.error(f'[probe] watchdog: {reason}, restarting report loop (#{_wd["restarts"]})')
    if ws is not None:
        try:
            ws.close()  # 打断可能卡住的 recv
        except Exception:
            pass
    _wd['last_ok'] = time.time()  # 给新循环一个完整的宽限期
    try:
        start_probe_ws_loop(gen)
    except Exception as e:
        logger.error(f'[probe] watchdog restart failed: {e}')


def _watchdog():
    while True:
        limit = max(10, PROBE_INTERVAL * max(1, PROBE_WATCHDOG_MISS))
        time.sleep(min(60, limit / 2))
        try:
            t = _wd['thread']
            if t is None or not t.is_alive():
                _wd_restart('report loop is not running')
            elif time.time() - _wd['last_ok'] > limit:
                _wd_restart(f'no successful report for {int(time.time() - _wd["last_ok"])}s')
        except Exception as e:
            logger.error(f'[probe] watchdog error: {e}')


def start(cfg=None, log=None):
    """入口: cfg 为 dict(键同 _CFG_KEYS, 未给的用默认/环境变量), log 为 logging.Logger; 后台线程运行, 立即返回"""
    global logger
    g = globals()
    for k, v in (cfg or {}).items():
        if k in _CFG_KEYS and v is not None:
            g[k] = v
    if log is not None:
        logger = log
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        logger.info('PROBE variable is empty, skipping probe')
        return
    _wd['last_ok'] = time.time()
    start_probe_ws_loop(_wd['gen'])
    if PROBE_WATCHDOG:
        threading.Thread(target=_watchdog, daemon=True, name='cf-probe-watchdog').start()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG if os.environ.get('DEBUG') else logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        print('请设置环境变量 PROBE_ID / PROBE_SECRET / PROBE_URL')
        sys.exit(2)
    start()
    while True:
        time.sleep(3600)
