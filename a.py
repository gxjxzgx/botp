#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import re
import json
import time
import base64
import random
import string
import shutil
import platform
import signal
import threading
import subprocess
import datetime
import socket
import ipaddress
import zipfile
import hashlib
import selectors
import errno
import ssl
import uuid as _uuid_mod

# ---- 第三方依赖: 缺少时自动 pip 安装到脚本同目录的 .pydeps, 装完直接继续运行 ----
_PYDEPS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.pydeps')
if os.path.isdir(_PYDEPS) and _PYDEPS not in sys.path:
    sys.path.insert(0, _PYDEPS)

def _ensure_deps():
    import importlib
    missing = []
    for mod in ('requests', 'cryptography'):
        try:
            importlib.import_module(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        return
    print(f'[deps] 缺少 {", ".join(missing)}, 正在安装到 {_PYDEPS} ...', flush=True)
    base = [sys.executable, '-m', 'pip', 'install', '-q', '--disable-pip-version-check', '--target', _PYDEPS]
    err = ''
    for extra in ([], ['--break-system-packages']):   # PEP 668 环境(externally-managed)再加参数试一次
        try:
            r = subprocess.run(base + extra + missing, capture_output=True, text=True, timeout=300)
        except Exception as e:
            err = str(e)
            continue
        if r.returncode == 0:
            break
        err = (r.stderr or r.stdout or '').strip()
    else:
        print(f'[deps] 自动安装失败, 请手动执行: pip install {" ".join(missing)}\n{err[-800:]}', flush=True)
        sys.exit(1)
    if _PYDEPS not in sys.path:
        sys.path.insert(0, _PYDEPS)
    importlib.invalidate_caches()
    print('[deps] 依赖安装完成', flush=True)

_ensure_deps()
import requests  # noqa: E402
from pathlib import Path
from urllib.parse import urlparse, quote, unquote
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from cryptography.hazmat.primitives.asymmetric import x25519, ec  # noqa: E402
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

# =========================== 环境变量 ===========================

# 本文件放在仓库(a.py), 由启动文件 app.py 拉取运行: 配置请改启动文件里的 CONF(写入环境变量后传进来),
# 下面只是默认值; 也可以不用启动文件, 直接运行本文件 + 环境变量
# ==================== 常修改配置（优先调整这里） ====================

NAME = '未设置变量'                           # 节点名称
UUID = ''                             # UUID（必须填写有效值）
ARGO_DOMAIN = ''                  # Argo 固定隧道域名，留空使用临时隧道
ARGO_AUTH = ''                     # Argo 固定隧道 token 或 json，留空使用临时隧道

# ==================== 端口与功能开关 ====================
S5_PORT = ''                                 # socks5 端口，留空不开启，填 0 自动分配
HY2_PORT = ''                                # hy2 端口，留空不开启，填 0 自动分配
REALITY_PORT = ''                            # reality 端口，留空不开启，填 0 自动分配

ENABLE_ARGO = True                           # 是否启用 Argo 隧道，默认启用
AUTO_ACCESS = False                          # 是否开启自动保活
SHOW_LOG = False                             # 是否显示日志

# ==================== 订阅、上传与其他 ====================
UPLOAD_URL = ''                              # 节点或订阅上传地址
PROJECT_URL = ''                             # 项目 URL，用于自动保活或上传订阅
FILE_PATH = '.cache'                         # 运行目录，sub.txt 保存路径
SUB_PATH = 'sub'                             # 订阅 token
CFIP = 'cf.877774.xyz'                       # 优选 IP 或域名

TG_CHAT_ID = ''                              # Telegram chat_id (由环境变量提供)
TG_BOT_TOKEN = ''                            # Telegram bot_token (由环境变量提供)

CERT_B64 = ''                                # 自定义证书（base64 编码的 PEM）
KEY_B64 = ''                                 # 自定义私钥（需与 CERT_B64 成对提供）
CLOUDFLARED_VERSION = '2026.10.0'            # cloudflared 版本号(固定版本, 避免 latest 升级后不兼容; 填 latest 可跟随最新)
XRAY_VERSION = 'v26.3.27'                    # Xray-core 版本号(固定版本, 避免 latest 升级后配置格式变化导致起不来)

PROBE_ID = ''                                            # 探针 ID, 留空跟随 UUID
PROBE_SECRET = ''                                       # 上报密钥
PROBE_URL = 'https://cf-server-monitor.gxjx.eu.cc/update'   # Worker 上报地址

USE_FORWARD = False                          # 转发模块(SOCKS5 出站 + cloudflared 边缘转发): True 启用; False 直连
EDGE_PROXY = ''                              # (USE_FORWARD=True 时) cloudflared 连 CF 边缘走的代理, 如 http://user:pass@host:3128 或 socks5://...; 留空读 HTTPS_PROXY/ALL_PROXY/HTTP_PROXY, 不通再试直连; 填 0 永不走代理
EDGE_PROXY_FILE = ''                         # 可选: 代理地址文件(一行代理地址), 填了以文件为准, 代理认证失败(407)时自动重读, 密码轮换不用重启


# ==================== 从环境变量覆盖（一般无需修改） ====================
def _env_raw(key, default):
    # 环境变量未设置或为空白时用默认值(面板里留空的变量常以空串传入)
    v = os.environ.get(key)
    if v is None or not str(v).strip():
        return default
    return v

def _env_int(key, default):
    try:
        return int(str(_env_raw(key, default)).strip())
    except (TypeError, ValueError):
        return int(default)

def _env_bool(key, default):
    return str(_env_raw(key, default)).strip().lower() not in ('false', '0', 'no', 'off', 'disable')

def _env_float(key, default):
    try:
        return float(str(_env_raw(key, default)).strip())
    except (TypeError, ValueError):
        return float(default)

NAME = os.environ.get('NAME', NAME)
UUID = os.environ.get('UUID', UUID).strip() or str(_uuid_mod.uuid4())   # 为空则随机生成(与 index.js 一致), 否则所有节点/配置都是坏的
ARGO_DOMAIN = os.environ.get('ARGO_DOMAIN', ARGO_DOMAIN).strip()
ARGO_AUTH = os.environ.get('ARGO_AUTH', ARGO_AUTH).strip()

S5_PORT = os.environ.get('S5_PORT', S5_PORT).strip()
HY2_PORT = os.environ.get('HY2_PORT', HY2_PORT).strip()
REALITY_PORT = os.environ.get('REALITY_PORT', REALITY_PORT).strip()


ENABLE_ARGO = _env_bool('ENABLE_ARGO', str(ENABLE_ARGO))
AUTO_ACCESS = str(_env_raw('AUTO_ACCESS', str(AUTO_ACCESS))).strip().lower() == 'true'
SHOW_LOG = _env_bool('SHOW_LOG', str(SHOW_LOG))

ARGO_PORT = _env_int('ARGO_PORT', 8001)    # Argo 隧道端口
PORT = _env_int('PORT', 3000)              # HTTP 订阅端口, 不填默认 3000, 填 0 自动分配
CFPORT = _env_int('CFPORT', 443)           # 优选端口

UPLOAD_URL = os.environ.get('UPLOAD_URL', UPLOAD_URL).strip().rstrip('/')
PROJECT_URL = os.environ.get('PROJECT_URL', PROJECT_URL).strip().rstrip('/')
FILE_PATH = _env_raw('FILE_PATH', FILE_PATH).strip()   # 空串会 resolve 成当前目录, cleanup_old_files 会把脚本所在目录清空
SUB_PATH = os.environ.get('SUB_PATH', SUB_PATH).strip().strip('/') or 'sub'   # 去掉首尾 /, 避免 '/sub' 变成 '//sub' 永远匹配不上
CFIP = _env_raw('CFIP', CFIP).strip()   # 为空时链接会变成 @:443, 退回默认

TG_CHAT_ID = os.environ.get('TG_CHAT_ID', TG_CHAT_ID)
TG_BOT_TOKEN = os.environ.get('TG_BOT_TOKEN', TG_BOT_TOKEN)

CERT_B64 = os.environ.get('CERT_B64', CERT_B64)
KEY_B64 = os.environ.get('KEY_B64', KEY_B64)
CLOUDFLARED_VERSION = str(_env_raw('CLOUDFLARED_VERSION', CLOUDFLARED_VERSION)).strip()   # 面板留空时保持固定版本, 不变成 latest
XRAY_VERSION = str(_env_raw('XRAY_VERSION', XRAY_VERSION)).strip()


# ---- 转发模块(代码在本文件下方) ----
USE_FORWARD = _env_bool('USE_FORWARD', 'true' if USE_FORWARD else 'false')
EDGE_PROXY = str(_env_raw('EDGE_PROXY', EDGE_PROXY)).strip()
EDGE_PROXY_FILE = str(_env_raw('EDGE_PROXY_FILE', EDGE_PROXY_FILE)).strip()

# ---- CF-Server-Monitor 上报: 探针代码不在本文件, 启动时从仓库拉取 botp.py 运行; 本文件只传 ID/地址/密钥 ----
# 其它探针参数(上报间隔、三网测速节点等)用 botp 默认值, 需要改就设同名环境变量, botp 自己会读
PROBE_MODULE_URL = os.environ.get('PROBE_MODULE_URL', 'https://raw.githubusercontent.com/gxjxzgx/botp/main/botp.py')  # 探针代码地址
PROBE_MODULE_SHA256 = os.environ.get('PROBE_MODULE_SHA256', '').strip().lower()   # 可选: 填了就校验探针代码的 SHA-256, 不一致不运行
PROBE_ID = os.environ.get('PROBE_ID', PROBE_ID) or UUID      # 探针 ID(为空跟随最终 UUID, 含环境变量覆盖后的值)
PROBE_SECRET = os.environ.get('PROBE_SECRET', PROBE_SECRET)                            # 上报密钥
PROBE_URL = os.environ.get('PROBE_URL', PROBE_URL)  # Worker 上报地址

# =========================== 日志控制 ===========================
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except Exception:
    pass

def log(msg):
    if SHOW_LOG:
        print(msg, flush=True)

def log_error(msg):
    if SHOW_LOG:
        print(msg, file=sys.stderr, flush=True)

def always_log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()

# =========================== 全局变量 ===========================
private_key = ''
public_key = ''
sub_txt_content = ''
FILE_PATH = Path(FILE_PATH).resolve()
if FILE_PATH in (Path.cwd().resolve(), Path(os.path.expanduser("~")).resolve(), Path(__file__).resolve().parent) or FILE_PATH in Path.cwd().resolve().parents or len(FILE_PATH.parts) < 2:
    print(f'[warn] FILE_PATH={FILE_PATH} 是当前目录/主目录/脚本目录/根目录, 清理时会删光里面的文件, 已改用 .cache')
    FILE_PATH = (Path.cwd() / '.cache').resolve()

def generate_random_name(length=6):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

web_name = generate_random_name()
bot_name = generate_random_name()

web_path = FILE_PATH / web_name
bot_path = FILE_PATH / bot_name
sub_path = FILE_PATH / 'sub.txt'
list_path = FILE_PATH / 'list.txt'
boot_log_path = FILE_PATH / 'boot.log'
config_path = FILE_PATH / 'config.json'
cert_path = FILE_PATH / 'cert.pem'
key_path = FILE_PATH / 'private.key'
auto_ports_path = FILE_PATH / 'auto_ports.json'   # 端口填 0 时自动分配的结果, 重启后尽量沿用, 节点不变

def _port_bind_test(port, udp):
    # 能绑定则返回 socket(调用方负责关闭), 否则 None, port=0 由系统分配
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    try:
        if not udp:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        return s
    except OSError:
        s.close()
        return None

def resolve_auto_ports():
    # 端口留空 = 不开启, 填 0 = 自动分配空闲端口(HY2 为 UDP, 其余 TCP)
    global S5_PORT, HY2_PORT, REALITY_PORT
    port_items = [('S5_PORT', S5_PORT), ('HY2_PORT', HY2_PORT), ('REALITY_PORT', REALITY_PORT)]
    wanted = [k for k, v in port_items if str(v).strip() == '0']
    if not wanted:
        return
    saved = {}
    try:
        saved = json.loads(auto_ports_path.read_text(encoding='utf-8'))
        if not isinstance(saved, dict):
            saved = {}
    except Exception:
        saved = {}
    fixed = set()
    busy_ports = [S5_PORT, HY2_PORT, REALITY_PORT, PORT, ARGO_PORT]
    busy_ports += reserved_ports()   # 转发用的本地端口(未启用转发时为空)
    for v in busy_ports:
        try:
            if int(str(v).strip()) > 0:
                fixed.add(int(str(v).strip()))
        except (TypeError, ValueError):
            pass
    held = []
    result = {}
    try:
        for key in wanted:
            udp = (key == 'HY2_PORT')
            sock = None
            try:
                old = int(saved.get(key, 0))
            except (TypeError, ValueError):
                old = 0
            if 1024 <= old <= 65535 and old not in fixed and old not in result.values():
                sock = _port_bind_test(old, udp)
            # 先在 20000-32767 里随机挑(低于系统临时端口段), 避免释放后到 Xray 绑定前被出站连接的源端口抢走
            tries = 0
            while sock is None and tries < 60:
                tries += 1
                if tries <= 50:
                    want = random.randint(20000, 32767)
                    if want in fixed or want in result.values():
                        continue
                    cand = _port_bind_test(want, udp)
                    if cand is None:
                        continue
                else:
                    cand = _port_bind_test(0, udp)
                    if cand is None:
                        break
                p = cand.getsockname()[1]
                if p in fixed or p in result.values():
                    held.append(cand)
                    continue
                sock = cand
            if sock is None:
                log(f'{key}=0 自动分配端口失败, 该节点不开启')
                result[key] = ''
                continue
            held.append(sock)
            result[key] = sock.getsockname()[1]
    finally:
        for s in held:
            try:
                s.close()
            except Exception:
                pass
    for key, p in result.items():
        v = str(p) if p else ''
        if key == 'S5_PORT':
            S5_PORT = v
        elif key == 'HY2_PORT':
            HY2_PORT = v
        elif key == 'REALITY_PORT':
            REALITY_PORT = v
        if p:
            log(f'{key}=0 已自动分配端口: {p}')
    try:
        saved.update({k: v for k, v in result.items() if v})
        auto_ports_path.write_text(json.dumps(saved), encoding='utf-8')
    except Exception:
        pass

# =========================== 端口检查 ===========================
def is_valid_port(port):
    try:
        if port is None or port == '':
            return False
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return False
        return True
    except (ValueError, TypeError):
        return False

# =========================== X25519 密钥对生成 ===========================
def generate_x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return {
        'privateKey': base64.urlsafe_b64encode(priv_bytes).decode().rstrip('='),
        'publicKey': base64.urlsafe_b64encode(pub_bytes).decode().rstrip('=')
    }

def generate_or_load_keypair():
    global private_key, public_key
    key_file_path = FILE_PATH / 'key.txt'
    if key_file_path.exists():
        content = key_file_path.read_text(encoding='utf-8')
        priv_match = re.search(r'PrivateKey:\s*(.*)', content)
        pub_match = re.search(r'PublicKey:\s*(.*)', content)
        if priv_match and pub_match:
            private_key = priv_match.group(1).strip()
            public_key = pub_match.group(1).strip()
            log(f'Private Key: {private_key}')
            log(f'Public Key: {public_key}')
            return
    keypair = generate_x25519_keypair()
    private_key = keypair['privateKey']
    public_key = keypair['publicKey']
    key_file_path.write_text(
        f'PrivateKey: {private_key}\nPublicKey: {public_key}\n', encoding='utf-8')
    log(f'Private Key: {private_key}')
    log(f'Public Key: {public_key}')

# =========================== TLS 证书生成 ===========================
FALLBACK_EC_KEY = (
    '-----BEGIN EC PARAMETERS-----\n'
    'BggqhkjOPQMBBw==\n'
    '-----END EC PARAMETERS-----\n'
    '-----BEGIN EC PRIVATE KEY-----\n'
    'MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49\n'
    'AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa\n'
    '/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==\n'
    '-----END EC PRIVATE KEY-----\n'
)

FALLBACK_CERT = (
    '-----BEGIN CERTIFICATE-----\n'
    'MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw\n'
    'EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy\n'
    'MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n'
    'A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h\n'
    'aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR\n'
    'BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB\n'
    'Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+\n'
    'eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==\n'
    '-----END CERTIFICATE-----\n'
)

def ensure_tls_certificates(cert_file, key_file):
    """生成/写入 TLS 证书 (用于 Hysteria2)
    优先使用 CERT_B64/KEY_B64 提供的自定义证书(如 Cloudflare Origin CA 证书,
    可配 CF Full Strict);未提供则退回自签名证书(只能配 CF Full,配不了 Strict)"""
    cert_file.parent.mkdir(parents=True, exist_ok=True)

    if CERT_B64 and KEY_B64:
        try:
            cert_pem = base64.b64decode(CERT_B64)
            key_pem = base64.b64decode(KEY_B64)
            # 解出来不是 PEM(填错/乱码)就退回自签, 免得写出坏证书让 HY2/TLS 起不来
            if b'-----BEGIN CERTIFICATE-----' not in cert_pem or b'PRIVATE KEY-----' not in key_pem:
                raise ValueError('not a PEM certificate/key')
            cert_file.write_bytes(cert_pem)
            key_file.write_bytes(key_pem)
            log('Using custom certificate from CERT_B64/KEY_B64')
            return
        except Exception as e:
            log_error(f'Failed to decode CERT_B64/KEY_B64, falling back to self-signed: {e}')

    if cert_file.exists() and key_file.exists():
        return
    try:
        ec_private_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'bing.com')
        ])
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ec_private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None))
            .not_valid_after((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).replace(tzinfo=None))
            .sign(ec_private_key, hashes.SHA256())
        )
        key_pem = ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        key_file.write_bytes(key_pem)
        cert_file.write_bytes(cert_pem)
    except Exception as e:
        log_error(f'Failed to generate TLS certificate: {e}')
        key_file.write_text(FALLBACK_EC_KEY, encoding='utf-8')
        cert_file.write_text(FALLBACK_CERT, encoding='utf-8')

# =========================== 证书指纹计算 ===========================
def get_certificate_fingerprint(cert_file):
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-noout', '-fingerprint', '-sha256', '-in', str(cert_file)],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            match = re.search(r'=(.+)$', output)
            if match and match.group(1):
                return match.group(1).upper()
    except Exception:
        pass
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data)
        fingerprint = cert.fingerprint(hashes.SHA256())
        return ':'.join(f'{b:02X}' for b in fingerprint)
    except Exception as e:
        log_error(f'Failed to calculate certificate fingerprint: {e}')
        return ''

# =========================== 创建运行文件夹 ===========================
def create_directory():
    if not SHOW_LOG:
        print('\033c', end='')
    FILE_PATH.mkdir(parents=True, exist_ok=True)

# =========================== 删除旧节点 ===========================
def delete_nodes():
    try:
        if not UPLOAD_URL:
            return
        if not sub_path.exists():
            return
        content = sub_path.read_text(encoding='utf-8')
        decoded = base64.b64decode(content).decode('utf-8')
        nodes = [line for line in decoded.split('\n')
                 if re.match(r'(vless|vmess|trojan|hysteria2|socks)://', line)]
        if not nodes:
            return
        requests.post(f'{UPLOAD_URL}/api/delete-nodes',
                       json={'nodes': nodes}, timeout=10)
    except Exception:
        pass

# =========================== 清理历史文件 ===========================
def cleanup_old_files():
    preserve_files = {FILE_PATH / 'key.txt', cert_path, key_path, auto_ports_path}
    if EDGE_PROXY_FILE:
        preserve_files.add(Path(EDGE_PROXY_FILE).resolve())   # 代理密码文件放在 FILE_PATH 里也不能删
    try:
        for item in FILE_PATH.iterdir():
            if item in preserve_files:
                continue
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            except Exception:
                pass
    except Exception:
        pass

# =========================== 判断系统架构 ===========================
def get_system_architecture():
    arch = platform.machine().lower()
    if arch in ('arm', 'arm64', 'aarch64'):
        return 'arm'
    return 'amd'

# =========================== 下载文件 ===========================
def download_file(file_name, file_url):
    file_path = FILE_PATH / file_name
    try:
        with requests.get(file_url, stream=True, timeout=180) as response:   # stream=True 必须关闭响应, 否则连接/fd 泄漏
            response.raise_for_status()
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        log(f'Download {file_name} successfully')
        return True
    except Exception as e:
        log_error(f'Download {file_name} failed: {e}')
        _unlink(file_path)
        return False

def _unlink(p):
    """删文件, 不存在或删不掉都忽略"""
    try:
        p.unlink()
    except OSError:
        pass

def _gh_release_url(repo, version, asset):
    v = version or 'latest'
    return f'https://github.com/{repo}/releases/' + ('latest/download' if v == 'latest' else f'download/{v}') + f'/{asset}'

def download_web_official(arch_zip):
    """官方 Xray-core zip, 只取出 xray 二进制"""
    url = _gh_release_url('XTLS/Xray-core', XRAY_VERSION, f'Xray-linux-{arch_zip}.zip')
    log(f'Downloading Xray-core ({XRAY_VERSION or "latest"}) from official source: {url}')
    zip_path = FILE_PATH / f'{web_name}.zip'
    if not download_file(zip_path.name, url):
        return False
    try:
        with zipfile.ZipFile(zip_path) as zf, zf.open('xray') as src, open(web_path, 'wb') as dst:
            shutil.copyfileobj(src, dst)
        return True
    except Exception as e:
        log_error(f'Failed to extract Xray-core zip: {e}')
        _unlink(web_path)   # 解压到一半的残缺文件不能留, 否则 watchdog 会一直拉起坏文件
        return False
    finally:
        _unlink(zip_path)

def download_cloudflared_official(arch_gh):
    url = _gh_release_url('cloudflare/cloudflared', CLOUDFLARED_VERSION, f'cloudflared-linux-{arch_gh}')
    log(f'Downloading cloudflared ({CLOUDFLARED_VERSION or "latest"}) from official source: {url}')
    return download_file(bot_name, url)

def _download_from_mirrors(name, kind, base_urls):
    for index, base_url in enumerate(base_urls):
        if download_file(name, f'{base_url}/{kind}'):
            return True
        if index + 1 < len(base_urls):
            log(f'Retrying {name} from backup source')
    log_error(f'Error downloading {name}: all sources failed')
    return False

def download_all_files(need_web=True, need_bot=True):
    """下载所需二进制文件。cloudflared 仅在 ENABLE_ARGO 为真时下载; need_web/need_bot 可只下载其中一个(进程崩溃重下时用)
    填了版本号先走官方 GitHub, 失败或未填版本号走镜像"""
    arch = 'arm64' if get_system_architecture() == 'arm' else 'amd64'
    base_urls = [f'https://{arch}.oooen.com', f'https://{arch}.ssss.nyc.mn']
    jobs = []
    if need_web:
        jobs.append(('Xray-core', web_name, 'web', XRAY_VERSION, lambda: download_web_official('arm64-v8a' if arch == 'arm64' else '64')))
    if need_bot and ENABLE_ARGO:
        jobs.append(('cloudflared', bot_name, 'bot', CLOUDFLARED_VERSION, lambda: download_cloudflared_official(arch)))
    for label, name, kind, version, official in jobs:
        if version and official():
            continue
        if version:
            log_error(f'{label} official download failed, falling back to mirror')
        _download_from_mirrors(name, kind, base_urls)

# =========================== 授权文件执行权限 ===========================
def authorize_files(file_names):
    for name in file_names:
        file_path = FILE_PATH / name
        if file_path.exists():
            try:
                os.chmod(str(file_path), 0o775)
                log(f'Empowerment success for {name}: 775')
            except Exception as e:
                log_error(f'Empowerment failed for {name}: {e}')

# =========================== Argo 隧道配置 ===========================
def argo_type():
    """仅在 ENABLE_ARGO 为真时准备隧道配置文件"""
    if not ENABLE_ARGO:
        log('ENABLE_ARGO is false, skip Argo tunnel setup')
        return
    if not ARGO_AUTH or not ARGO_DOMAIN:
        log('ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels')
        return

    if 'TunnelSecret' in ARGO_AUTH:
        (FILE_PATH / 'tunnel.json').write_text(ARGO_AUTH, encoding='utf-8')
        try:
            tunnel_id = json.loads(ARGO_AUTH)['TunnelID']
        except Exception:
            m = re.search(r'"TunnelID"\s*:\s*"([^"]+)"', ARGO_AUTH)   # 兼容不是严格 JSON 的写法, 不再按引号下标硬切(会 IndexError)
            tunnel_id = m.group(1) if m else ''
            if not tunnel_id:
                log_error('ARGO_AUTH contains TunnelSecret but TunnelID not found')
        tunnel_yaml = f"""
tunnel: {tunnel_id}
credentials-file: {FILE_PATH / 'tunnel.json'}
protocol: http2

ingress:
  - hostname: {ARGO_DOMAIN}
    service: http://localhost:{ARGO_PORT}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
"""
        (FILE_PATH / 'tunnel.yml').write_text(tunnel_yaml, encoding='utf-8')
    else:
        log(f'Using token connect to tunnel, please set {ARGO_PORT} in cloudflare')


# =========================== 转发模块(SOCKS5 出站 + cloudflared 边缘转发) ===========================
# USE_FORWARD=false(默认)时下面的代码不启用, Xray / cloudflared 直连; true 时 Xray 出站经本机 SOCKS5 由 Python 代连, cloudflared 经本机端口由 Python 连 CF 边缘
# =========================== Python SOCKS5 出站 (Xray 自己出不了站时由 Python 代连) ===========================
EGRESS_MODE = 'direct'                       # 启用转发后 = python(经 Python 代连); 出站起不来时退回 direct(Xray 自己直连)
EGRESS_PORT = _env_int('EGRESS_PORT', '10087')          # 本机 SOCKS5 监听端口
BLOCK_QUIC = False         # 启用转发后为 True: 走 Python 出站时屏蔽 udp/443(QUIC); 退回 direct 时配置里也不会加这条规则

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

# EDGE_PROXY / EDGE_PROXY_FILE 来自上面的配置; _forward_启用转发后 EDGE_PROXY = 当前实际使用的代理(直连兜底时为空)
_edge_proxy_cfg = ''                         # 配置的代理(可被 EDGE_PROXY_FILE 重读更新)
EDGE_FWD = False                             # 启用转发后为 True

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



# =========================== 转发初始化 ===========================
def _forward_setup():
    """USE_FORWARD=true 时启动调用一次: 切到 Python 出站 + 边缘转发, 算出实际使用的代理"""
    global EGRESS_MODE, BLOCK_QUIC, EDGE_FWD, EDGE_PROXY, _edge_proxy_cfg
    EGRESS_MODE = 'python'
    BLOCK_QUIC = True   # 走 Python 出站时屏蔽 udp/443(QUIC)
    EDGE_FWD = True
    ep = str(EDGE_PROXY or '').strip()
    if ep.lower() in ('0', 'false', 'none', 'off', 'no'):
        EDGE_PROXY = ''
    else:
        EDGE_PROXY = _read_proxy_file() or _norm_proxy(ep or _sys_proxy())
    _edge_proxy_cfg = EDGE_PROXY
    always_log('[forward] 转发已启用')

def reserved_ports():
    """自动分配端口时要避开的本地端口(出站 3 个候选 + 边缘转发 4 个); 没启用转发时为空"""
    if not EDGE_FWD:
        return []
    return [EGRESS_PORT, EGRESS_PORT + 1, EGRESS_PORT + 2, EDGE_LOCAL_BASE, EDGE_LOCAL_BASE + 1, EDGE_LOCAL_BASE + 2, EDGE_LOCAL_BASE + 3]

if USE_FORWARD:
    _forward_setup()
else:
    always_log('[forward] USE_FORWARD=false, 跳过转发 (Xray / cloudflared 直连)')

# =========================== Xray 配置生成 ===========================
_SNIFF = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}

def _argo_ws_in(tag, port, protocol, path, client, security=True):
    """Argo fallback 到的内部 ws inbound(只监听 127.0.0.1)"""
    settings = {"clients": [client]}
    if protocol == "vless":
        settings["decryption"] = "none"
    stream = {"network": "ws", **({"security": "none"} if security else {}), "wsSettings": {"path": path}}
    return {"tag": tag, "port": port, "listen": "127.0.0.1", "protocol": protocol,
            "settings": settings, "streamSettings": stream, "sniffing": _SNIFF}

def generate_xray_config():
    config = {
        "log": {"access": "/dev/null", "error": "/dev/null", "loglevel": "none"},
        "inbounds": [],
        "dns": {"servers": ["https+local://8.8.8.8/dns-query"]},
        "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
    }

    # 出站: python 模式下默认出站走本机 SOCKS5(由 Python 代连), 不再用 DoH
    if EGRESS_MODE == 'python':
        config.pop("dns", None)
        config["outbounds"].insert(0, {"protocol": "socks", "tag": "py-egress",
                                       "settings": {"servers": [{"address": "127.0.0.1", "port": EGRESS_PORT}]}})
        # 屏蔽 udp/443(QUIC), 让浏览器/视频退回 TCP, 避免 Python 逐包转发大流量 UDP 拖垮 CPU
        if BLOCK_QUIC:
            config["routing"] = {"rules": [{"type": "field", "network": "udp", "port": "443", "outboundTag": "block"}]}

    # Argo 相关 inbound (公网监听的 vless-fallback-in 及其 fallback 到的四个内部端口)
    # 仅在 ENABLE_ARGO 为真时写入配置; 关闭 Argo 时这些端口完全不会被监听
    if ENABLE_ARGO:
        fallbacks = [{"dest": 51001}, {"path": "/vless-argo", "dest": 51002},
                     {"path": "/vmess-argo", "dest": 51003}, {"path": "/trojan-argo", "dest": 51004}]
        if PORT:
            fallbacks.append({"path": f"/{SUB_PATH}", "dest": PORT})   # Argo 域名/SUB_PATH 走 https 订阅
        config["inbounds"] += [
            {"tag": "vless-fallback-in", "listen": "::", "port": ARGO_PORT, "protocol": "vless",
             "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none", "fallbacks": fallbacks},
             "streamSettings": {"network": "tcp"}},
            {"tag": "vless-tcp-in", "port": 51001, "listen": "127.0.0.1", "protocol": "vless",
             "settings": {"clients": [{"id": UUID}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "none"}},
            _argo_ws_in("vless-ws-in", 51002, "vless", "/vless-argo", {"id": UUID, "level": 0}),
            _argo_ws_in("vmess-ws-in", 51003, "vmess", "/vmess-argo", {"id": UUID, "alterId": 0}, security=False),
            _argo_ws_in("trojan-ws-in", 51004, "trojan", "/trojan-argo", {"password": UUID}),
        ]

    if is_valid_port(REALITY_PORT):   # VLESS Reality
        config["inbounds"].append({
            "tag": "vless-reality-in", "listen": "::", "port": int(REALITY_PORT), "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "flow": "xtls-rprx-vision"}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "show": False, "dest": "www.iij.ad.jp:443", "xver": 0, "serverNames": ["www.iij.ad.jp"],
                "privateKey": private_key, "shortIds": [""]}}})

    if is_valid_port(HY2_PORT):   # Hysteria2
        config["inbounds"].append({
            "tag": "hysteria-in", "listen": "::", "port": int(HY2_PORT), "protocol": "hysteria",
            "settings": {"version": 2, "clients": [{"auth": UUID}]},
            "streamSettings": {
                "network": "hysteria",
                "hysteriaSettings": {"version": 2, "masquerade": {"type": "proxy", "url": "https://bing.com"}},
                "security": "tls",
                "tlsSettings": {"alpn": ["h3"], "certificates": [{"certificateFile": str(cert_path), "keyFile": str(key_path)}]}}})

    if is_valid_port(S5_PORT):   # SOCKS5
        config["inbounds"].append({
            "tag": "s5-in", "listen": "::", "port": int(S5_PORT), "protocol": "socks",
            "settings": {"auth": "password", "accounts": [{"user": UUID[:8], "pass": UUID[-12:]}], "udp": True}})

    _warn_port_conflicts(config)
    config_path.write_text(json.dumps(config, indent=2), encoding='utf-8')

def _warn_port_conflicts(config):
    """Xray 只要有一个端口绑不上整个进程就起不来: 提前把 TCP 端口撞车打印出来(HY2 是 UDP, 可以和 TCP 同号)"""
    used = {}
    def add(port, who):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        if port <= 0:
            return
        if port in used:
            always_log(f'[config] 端口冲突: {port} 同时被 {used[port]} 和 {who} 使用, Xray 可能整体启动失败')
        else:
            used[port] = who
    add(PORT, 'HTTP 订阅服务')
    if EGRESS_MODE == 'python':
        add(EGRESS_PORT, 'python egress')
    for ib in config.get('inbounds', []):
        if ib.get('protocol') == 'hysteria':
            continue
        add(ib.get('port'), ib.get('tag'))

# =========================== 启动命令 / 进程守护 ===========================
# 直接持有子进程句柄(与 index.js 一致): 不依赖 pkill/pgrep(精简镜像常没有 procps), 不会误杀同名进程, poll() 顺带回收僵尸
_procs = {'web': None, 'bot': None}
_procs_lock = threading.Lock()

def _spawn(key, argv):
    """不开新会话: 面板按进程组杀 python 时 xray/cloudflared 一起退出, 不残留占端口"""
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
    except Exception as e:
        log_error(f'Error executing command: {e}')
        return None
    with _procs_lock:
        _procs[key] = child
    return child

def _alive(key):
    c = _procs.get(key)
    return c is not None and c.poll() is None

def _kill(key, timeout=5):
    """SIGTERM, 等它退出; 超时再 SIGKILL。等到真正退出才返回, 端口/日志文件随之释放"""
    with _procs_lock:
        c = _procs.get(key)
        _procs[key] = None
    if c is None or c.poll() is not None:
        return
    try:
        c.terminate()
        c.wait(timeout)
    except subprocess.TimeoutExpired:
        try:
            c.kill()
            c.wait(3)
        except Exception:
            pass
    except Exception:
        pass

def _wait_port(port, timeout=5.0):
    """等本地端口开始监听(Xray 起来了), 最多 timeout 秒; 起得快就不白等"""
    if not is_valid_port(port):
        return False
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', int(port)), timeout=0.5).close()
            return True
        except OSError:
            if not _alive('web'):
                return False
            time.sleep(0.2)
    return False

def start_web():
    if _shutting_down:
        return
    _spawn('web', [str(web_path), '-c', str(config_path)])
    log(f'{web_name} is running')

ARGO_PROTOCOL = str(_env_raw('ARGO_PROTOCOL', 'auto')).strip().lower()   # cloudflared 协议: auto(先 QUIC, 不通退 http2) / quic / http2

def argo_protocol():
    """走边缘转发器时只能 http2(转发器只转 TCP); 直连时按 ARGO_PROTOCOL, 默认 auto"""
    if edge_local_addrs:
        return 'http2'
    return ARGO_PROTOCOL if ARGO_PROTOCOL in ('auto', 'quic', 'http2') else 'auto'

def bot_args():
    edge_args = [x for a in edge_local_addrs for x in ('--edge', a)]
    common = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', argo_protocol(), *edge_args,
              '--logfile', str(boot_log_path), '--loglevel', 'info']
    if "TunnelSecret" in ARGO_AUTH and ARGO_DOMAIN:   # 没有 ARGO_DOMAIN 时 argo_type() 不会写 tunnel.yml, 走临时隧道
        return common + ['--config', str(FILE_PATH / 'tunnel.yml'), 'run']
    if ARGO_AUTH and ARGO_DOMAIN:
        # 固定隧道 token: 不再用长度/字符集正则判断, 避免 token 稍长或带 +/_- 时被误当成临时隧道(链接却用 ARGO_DOMAIN, 全部不通)
        if not re.match(r'^[A-Za-z0-9+/=_-]{80,}$', ARGO_AUTH.strip()):
            log_error('ARGO_AUTH does not look like a tunnel token, trying it as token anyway')
        return common + ['run', '--token', ARGO_AUTH.strip()]
    return common + ['--url', f'http://localhost:{ARGO_PORT}']

def start_bot():
    if _shutting_down:
        return
    _spawn('bot', [str(bot_path)] + bot_args())
    log(f'{bot_name} is running')

_bot_lock = threading.Lock()   # cloudflared 的 kill/重启只允许一处在做: 防止 watchdog 和域名提取重试同时拉起两个进程

WATCHDOG = _env_bool('WATCHDOG', 'true')  # 进程崩溃后自动重新下载并拉起
WATCHDOG_INTERVAL = _env_int('WATCHDOG_INTERVAL', '10')   # 检查间隔(秒)
_shutting_down = False

def _clean_secrets_later():
    # watchdog 重启会重写 config.json / tunnel.json, 首次 90 秒清理已经跑过, 这里 30 秒后再删一次
    def run():
        time.sleep(30)
        for f in (config_path, FILE_PATH / 'tunnel.json', FILE_PATH / 'tunnel.yml'):
            _unlink(f)
    if _cleaned_once:
        threading.Thread(target=run, daemon=True).start()

def _restart_web():
    if _alive('web'):
        return
    if not web_path.exists():
        download_all_files(need_web=True, need_bot=False)
        authorize_files([web_name])
    if not web_path.exists():
        log_error('[watchdog] xray binary download failed, retry later')
        return
    if not config_path.exists():
        generate_xray_config()
    start_web()
    _clean_secrets_later()

def _restart_bot():
    if _alive('bot'):
        return
    if not bot_path.exists():
        download_all_files(need_web=False, need_bot=True)
        authorize_files([bot_name])
    if not bot_path.exists():
        log_error('[watchdog] cloudflared binary download failed, retry later')
        return
    if "TunnelSecret" in ARGO_AUTH and ARGO_DOMAIN and not (FILE_PATH / 'tunnel.yml').exists():
        argo_type()
    quick = not (ARGO_AUTH and ARGO_DOMAIN)
    if quick:
        _unlink(boot_log_path)          # 删掉旧日志, 免得读到上一次的旧域名
    start_bot()
    _clean_secrets_later()
    if quick:
        threading.Thread(target=_refresh_quick_tunnel_links, daemon=True).start()

def _refresh_quick_tunnel_links():
    """临时隧道重启后域名会变: 重新提取域名(extract_domains 自己轮询等域名), 更新订阅并重新推送"""
    try:
        delete_nodes()          # 先按旧 sub.txt 从订阅器删掉旧域名节点, 否则会越积越多
        extract_domains()
        send_telegram()
        upload_nodes()
        always_log('[watchdog] quick tunnel restarted, subscription links refreshed')
    except Exception as e:
        log_error(f'[watchdog] refresh quick tunnel links failed: {e}')

def watchdog_loop():
    specs = [('xray', 'web', _restart_web, True),
             ('cloudflared', 'bot', _restart_bot, ENABLE_ARGO)]
    state = {name: {'fails': 0, 'last': 0.0, 'next': 0.0} for name, _, _, _ in specs}
    time.sleep(20)   # 等首次启动完成
    while not _shutting_down:
        for name, key, restart, enabled in specs:
            if not enabled or _shutting_down:
                continue
            try:
                if name == 'cloudflared' and _bot_lock.locked():
                    continue                         # 域名提取正在重启它, 别插手
                if _alive(key):
                    continue
                st = state[name]
                now = time.time()
                if now < st['next']:
                    continue
                if now - st['last'] > 600:   # 上次重启 10 分钟后还活着才清零(退避上限是 5 分钟, 用 300 会永远清零)
                    st['fails'] = 0
                st['fails'] += 1
                st['last'] = now
                st['next'] = now + min(300, 10 * 2 ** (st['fails'] - 1))   # 退避: 10s,20s,40s...最长5分钟
                log(f'[watchdog] {name} is not running, restarting (attempt {st["fails"]})')
                if name == 'cloudflared':
                    if not _bot_lock.acquire(blocking=False):
                        continue
                    try:
                        restart()
                    finally:
                        _bot_lock.release()
                else:
                    restart()
            except Exception as e:
                log_error(f'[watchdog] {name} restart error: {e}')
        time.sleep(WATCHDOG_INTERVAL)

def start_watchdog():
    if not WATCHDOG:
        return
    threading.Thread(target=watchdog_loop, daemon=True).start()
    log('[watchdog] started')

# =========================== 下载并运行 ===========================
def download_files_and_run():
    # 下载文件
    download_all_files()

    # 授权执行权限 (cloudflared 仅在启用 Argo 时需要授权)
    to_authorize = [web_name]
    if ENABLE_ARGO:
        to_authorize.append(bot_name)
    authorize_files(to_authorize)

    # 运行 Xray: 等 Argo 入站端口开始监听再起 cloudflared(最多 5 秒), 不再固定 sleep
    try:
        start_web()
        if ENABLE_ARGO and not _wait_port(ARGO_PORT, 5):
            log_error(f'xray not listening on {ARGO_PORT} after 5s, starting cloudflared anyway')
    except Exception as e:
        log_error(f'web running error: {e}')

    # 运行 Cloudflared (仅在启用 Argo 时)
    if ENABLE_ARGO:
        start_edge_forwarder()   # 先起转发: 即使 cloudflared 下载失败, watchdog 重下后也能用上 --edge
    if ENABLE_ARGO and bot_path.exists():
        try:
            start_bot()
        except Exception as e:
            log_error(f'Error executing command: {e}')

    threading.Thread(target=argo_diag, daemon=True).start()   # 后台诊断, 不阻塞主流程(与 index.js 一致)


# =========================== Argo 诊断 ===========================
def argo_diag():
    """打印 cloudflared 日志尾部 + 用 Python 测边缘连通性, 用来判断隧道为什么没起来"""
    if not (ENABLE_ARGO and SHOW_LOG):
        return
    try:
        time.sleep(8)
        log('[argo-diag] ---- cloudflared log (tail) ----')
        if boot_log_path.exists():
            txt = boot_log_path.read_text(encoding='utf-8', errors='replace')
            txt = re.sub(r'eyJ[A-Za-z0-9=_-]{20,}', '<token>', txt)
            for ln in txt.strip().split('\n')[-25:]:
                log('[argo-diag] ' + ln[:300])
        else:
            log('[argo-diag] boot.log not found (cloudflared may have exited immediately)')
        for host in (() if (EDGE_PROXY and edge_local_addrs) else EDGE_HOSTS):
            try:
                t0 = time.time()
                addrs = sorted({a[4][0] for a in socket.getaddrinfo(host, 7844, socket.AF_INET, socket.SOCK_STREAM)})
                log(f'[argo-diag] dns {host} -> {addrs[:3]}')
                s = socket.create_connection((addrs[0], 7844), timeout=5)
                s.close()
                log(f'[argo-diag] python tcp {addrs[0]}:7844 ok {time.time()-t0:.2f}s')
            except Exception as e:
                log(f'[argo-diag] python tcp {host}:7844 FAILED {type(e).__name__}: {e}')
        if EDGE_PROXY and edge_local_addrs:
            log('[argo-diag] 边缘经代理转发, 跳过直连 7844 测试')
        c = _procs.get('bot')
        log(f'[argo-diag] cloudflared pid: {c.pid if c is not None and c.poll() is None else "NOT RUNNING"}')
    except Exception as e:
        log(f'[argo-diag] error: {e}')

# =========================== 提取隧道域名 ===========================
EXTRACT_MAX_RETRY = _env_int('EXTRACT_MAX_RETRY', '5')
EXTRACT_WAIT = _env_int('EXTRACT_WAIT', '20')   # 每次最多等多少秒拿临时隧道域名; 拿到立即继续

_QUICK_RE = re.compile(r'https?://([a-z0-9-]+\.trycloudflare\.com)', re.I)

def _read_quick_domain():
    """从 boot.log 找 xxx-xxx.trycloudflare.com, 排除报错行里的 api.trycloudflare.com"""
    try:
        txt = boot_log_path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None
    for m in _QUICK_RE.finditer(txt):
        if m.group(1).lower() != 'api.trycloudflare.com':
            return m.group(1)
    return None

def _wait_quick_domain(timeout):
    """轮询 boot.log, 拿到域名就返回; cloudflared 已退出则不再白等"""
    t0 = time.time()
    while True:
        d = _read_quick_domain()
        now = time.time()
        if d or now - t0 >= timeout or _shutting_down:
            return d
        if not _alive('bot') and now - t0 > 2:   # 进程没了: 给 2 秒把最后的日志写完就不等了
            return _read_quick_domain()
        time.sleep(0.5)

def extract_domains(_retry=0):
    """ENABLE_ARGO=false 时直接跳过隧道域名提取,仅生成非 Argo 节点"""
    if not ENABLE_ARGO:
        log('ENABLE_ARGO is false, skip Argo domain extraction')
        generate_links(None, 'ENABLE_ARGO 已关闭, 未生成 Argo 节点')
        return

    argo_domain = None

    if ARGO_AUTH and ARGO_DOMAIN:
        argo_domain = ARGO_DOMAIN
        log(f'ARGO_DOMAIN: {argo_domain}')
        log(f'Argo 订阅: https://{argo_domain}/{SUB_PATH}')
        generate_links(argo_domain)
    else:
        try:
            argo_domain = _wait_quick_domain(EXTRACT_WAIT)
            if argo_domain:
                log(f'ArgoDomain: {argo_domain}')
                generate_links(argo_domain)
                return
            if not boot_log_path.exists() and not _alive('bot'):
                generate_links(None, '读取不到 boot.log, 获取不到临时隧道, 已跳过 Argo 节点')
                return
            if _retry >= EXTRACT_MAX_RETRY:
                log_error(f'ArgoDomain not found after {_retry} retries, generating non-Argo nodes only')
                generate_links(None, f'重试 {_retry} 次仍获取不到临时隧道域名, 已跳过 Argo 节点')
                return
            log('ArgoDomain not found, re-running bot to obtain ArgoDomain')
            with _bot_lock:
                _kill('bot')                 # 等旧进程真正退出, 不再固定 sleep 3 秒
                _unlink(boot_log_path)
                start_bot()                  # 复用 bot_args(), 保留 --edge 转发参数
        except Exception as e:
            log_error(f'Error reading boot.log: {e}')
            generate_links(None, f'提取隧道域名出错({e}), 已跳过 Argo 节点')
            return
        extract_domains(_retry + 1)

# =========================== 获取 ISP 信息 ===========================
def get_meta_info():
    try:
        resp = requests.get('https://api.ip.sb/geoip',
                            headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
        data = resp.json()
        if data.get('country_code') and data.get('isp'):
            return f"{data['country_code']}-{data['isp']}".replace(' ', '_')
    except Exception:
        pass
    try:
        resp = requests.get('http://ip-api.com/json',
                            headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
        data = resp.json()
        if data.get('status') == 'success' and data.get('countryCode') and data.get('org'):
            return f"{data['countryCode']}-{data['org']}".replace(' ', '_')
    except Exception:
        pass
    return 'Unknown'

# =========================== 获取服务器公网 IP ===========================
def _looks_like_ip(s):
    """校验字符串是否为合法IP地址,避免探测接口返回非预期内容(错误页/提示文本)时被误用"""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def _fetch_public_ip_version(version='v4', timeout=3):
    host = 'ipv4.ip.sb' if version == 'v4' else 'ipv6.ip.sb'
    try:
        resp = requests.get(f'http://{host}', timeout=timeout)
        ip = resp.text.strip()
        if ip and _looks_like_ip(ip):
            return ip
    except Exception:
        pass
    try:
        result = subprocess.run(['curl', '-sm', str(int(timeout) + 2), host],
                                capture_output=True, text=True, timeout=timeout + 3)
        ip = result.stdout.strip()
        if ip and _looks_like_ip(ip):
            return ip
    except Exception:
        pass
    return None

def get_server_ip():
    ip = _fetch_public_ip_version('v4')
    if ip:
        return ip
    ip = _fetch_public_ip_version('v6')
    if ip:
        return f'[{ip}]'
    log_error('Failed to get IP address')
    return None   # 不要空 return

# =========================== 生成节点链接 ===========================
# 供 TG 推送说明节点情况
link_status = {'total': 0, 'argo': 0, 'direct': 0, 'argo_note': '', 'ip_note': '', 'name': ''}

def generate_links(argo_domain, argo_note=''):
    global sub_txt_content, link_status

    node_name = NAME or get_meta_info()   # NAME 有值直接用, 为空才查 ISP(顺便省掉一次 3~6 秒的接口请求)
    nn = quote(node_name, safe='')        # 链接 # 后面的备注要 URL 编码, 防止 # % & 或中文把链接弄坏
    # 只有开了需要公网 IP 的直连节点才去取 IP; 一个都没开就不取, 也不报"获取不到公网 IP"
    ip_items = [('HY2', HY2_PORT), ('Reality', REALITY_PORT), ('SOCKS5', S5_PORT)]
    direct_types = [n for n, p in ip_items if is_valid_port(p)]
    server_ip = get_server_ip() if direct_types else None
    ip_note = ''
    if direct_types and not server_ip:
        ip_note = f'获取不到公网 IP, 已跳过直连节点({"/".join(direct_types)})'
        log_error(f'No public IP, skip direct nodes ({"/".join(direct_types)})')

    sub_txt = ''

    # Argo 节点 (VLESS / VMess / Trojan), 仅在启用 Argo 且拿到隧道域名时生成
    if ENABLE_ARGO and argo_domain:
        sub_txt += f'\nvless://{UUID}@{CFIP}:{CFPORT}?encryption=none&security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Fvless-argo%3Fed%3D2560#{nn}-VLESS-Argo'

        vmess_obj = {
            'v': '2', 'ps': f'{node_name}-VMess-Argo', 'add': CFIP, 'port': CFPORT,
            'id': UUID, 'aid': '0', 'scy': 'auto', 'net': 'ws',
            'type': 'none', 'host': argo_domain, 'path': '/vmess-argo?ed=2560',
            'tls': 'tls', 'sni': argo_domain, 'alpn': '', 'fp': 'firefox'
        }
        vmess_b64 = base64.b64encode(json.dumps(vmess_obj, separators=(',', ':')).encode()).decode()
        sub_txt += f'\nvmess://{vmess_b64}'

        sub_txt += f'\ntrojan://{UUID}@{CFIP}:{CFPORT}?security=tls&sni={argo_domain}&fp=firefox&type=ws&host={argo_domain}&path=%2Ftrojan-argo%3Fed%3D2560#{nn}-Trojan-Argo'

    # Hysteria2 节点
    if server_ip and is_valid_port(HY2_PORT):
        fingerprint = get_certificate_fingerprint(cert_path)
        fingerprint_param = f'&pinSHA256={quote(fingerprint, safe="")}' if fingerprint else ''
        sub_txt += f'\nhysteria2://{UUID}@{server_ip}:{HY2_PORT}/?sni=bing.com&insecure=1&alpn=h3{fingerprint_param}#{nn}-HY2'

    # Reality 节点
    if server_ip and is_valid_port(REALITY_PORT):
        sub_txt += f'\nvless://{UUID}@{server_ip}:{REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk={public_key}&type=tcp&headerType=none#{nn}-Reality'

    # SOCKS5 节点
    if server_ip and is_valid_port(S5_PORT):
        s5_auth = base64.b64encode(f'{UUID[:8]}:{UUID[-12:]}'.encode()).decode()
        sub_txt += f'\nsocks://{s5_auth}@{server_ip}:{S5_PORT}#{nn}-SOCKS5'

    lines = [l for l in sub_txt.split('\n') if l]
    argo_count = len([l for l in lines if l.startswith('vmess://') or l.endswith('-VLESS-Argo') or l.endswith('-Trojan-Argo')])
    link_status = {
        'total': len(lines), 'argo': argo_count, 'direct': len(lines) - argo_count,
        'argo_note': argo_note if (ENABLE_ARGO and not argo_domain) else '',
        'ip_note': ip_note,
        'name': node_name,
        'sub_url': f'https://{argo_domain}/{SUB_PATH}' if (argo_domain and PORT) else (f'{PROJECT_URL}/{SUB_PATH}' if PROJECT_URL else ''),
    }
    if not lines:
        log_error('No nodes generated: 空节点')
    elif link_status['argo_note']:
        log_error(link_status['argo_note'])

    sub_txt_b64 = base64.b64encode(sub_txt.encode()).decode()
    if SHOW_LOG and lines:
        print(f'\033[32m{sub_txt_b64}\033[0m')
        print('\033[35mLogs will be deleted in 90 seconds, you can copy the above nodes\033[0m')

    sub_path.write_text(sub_txt_b64, encoding='utf-8')
    list_path.write_text(sub_txt, encoding='utf-8')
    log(f'{FILE_PATH}/sub.txt saved successfully')

    sub_txt_content = sub_txt_b64
    return sub_txt

# =========================== Telegram 推送 ===========================
def _esc_md(t):
    # MarkdownV2 普通文本转义(含反斜杠本身)
    return re.sub(r'([\\_*\[\]()~`>#+=|{}.!-])', r'\\\1', str(t))

def _tg_send(text, parse_mode=None):
    data = {'chat_id': TG_CHAT_ID, 'text': text}
    if parse_mode:
        data['parse_mode'] = parse_mode
    # 参数放在 POST body 里, 订阅很长时也不会超出 URL 长度限制
    try:
        resp = requests.post(f'https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage', data=data, timeout=10)
    except Exception as e:   # 网络异常也要走纯文本重试, 且不能打断后面的异常通知
        return False, 0, f'{type(e).__name__}: {e}'.replace(TG_BOT_TOKEN or '<token>', '<token>')[:200]   # 异常里带 URL, 别把 bot token 打进日志
    return resp.ok, resp.status_code, ('' if resp.ok else resp.text[:200])

def _tg_push(md, plain):
    # 先按 MarkdownV2 发, 失败(解析错误/超长)自动退回纯文本
    if len(md) <= 4096:
        ok, code, body = _tg_send(md, 'MarkdownV2')
    else:
        ok, code, body = False, 0, 'message too long'
    if not ok:
        log_error(f'Telegram MarkdownV2 send failed: HTTP {code} {body}, retry as plain text')
        if len(plain) > 4096:
            plain = plain[:4090] + '\n...'
        ok, code, body = _tg_send(plain)
    if ok:
        log('Telegram message sent successfully')
    else:
        log_error(f'Telegram send failed: HTTP {code} {body}')

def send_telegram():
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log('TG variables is empty, Skipping push nodes to TG')
        return
    try:
        try:
            message = sub_path.read_text(encoding='utf-8').strip()
        except Exception:
            message = ''
        st = link_status
        nm = st.get('name') or NAME   # NAME 为空时用 ISP 名, 和节点备注一致

        # 1) 有节点: 先推节点
        if st['total'] and message:
            title = f'{nm}节点推送通知'
            info = f"节点数: {st['total']} (Argo {st['argo']} / 直连 {st['direct']})"
            body = re.sub(r'([\\`])', r'\\\1', message)
            url = st.get('sub_url') or ''
            sub_plain = f'\n订阅地址: {url}\n' if url else ''
            sub_md = _esc_md(sub_plain)
            _tg_push(f'*{_esc_md(title)}*\n{_esc_md(info)}\n```\n{body}\n```{sub_md}',
                     f'{title}\n{info}\n\n{message}\n{sub_plain}')

        # 2) 再单独推报错: 空节点 / 拿不到临时隧道 / 拿不到公网 IP
        errs = []
        if not st['total']:
            errs.append('空节点: 没有生成任何节点')
        if st['argo_note']:
            errs.append(st['argo_note'])
        if st['ip_note']:
            errs.append(st['ip_note'])
        if errs:
            et = f'{nm}节点异常通知'
            _tg_push('*⚠️ ' + _esc_md(et) + '*\n' + '\n'.join('• ' + _esc_md(e) for e in errs),
                     '⚠️ ' + et + '\n' + '\n'.join('• ' + e for e in errs))
    except Exception as e:
        log_error(f'Failed to send Telegram message: {e}')

# =========================== 上传节点到订阅器 ===========================
def upload_nodes():
    if UPLOAD_URL and PROJECT_URL:
        subscription_url = f'{PROJECT_URL}/{SUB_PATH}'
        try:
            resp = requests.post(f'{UPLOAD_URL}/api/add-subscriptions',
                                 json={'subscription': [subscription_url]},
                                 timeout=10)
            if resp.status_code == 200:
                log('Subscription uploaded successfully')
        except Exception:
            pass
    elif UPLOAD_URL:
        if not list_path.exists():
            return
        content = list_path.read_text(encoding='utf-8')
        nodes = [line for line in content.split('\n')
                 if re.match(r'(vless|vmess|trojan|hysteria2|socks)://', line)]
        if not nodes:
            return
        try:
            resp = requests.post(f'{UPLOAD_URL}/api/add-nodes',
                                 json={'nodes': nodes},
                                 timeout=10)
            if resp.status_code == 200:
                log('Nodes uploaded successfully')
        except Exception:
            pass

# =========================== 自动保活 ===========================
def add_visit_task():
    if not AUTO_ACCESS or not PROJECT_URL:
        log('Skipping adding automatic access task')
        return
    try:
        requests.post('https://oooo.serv00.net/add-url',
                      json={'url': PROJECT_URL},
                      headers={'Content-Type': 'application/json'},
                      timeout=10)
        log('automatic access task added successfully')
    except Exception as e:
        log_error(f'Add URL failed: {e}')

# =========================== CF-Server-Monitor 探针(运行时从仓库拉取 botp.py) ===========================
class _ProbeLogger:
    """把 botp 的 logger.info/error/debug 接到本文件的日志函数"""
    def info(self, m): log(m)
    def warning(self, m): log_error(m)
    def error(self, m): log_error(m)
    def debug(self, m): pass


def _probe_fetch_module():
    """下载探针代码并加载成模块; 失败抛异常。
    支持两种形态(自动识别):
      - 单文件 botp.py: 在内存里 exec, 不落盘;
      - 压缩包 botp.zip / botp.tar.gz(混淆后 botp.py + pyarmor_runtime_*):
        解包到 <运行目录>/.probe, 加入 sys.path 后 import。"""
    import types
    resp = requests.get(PROBE_MODULE_URL, timeout=20)
    resp.raise_for_status()
    blob = resp.content
    if PROBE_MODULE_SHA256 and hashlib.sha256(blob).hexdigest() != PROBE_MODULE_SHA256:
        raise ValueError('SHA-256 不匹配, 拒绝运行')
    if blob[:4] == b'PK\x03\x04' or blob[:2] == b'\x1f\x8b':
        return _probe_load_bundle(blob)
    mod = types.ModuleType('botp')
    mod.__file__ = PROBE_MODULE_URL
    sys.modules['botp'] = mod
    exec(compile(blob, 'botp.py', 'exec'), mod.__dict__)
    if not callable(getattr(mod, 'start', None)):
        raise ValueError('探针代码里没有 start()')
    return mod


def _probe_load_bundle(blob):
    """把探针整包(含 pyarmor 运行时)解到 .probe 目录后 import botp。"""
    import io
    import zipfile
    import tarfile
    import shutil
    import importlib
    base = os.path.dirname(os.path.abspath(__file__))
    staging = os.path.join(base, '.probe.new')
    dest = os.path.join(base, '.probe')
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging, exist_ok=True)
    bio = io.BytesIO(blob)
    sroot = os.path.abspath(staging)

    def _guard(name):
        t = os.path.abspath(os.path.join(sroot, name))
        if t != sroot and not t.startswith(sroot + os.sep):
            raise RuntimeError(f'探针包路径越界: {name}')

    if blob[:4] == b'PK\x03\x04':
        with zipfile.ZipFile(bio) as z:
            for n in z.namelist():
                _guard(n)
            z.extractall(sroot)
    else:
        with tarfile.open(fileobj=bio, mode='r:gz') as t:
            for m in t.getmembers():
                _guard(m.name)
            t.extractall(sroot)
    # 入口 botp.py: 优先根目录, 否则第一个
    entry = os.path.join(sroot, 'botp.py')
    if not os.path.isfile(entry):
        for dp, _d, fs in os.walk(sroot):
            if 'botp.py' in fs:
                entry = os.path.join(dp, 'botp.py')
                break
    if not os.path.isfile(os.path.join(sroot, 'botp.py')) and os.path.isfile(entry):
        os.replace(entry, os.path.join(sroot, 'botp.py'))
    # 原子替换 .probe
    backup = os.path.join(base, '.probe.old')
    shutil.rmtree(backup, ignore_errors=True)
    if os.path.isdir(dest):
        os.replace(dest, backup)
    os.replace(staging, dest)
    shutil.rmtree(backup, ignore_errors=True)
    if dest not in sys.path:
        sys.path.insert(0, dest)
    sys.modules.pop('botp', None)
    mod = importlib.import_module('botp')
    if not callable(getattr(mod, 'start', None)):
        raise ValueError('探针代码里没有 start()')
    return mod


def start_probe():
    if not (PROBE_ID and PROBE_SECRET and PROBE_URL):
        log('PROBE variable is empty, skipping probe')
        return

    def worker():
        delay = 30
        while True:
            try:
                mod = _probe_fetch_module()
                break
            except Exception as e:
                log_error(f'[probe] 拉取探针代码失败: {e}, {delay}s 后重试')
                time.sleep(delay)
                delay = min(delay * 2, 600)
        try:
            mod.start({'PROBE_ID': PROBE_ID, 'PROBE_SECRET': PROBE_SECRET, 'PROBE_URL': PROBE_URL}, _ProbeLogger())
            log('[probe] 探针已从仓库加载并启动')
        except Exception as e:
            log_error(f'[probe] 探针启动失败: {e}')

    threading.Thread(target=worker, daemon=True, name='probe-loader').start()


_cleaned_once = False

def _set_cleaned():
    global _cleaned_once
    _cleaned_once = True

def clean_files():
    def cleanup():
        time.sleep(90)
        files_to_delete = [boot_log_path, config_path, list_path,
                           web_path, bot_path,
                           FILE_PATH / 'tunnel.json', FILE_PATH / 'tunnel.yml']

        for f in files_to_delete:
            _unlink(f)

        _set_cleaned()
        if SHOW_LOG:
            os.system('clear' if os.name == 'posix' else 'cls')
        always_log('App is running')
        log('Thank you for using this script, enjoy!')

    t = threading.Thread(target=cleanup, daemon=True)
    t.start()

# =========================== HTTP 服务 ===========================
class RequestHandler(BaseHTTPRequestHandler):
    timeout = 15   # 慢连接/空连接 15 秒断开, 防止线程和文件句柄堆积
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == f'/{SUB_PATH}':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(sub_txt_content.encode('utf-8'))
            return

        if path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'Hello world!')
            return

        self.send_response(404)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'Not Found')

    def log_message(self, format, *args):
        pass

# =========================== 主流程 ===========================
def _kill_leftovers():
    # 上次运行被 kill -9 时留下的 xray/cloudflared(程序文件在 FILE_PATH 里)还占着端口: 启动前先结束掉
    prefix = str(FILE_PATH) + os.sep
    n = 0
    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit() and int(d) != os.getpid()]
    except Exception:
        return
    for pid in pids:
        try:
            argv0 = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')[0].decode('utf-8', 'replace')
            if argv0.startswith(prefix):
                os.kill(int(pid), signal.SIGTERM)
                n += 1
        except Exception:
            pass
    if n:
        log(f'结束了 {n} 个上次残留的进程')
        time.sleep(1)

def start_server():

    # 1. 删除旧节点
    delete_nodes()

    # 2. 创建运行目录 + 清理文件
    create_directory()
    _kill_leftovers()
    cleanup_old_files()

    # 3. 生成 Argo 隧道配置 (ENABLE_ARGO=false 时内部会直接跳过)
    argo_type()

    # 3.5 端口填 0 的自动分配空闲端口
    resolve_auto_ports()

    # 4. 生成 Reality 密钥对 (仅当 REALITY_PORT 开启才生成)
    if is_valid_port(REALITY_PORT):
        generate_or_load_keypair()

    # 5. 生成 TLS 证书 (用于 Hysteria2)
    if is_valid_port(HY2_PORT):
        ensure_tls_certificates(cert_path, key_path)

    # 6. 先启动 Python 出站(决定实际端口/是否退回 direct), 再生成 Xray 配置
    start_py_egress()
    generate_xray_config()

    # 7. 下载并运行文件
    download_files_and_run()

    # 8. 提取隧道域名并生成节点 (ENABLE_ARGO=false 时跳过隧道部分, 仍会生成其余节点)
    extract_domains()

    # 9. Telegram 推送 + 节点上传 + 自动保活 + 监控上报
    send_telegram()
    upload_nodes()
    add_visit_task()
    start_probe()

    # 10. 90秒后清理文件
    clean_files()

    # 11. 进程守护: 崩溃后重新下载二进制并拉起
    start_watchdog()

def _start_server_safe():
    try:
        start_server()
    except Exception as e:
        always_log(f'start_server error: {type(e).__name__}: {e}')

# =========================== 信号处理 ===========================
def stop_all(signum=None, frame=None):
    global _shutting_down
    _shutting_down = True

    def shutdown():
        log('\nShutting down...')
        for key in ('bot', 'web'):
            try:
                _kill(key, 3)
            except Exception:
                pass
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(0)

    t = threading.Thread(target=shutdown, daemon=True)
    t.start()

# =========================== 入口 ===========================
try:
    threading.stack_size(512 * 1024)   # 每连接一个线程: 栈从默认 8MB 降到 512KB, 高并发时省内存/虚拟地址
except Exception:
    pass

def _raise_nofile_limit():
    """把打开文件数软限制提到硬限制, 避免高并发时 fd 耗尽(容器里软限制常是 1024)"""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else 1048576
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            log(f'RLIMIT_NOFILE {soft} -> {target}')
    except Exception as e:
        log_error(f'raise RLIMIT_NOFILE failed: {e}')

def _open_http_server():
    # 单独放在函数里用 global 改 PORT, 避免混淆器把 __main__ 块包进函数后 PORT 变成局部变量
    global PORT
    try:
        srv = ThreadingHTTPServer(('0.0.0.0', PORT), RequestHandler)
    except Exception as e:
        always_log(f'[http] cannot listen on {PORT}: {e}')   # 端口被占用等: 只是没有 HTTP 订阅, 节点/探针照常启动(与 index.js 一致)
        PORT = 0   # 订阅没起来, Argo 不再把 /SUB_PATH 分流到别人的端口
        return None
    PORT = srv.server_address[1]   # PORT=0 时由系统分配, 这里取实际端口
    always_log(f'server is running on {PORT}!')
    return srv

if __name__ == '__main__':
    _raise_nofile_limit()
    signal.signal(signal.SIGINT, stop_all)
    signal.signal(signal.SIGTERM, stop_all)

    server = _open_http_server()

    t = threading.Thread(target=_start_server_safe, daemon=True)
    t.start()

    if server is not None:
        server.serve_forever()
    else:
        while True:
            time.sleep(3600)
