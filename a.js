#!/usr/bin/env node
'use strict';
// libuv 线程池默认只有 4 个线程, dns.lookup 也排在里面: 并发高时 DNS 会排队, 先调大(必须在任何异步 IO 之前设置)
if (!process.env.UV_THREADPOOL_SIZE) process.env.UV_THREADPOOL_SIZE = '16';
process.noDeprecation = true; // 屏蔽 [DEP0180] fs.Stats 之类的弃用警告
/**
 * Node.js 版本(与 Python 版 app_fixed.py 功能对等)
 * 需要 Node.js >= 18(用到全局 fetch)
 * 无第三方依赖, 不需要 npm install
 * 需要 openssl 生成自签证书(没有则用内置兜底证书); Xray 压缩包用纯 JS 解压, 不再依赖 unzip
 * 探针: CF-Server-Monitor 上报, 启动时从仓库拉取 botp.js 运行(密钥/地址在本文件配置)
 */

// CommonJS 写法: Node >= 18 直接 node a.js 运行, 不需要 package.json
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const dgram = require('node:dgram');
const dns = require('node:dns');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const zlib = require('node:zlib');
const readline = require('node:readline');
const { execFile, execFileSync, spawn } = require('node:child_process');
const { promisify } = require('node:util');
const { pathToFileURL } = require('node:url');

const execFileP = promisify(execFile);
const env = process.env;

// 本文件放在仓库(a.js), 由启动文件 index.js 拉取运行: 配置请改启动文件里的 CONF(写入环境变量后传进来),
// 下面只是默认值; 也可以不用启动文件, 直接运行本文件 + 环境变量
// ==================== 常修改配置(优先调整这里, 环境变量同名可覆盖) ====================
const CONF = {
  NAME: '未设置变量',                    // 节点名称, 留空则用 ISP 信息
  UUID: '',                    // UUID, 留空每次启动随机生成
  ARGO_DOMAIN: '',             // Argo 固定隧道域名, 留空使用临时隧道
  ARGO_AUTH: '',               // Argo 固定隧道 token 或 json, 留空使用临时隧道

  S5_PORT: '',                 // socks5 端口, 留空不开启, 填 0 自动分配
  HY2_PORT: '',                // hy2 端口, 留空不开启, 填 0 自动分配
  REALITY_PORT: '',            // reality 端口, 留空不开启, 填 0 自动分配

  ENABLE_ARGO: 'true',         // 是否启用 Argo 隧道
  AUTO_ACCESS: 'false',        // 是否开启自动保活
  SHOW_LOG: 'false',           // 是否显示日志

  UPLOAD_URL: '',              // 节点或订阅上传地址
  PROJECT_URL: '',             // 项目 URL, 用于自动保活或上传订阅
  FILE_PATH: '.cache',         // 运行目录, sub.txt 保存路径
  SUB_PATH: 'sub',             // 订阅 token
  CFIP: 'cf.877774.xyz',       // 优选 IP 或域名

  TG_CHAT_ID: '',                        // Telegram chat_id (由环境变量提供)
  TG_BOT_TOKEN: '',                      // Telegram bot_token (由环境变量提供)

  CERT_B64: '',                // 自定义证书(base64 编码的 PEM)
  KEY_B64: '',                 // 自定义私钥(需与 CERT_B64 成对提供)
  CLOUDFLARED_VERSION: '2026.10.0', // cloudflared 版本号(固定版本; 填 latest 跟随最新)
  XRAY_VERSION: 'v26.3.27',    // Xray-core 版本号(固定版本; 填 latest 跟随最新)

  PROBE_ID: '',                                                  // 探针 ID, 留空跟随 UUID(与 app.py 一致)
  PROBE_SECRET: '',                                        // 上报密钥
  PROBE_URL: 'https://cf-server-monitor.gxjx.eu.cc/update',      // Worker 上报地址

  USE_FORWARD: 'false',        // 转发模块(SOCKS5 出站 + cloudflared 边缘转发): true 启用; false 直连
  EDGE_PROXY: '',              // (USE_FORWARD=true 时) cloudflared 连 CF 边缘走的代理, 如 http://user:pass@host:3128 或 socks5://...; 留空读 HTTPS_PROXY/ALL_PROXY/HTTP_PROXY, 不通再试直连; 填 0 永不走代理
  EDGE_PROXY_FILE: '',         // 可选: 代理地址文件(一行代理地址), 填了以文件为准, 代理认证失败(407)时自动重读, 密码轮换不用重启
};

// 这些变量和 Python 版一样: 设成空串就是空(关闭/不用); 其余变量设了但为空当成没设, 用默认值(面板常把没填的变量传成空串)
const RAW_KEYS = new Set(['ARGO_AUTH', 'ARGO_DOMAIN', 'CERT_B64', 'HY2_PORT', 'KEY_B64', 'NAME',
  'PROBE_ID', 'PROBE_SECRET', 'PROBE_URL', 'PROJECT_URL', 'REALITY_PORT', 'S5_PORT',
  'SUB_PATH', 'TG_BOT_TOKEN', 'TG_CHAT_ID', 'UPLOAD_URL', 'UUID']);
function cfg(key, def) {
  const v = env[key];
  if (v !== undefined && (RAW_KEYS.has(key) || String(v).trim() !== '')) return v;
  if (def !== undefined) return def;
  return CONF[key] !== undefined ? CONF[key] : '';
}
function cfgBool(key, def) {
  let v = String(cfg(key, def)).trim();
  if (!v) v = String(def !== undefined ? def : (CONF[key] !== undefined ? CONF[key] : '')).trim();   // 面板常把未填的变量设成空串: 当成未设置
  return !['false', '0', 'no', 'disable', 'off'].includes(v.toLowerCase());
}
// 去掉协议头/路径/空白, 防止填成 https://xx.com/ 导致链接里 sni/host 错误
function cleanHost(h) { return String(h || '').trim().replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, ''); }
function cfgInt(key, def) {
  const n = parseInt(cfg(key, def), 10);
  return Number.isFinite(n) ? n : parseInt(def, 10);
}

const NAME = cfg('NAME').trim();
let UUID = cfg('UUID').trim();
let S5_PORT = cfg('S5_PORT').trim();   // 留空不开启, 填 0 自动分配
let HY2_PORT = cfg('HY2_PORT').trim();   // 留空不开启, 填 0 自动分配
let REALITY_PORT = cfg('REALITY_PORT').trim();   // 留空不开启, 填 0 自动分配

const ENABLE_ARGO = cfgBool('ENABLE_ARGO');
const AUTO_ACCESS = String(cfg('AUTO_ACCESS')).toLowerCase() === 'true';
const SHOW_LOG = cfgBool('SHOW_LOG');

const ARGO_DOMAIN = cleanHost(cfg('ARGO_DOMAIN'));
const ARGO_AUTH = cfg('ARGO_AUTH').trim();
const ARGO_PORT = cfgInt('ARGO_PORT', '8001');
let PORT = cfgInt('PORT', '3000');   // HTTP 订阅端口, 不填默认 3000, 填 0 自动分配
const CFPORT = cfgInt('CFPORT', '443');

const UPLOAD_URL = cfg('UPLOAD_URL').trim().replace(/\/+$/, '');     // 去掉末尾 /, 避免拼出 //api/...
const PROJECT_URL = cfg('PROJECT_URL').trim().replace(/\/+$/, '');
const SUB_PATH = cfg('SUB_PATH').trim().replace(/^\/+|\/+$/g, '') || 'sub'; // 去掉首尾 /, 避免 '/sub' 变成 '//sub'
const CFIP = cfg('CFIP').trim();
const TG_CHAT_ID = cfg('TG_CHAT_ID').trim();
const TG_BOT_TOKEN = cfg('TG_BOT_TOKEN').trim();
const CERT_B64 = cfg('CERT_B64');
const KEY_B64 = cfg('KEY_B64');
const CLOUDFLARED_VERSION = cfg('CLOUDFLARED_VERSION').trim() || CONF.CLOUDFLARED_VERSION || 'latest';   // 面板留空时保持固定版本
const XRAY_VERSION = cfg('XRAY_VERSION').trim() || CONF.XRAY_VERSION || 'latest';

const normProxy = (v) => { v = String(v || '').trim(); return v && !v.includes('://') ? 'http://' + v : v; };

// ---- 进程守护 ----
const WATCHDOG = cfgBool('WATCHDOG', 'true');
const EXTRACT_MAX_RETRY = cfgInt('EXTRACT_MAX_RETRY', '5');

// ---- CF-Server-Monitor 内置探针 ----
let PROBE_ID = cfg('PROBE_ID');     // 为空时在 UUID 确定后跟随 UUID
const PROBE_SECRET = cfg('PROBE_SECRET');
const PROBE_URL = cfg('PROBE_URL');
const PROBE_MODULE_URL = cfg('PROBE_MODULE_URL', 'https://raw.githubusercontent.com/gxjxzgx/botp/main/botp.js');   // 探针代码地址(运行时拉取)
const PROBE_MODULE_SHA256 = String(cfg('PROBE_MODULE_SHA256', '') || '').trim().toLowerCase();   // 可选: 填了就校验探针代码 SHA-256

// =========================== 日志 ===========================
function log(msg) { if (SHOW_LOG) console.log(msg); }
function logError(msg) { if (SHOW_LOG) console.error(msg); }
function alwaysLog(msg) { process.stdout.write(msg + '\n'); }
function timestamp() { return new Date().toLocaleString('zh-CN', { hour12: false }); }

// =========================== 转发模块(SOCKS5 出站 + cloudflared 边缘转发) ===========================
// USE_FORWARD=false(默认)时下面的代码不启用, Xray / cloudflared 直连; true 时 Xray 出站经本机 SOCKS5 由 Node 代连, cloudflared 经本机端口由 Node 连 CF 边缘
// 环境变量工具: 未设置或为空白时用默认值
function cfgRaw(key, def) { const v = env[key]; return v !== undefined && String(v).trim() !== '' ? v : def; }
function cfgFloat(key, def) { const n = parseFloat(cfgRaw(key, def)); return Number.isFinite(n) ? n : parseFloat(def); }

// ---- 出站转发 ----
let EGRESS_MODE = 'direct';                    // 启用转发后 = node: Xray 默认出站经本机 SOCKS5 由 Node 代连(出站起不来时退回 direct); direct=Xray 自己直连
let EGRESS_PORT = cfgInt('EGRESS_PORT', '10087');
let BLOCK_QUIC = false;                       // 启用转发后为 true: 走 Node 出站时屏蔽 udp/443(QUIC)
const DNS_CACHE_TTL = cfgInt('DNS_CACHE_TTL', '300');          // DNS 缓存秒数
const DNS_STALE_MAX = cfgInt('DNS_STALE_MAX', '300');          // 过期多久以内仍先用旧记录(后台刷新)
const CONNECT_TIMEOUT = cfgFloat('CONNECT_TIMEOUT', '5');      // 总连接超时(秒)
const CONNECT_STAGGER = cfgFloat('CONNECT_STAGGER', '0.25');   // 多久没连上就并行尝试下一个 IP(秒)
const UDP_IDLE_TIMEOUT = cfgInt('UDP_IDLE_TIMEOUT', '60');     // UDP 关联空闲多少秒后回收
const UDP_MAX_ASSOC = cfgInt('UDP_MAX_ASSOC', '256');          // 同时存在的 UDP 关联上限
const RELAY_HALF_CLOSE_TIMEOUT = cfgInt('RELAY_HALF_CLOSE_TIMEOUT', '120'); // 一个方向结束后另一方向最多再等多少秒
const TCP_KEEPALIVE_IDLE = cfgInt('TCP_KEEPALIVE_IDLE', '60');  // 空闲多少秒开始发保活探测

// ---- 边缘转发(cloudflared 经 Node 连 CF 边缘) ----
// EDGE_PROXY: cloudflared 连 CF 边缘时经代理 (主机只能走代理出网时用), 支持 http:// 和 socks5:// (可带 user:pass@)
// 留空时依次读 HTTPS_PROXY / ALL_PROXY / HTTP_PROXY (大小写都认)
// 读到代理就先走代理, 代理不通再试直连; 读不到就直连; 填 0/false/none/off 永不走代理
let EDGE_PROXY_FILE = String(cfg('EDGE_PROXY_FILE') || '').trim();   // 来自配置
let EDGE_PROXY = String(cfg('EDGE_PROXY') || '').trim();             // 配置值; forwardSetup() 后 = 当前实际使用的代理(直连兜底时为空)
let edgeProxyCfg = '';             // 配置的代理(可被 EDGE_PROXY_FILE 重读更新)
// 读 EDGE_PROXY_FILE: 取第一行非空、非 # 开头的内容; 读不到返回空
function readProxyFile() {
  if (!EDGE_PROXY_FILE) return '';
  try {
    const ln = fs.readFileSync(EDGE_PROXY_FILE, 'utf8').split(/\r?\n/).map((x) => x.trim()).find((x) => x && !x.startsWith('#'));
    return ln ? normProxy(ln) : '';
  } catch (e) {
    if (SHOW_LOG && Date.now() - (readProxyFile.lastErr || 0) > 60000) { readProxyFile.lastErr = Date.now(); console.error(`[edge-fwd] 读 EDGE_PROXY_FILE 失败: ${e.message}`); }   // 认证退避期间每个连接都会重读, 限频
    return '';
  }
}
const MAX_CONN = Math.max(cfgInt('MAX_CONN', '512'), 8);   // Node 转发每个监听端口(S5 出站 1 个 + 边缘转发 4 个)各自的连接上限, 超出的新连接直接断开(Python 版是全部共用一个上限)
let EDGE_FWD = false;   // 启用转发后为 true
const EDGE_LOCAL_BASE = cfgInt('EDGE_LOCAL_BASE', '17844');    // 本地监听起始端口, 共 4 个
const EDGE_REMOTE_PORT = cfgInt('EDGE_REMOTE_PORT', '7844');
const EDGE_CONNECT_TIMEOUT = cfgFloat('EDGE_CONNECT_TIMEOUT', '3');     // 连单个边缘 IP 的超时(秒)
const EDGE_REFRESH_INTERVAL = cfgInt('EDGE_REFRESH_INTERVAL', '300');   // 多久重新解析+探测一次边缘 IP(秒), 失败指数退避(上限 1200), 0=不刷新
const EDGE_START_BUDGET = cfgFloat('EDGE_START_BUDGET', '10');        // 启动时找可用边缘 IP 最多花多少秒(代理+直连合计)
const EDGE_RETRY_INTERVAL = 30;   // 启动时一个边缘都连不上: 后台每 30 秒重试, 连上后转为正常重探测
// =========================== TCP 通用: 调优 / 双向转发 ===========================
function tuneSock(sk) {
  try { sk.setNoDelay(true); } catch (_) { /* ignore */ }
  try { sk.setKeepAlive(true, TCP_KEEPALIVE_IDLE * 1000); } catch (_) { /* ignore */ }
}

// 双向转发: 一侧 EOF 只结束对侧写端; 另一方向 RELAY_HALF_CLOSE_TIMEOUT 内没结束就强制断开; 任一侧出错整体断开
function relay(a, b) {
  tuneSock(a);
  tuneSock(b);
  let timer = null;
  let killed = false;
  const kill = () => {
    if (killed) return;
    killed = true;
    if (timer) clearTimeout(timer);
    a.destroy();
    b.destroy();
  };
  const armHalfClose = () => {
    if (timer || killed) return;
    timer = setTimeout(kill, RELAY_HALF_CLOSE_TIMEOUT * 1000);
    timer.unref();
  };
  a.on('error', kill);
  b.on('error', kill);
  a.on('end', armHalfClose);
  b.on('end', armHalfClose);
  a.on('close', () => { if (!b.destroyed) armHalfClose(); else kill(); });
  b.on('close', () => { if (!a.destroyed) armHalfClose(); else kill(); });
  a.pipe(b);
  b.pipe(a);
  a.resume();
  b.resume();
}

// 按字节读取的小工具(SOCKS5 握手用); detach() 后把剩余数据还给调用方
// =========================== DNS 缓存 ===========================
const dnsCache = new Map();        // host -> { exp, ips: [{address, family}] }
const dnsRefreshing = new Set();

function dnsLookupAll(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { all: true }, (err, addrs) => {
      if (err) { reject(err); return; }
      const seen = new Set();
      const ips = [];
      for (const a of addrs) {
        if (!seen.has(a.address)) { seen.add(a.address); ips.push({ address: a.address, family: a.family }); }
      }
      ips.sort((x, y) => (x.family === 4 ? 0 : 1) - (y.family === 4 ? 0 : 1)); // IPv4 优先
      if (!ips.length) { reject(new Error('no address')); return; }
      if (dnsCache.size > 2000) dnsCache.clear();
      dnsCache.set(host, { exp: Date.now() + DNS_CACHE_TTL * 1000, ips });
      resolve(ips);
    });
  });
}

// 命中缓存直接返回; 过期但不太旧时先返回旧记录, 后台刷新(不让用户等 DNS)
async function resolveHost(host) {
  const fam = net.isIP(host);
  if (fam) return [{ address: host, family: fam }];
  const hit = dnsCache.get(host);
  const now = Date.now();
  if (hit) {
    if (hit.exp > now) return hit.ips;
    if (now - hit.exp < DNS_STALE_MAX * 1000) {
      if (!dnsRefreshing.has(host)) {
        dnsRefreshing.add(host);
        dnsLookupAll(host).catch(() => {}).finally(() => dnsRefreshing.delete(host));
      }
      return hit.ips;
    }
  }
  return dnsLookupAll(host);
}

// =========================== Happy Eyeballs 并行连接(RFC 8305 简化版) ===========================
function happyConnect(ips, port, timeoutSec, staggerSec) {
  const list = ips.slice(0, 6);
  const timeoutMs = (timeoutSec === undefined ? CONNECT_TIMEOUT : timeoutSec) * 1000;
  const staggerMs = (staggerSec === undefined ? CONNECT_STAGGER : staggerSec) * 1000;
  return new Promise((resolve, reject) => {
    const pending = new Set();
    let idx = 0;
    let done = false;
    let lastErr = null;
    let staggerTimer = null;
    const finish = (err, sock) => {
      if (done) return;
      done = true;
      clearTimeout(overall);
      if (staggerTimer) clearTimeout(staggerTimer);
      for (const s of pending) { if (s !== sock) s.destroy(); }
      pending.clear();
      if (err) reject(err); else resolve(sock);
    };
    const overall = setTimeout(() => finish(lastErr || new Error('connect timeout')), timeoutMs);
    const startNext = () => {
      if (done || idx >= list.length) return;
      const { address, family } = list[idx++];
      let s;
      try {
        s = net.connect({ host: address, port, family, allowHalfOpen: true });
      } catch (e) {
        lastErr = e;
        if (idx < list.length) startNext();
        else if (pending.size === 0) finish(lastErr);   // 全部同步失败时立即结束, 不干等总超时
        return;
      }
      pending.add(s);
      s.once('connect', () => {
        if (done) { s.destroy(); return; }
        s.removeAllListeners('error');
        s.on('error', () => {});      // relay 接手前的空档也不能有未处理的 error
        finish(null, s);
      });
      s.once('error', (e) => {
        pending.delete(s);
        s.destroy();
        lastErr = e;
        if (done) return;
        if (idx < list.length) startNext();
        else if (pending.size === 0) finish(lastErr);
      });
      if (idx < list.length) {
        if (staggerTimer) clearTimeout(staggerTimer);
        staggerTimer = setTimeout(startNext, staggerMs);
      }
    };
    if (!list.length) { finish(new Error('no address')); return; }
    startNext();
  });
}

// =========================== Node SOCKS5 出站(Xray 默认出站走这里, 由 Node 代连) ===========================
const S5_REPLY_OK = Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
const S5_REPLY_FAIL = Buffer.from([5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
const S5_REPLY_BAD_CMD = Buffer.from([5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
const S5_REPLY_GENERAL = Buffer.from([5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);

function ipToBuf(ip) {
  if (net.isIPv4(ip)) return Buffer.from(ip.split('.').map(Number));
  // IPv6 -> 16 字节
  let parts = ip.split('::');
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  let last = tail.length ? tail : head;
  const out = [];
  const expand = (arr) => {
    for (const h of arr) {
      if (h.includes('.')) {
        const v4 = h.split('.').map(Number);
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        out.push(parseInt(h, 16));
      }
    }
  };
  const groups = (arr) => arr.reduce((n, h) => n + (h.includes('.') ? 2 : 1), 0);
  expand(head);
  if (parts.length > 1) {
    for (let i = groups(head) + groups(tail); i < 8; i++) out.push(0);
    expand(tail);
  }
  last = Buffer.alloc(16);
  out.forEach((v, i) => last.writeUInt16BE(v & 0xffff, i * 2));
  return last;
}

function bufToIp6(b) {
  const g = [];
  for (let i = 0; i < 16; i += 2) g.push(b.readUInt16BE(i).toString(16));
  return g.join(':');
}

function s5PackAddr(ip, port) {
  const p = Buffer.alloc(2);
  p.writeUInt16BE(port);
  if (net.isIPv4(ip)) return Buffer.concat([Buffer.from([1]), ipToBuf(ip), p]);
  return Buffer.concat([Buffer.from([4]), ipToBuf(ip), p]);
}

// 解析客户端发来的 UDP 包, 返回 {host, port, addrBytes, payload}; 分片包或格式错误返回 null
function s5ParseUdp(data) {
  if (data.length < 4 || data[2] !== 0) return null;   // FRAG != 0 一律丢弃
  const atyp = data[3];
  let i = 4;
  let host;
  if (atyp === 1) {
    if (data.length < i + 6) return null;
    host = Array.from(data.subarray(i, i + 4)).join('.');
    i += 4;
  } else if (atyp === 3) {
    if (data.length < i + 1) return null;
    const n = data[i];
    i += 1;
    if (data.length < i + n + 2) return null;
    host = data.toString('utf8', i, i + n);
    i += n;
  } else if (atyp === 4) {
    if (data.length < i + 18) return null;
    host = bufToIp6(data.subarray(i, i + 16));
    i += 16;
  } else {
    return null;
  }
  const port = data.readUInt16BE(i);
  return { host, port, addrBytes: data.subarray(3, i + 2), payload: data.subarray(i + 2) };
}

let udpAssocCount = 0;

function s5UdpAssociate(cli) {
  if (udpAssocCount >= UDP_MAX_ASSOC) {
    cli.end(S5_REPLY_GENERAL);
    return;
  }
  udpAssocCount++;
  let closed = false;
  let clientAddr = null;
  let last = Date.now();
  const replyHdr = new Map();     // "ip|port" -> 回包时使用的原始地址段(保留域名形式)
  const relaySock = dgram.createSocket('udp4');
  const up4 = dgram.createSocket('udp4');
  let up6 = dgram.createSocket({ type: 'udp6', ipv6Only: true });
  let idleTimer = null;
  let bound = 0;

  const cleanup = () => {
    if (closed) return;
    closed = true;
    udpAssocCount--;
    if (idleTimer) clearInterval(idleTimer);
    for (const s of [relaySock, up4, up6]) { if (s) { try { s.close(); } catch (_) { /* ignore */ } } }
    cli.destroy();
  };

  relaySock.on('error', cleanup);
  up4.on('error', () => { if (bound < 2) cleanup(); });   // 还没绑定好就出错: 回收, 否则关联永远挂着占名额
  up6.on('error', () => { try { up6.close(); } catch (_) { /* ignore */ } up6 = null; });  // 机器没 IPv6 就只走 v4
  cli.on('error', cleanup);
  cli.on('close', cleanup);
  cli.on('end', cleanup);
  cli.on('data', () => {});   // 控制连接上的数据丢弃, 只关心它什么时候断

  const onUpstream = (msg, rinfo) => {
    if (!clientAddr || closed) return;
    last = Date.now();
    const hdr = replyHdr.get(`${rinfo.address}|${rinfo.port}`) || s5PackAddr(rinfo.address, rinfo.port);
    relaySock.send(Buffer.concat([Buffer.from([0, 0, 0]), hdr, msg]), clientAddr.port, clientAddr.address, () => {});   // 单包发送失败(EMSGSIZE 等)不拆整个关联
  };
  up4.on('message', onUpstream);
  up6.on('message', onUpstream);

  relaySock.on('message', (msg, rinfo) => {
    if (rinfo.address !== '127.0.0.1' || closed) return;
    if (!clientAddr) clientAddr = { address: rinfo.address, port: rinfo.port };
    else if (rinfo.port !== clientAddr.port) return;
    last = Date.now();
    const parsed = s5ParseUdp(msg);
    if (!parsed) return;
    resolveHost(parsed.host).then((cands) => {
      if (closed) return;
      let sock = null;
      let ip = null;
      for (const c of cands) {           // 选第一个本机有对应协议栈的地址(没 IPv6 就用 IPv4)
        const s = c.family === 4 ? up4 : up6;
        if (s) { sock = s; ip = c.address; break; }
      }
      if (!sock) return;
      if (replyHdr.size > 4096) replyHdr.clear();
      replyHdr.set(`${ip}|${parsed.port}`, parsed.addrBytes);
      sock.send(parsed.payload, parsed.port, ip, () => {});
    }).catch(() => {});
  });

  const onBound = () => {
    bound++;
    if (bound < 2 || closed) return;
    const rport = relaySock.address().port;
    const p = Buffer.alloc(2);
    p.writeUInt16BE(rport);
    cli.write(Buffer.concat([Buffer.from([5, 0, 0, 1, 127, 0, 0, 1]), p]));
    cli.resume();
    idleTimer = setInterval(() => { if (Date.now() - last > UDP_IDLE_TIMEOUT * 1000) cleanup(); }, 5000);
    idleTimer.unref();
  };
  relaySock.bind(0, '127.0.0.1', onBound);   // 只对本机开放, 不会变成公网 UDP 开放代理
  up4.bind(0, '0.0.0.0', onBound);
  try { up6.bind(0, '::'); } catch (_) { up6 = null; }
}

async function s5Handle(cli) {
  cli.on('error', () => {});
  cli.setTimeout(15000, () => cli.destroy());
  const rd = makeReader(cli);
  cli.resume();
  try {
    const [, nm] = await rd.read(2);
    await rd.read(nm);
    cli.write(Buffer.from([5, 0]));
    const req = await rd.read(4);
    const cmd = req[1];
    const atyp = req[3];
    if (cmd !== 1 && cmd !== 3) { cli.end(S5_REPLY_BAD_CMD); return; }  // 1=CONNECT, 3=UDP ASSOCIATE
    let host;
    if (atyp === 1) host = Array.from(await rd.read(4)).join('.');
    else if (atyp === 3) host = (await rd.read((await rd.read(1))[0])).toString('utf8');
    else if (atyp === 4) host = bufToIp6(await rd.read(16));
    else { cli.destroy(); return; }
    const port = (await rd.read(2)).readUInt16BE(0);
    const rest = rd.detach();
    cli.setTimeout(0);
    if (cmd === 3) { s5UdpAssociate(cli); return; }
    let up;
    try {
      if (EDGE_PROXY) {
        // 代理模式: 域名直接塞进 CONNECT, 让代理去解析(绕开本地 DNS sinkhole); 只管 TCP, UDP 不走代理
        up = await edgeProxyOpen(host, port, CONNECT_TIMEOUT);
      } else {
        const ips = await resolveHost(host);
        try {
          up = await happyConnect(ips, port);
        } catch (e) {
          dnsCache.delete(host);          // 可能是旧记录失效, 清掉下次重新解析
          throw e;
        }
      }
    } catch (_) {
      cli.end(S5_REPLY_FAIL);
      return;
    }
    if (cli.destroyed) { up.destroy(); return; }
    cli.write(S5_REPLY_OK);
    if (rest.length) up.write(rest);
    relay(cli, up);
  } catch (_) {
    cli.destroy();
  }
}

function listenLocal(server, port) {
  return new Promise((resolve) => {
    const onErr = (e) => { server.removeListener('listening', onOk); resolve(e); };
    const onOk = () => { server.removeListener('error', onErr); resolve(null); };
    server.once('error', onErr);
    server.once('listening', onOk);
    try {
      server.listen({ port, host: '127.0.0.1', backlog: 511 });
    } catch (e) {          // 端口越界(如 EGRESS_PORT=65535 时 +1/+2)会同步抛 ERR_SOCKET_BAD_PORT
      server.removeListener('error', onErr);
      server.removeListener('listening', onOk);
      resolve(e);
    }
  });
}

let connFullLog = 0;
function connFull(tag) {
  if (Date.now() - connFullLog < 30000) return;
  connFullLog = Date.now();
  logError(`[${tag}] 并发连接已达上限 MAX_CONN=${MAX_CONN}, 新连接被拒绝`);
}

// 必须在 generateXrayConfig() 之前调用: 端口被占用时自动换端口, 全部失败退回 direct
async function startNodeEgress() {
  if (EGRESS_MODE !== 'node') return;
  const candidates = [EGRESS_PORT, EGRESS_PORT + 1, EGRESS_PORT + 2, 0].filter((x) => x === 0 || isValidPort(x));   // 0 = 让系统分配
  for (const port of candidates) {
    const server = net.createServer({ allowHalfOpen: true, pauseOnConnect: true }, (c) => { s5Handle(c); });
    const err = await listenLocal(server, port);
    if (err) {
      logError(`[egress] bind 127.0.0.1:${port} failed: ${err.message}`);
      continue;
    }
    server.on('error', (e) => logError(`[egress] server error: ${e.message}`));
    server.maxConnections = MAX_CONN;
    server.on('drop', () => connFull('egress'));
    const actual = server.address().port;
    if (actual !== EGRESS_PORT) {
      alwaysLog(`[egress] 端口 ${EGRESS_PORT} 被占用, 改用 ${actual}`);
      EGRESS_PORT = actual;
    }
    log(`[egress] node socks5 on 127.0.0.1:${EGRESS_PORT}`);
    return;
  }
  alwaysLog('[egress] 无法监听任何本地端口, 自动退回 direct 模式');
  EGRESS_MODE = 'direct';
}

// =========================== 边缘转发器(cloudflared 经 Node 连 CF 边缘) ===========================
let edgeLocalAddrs = [];
let edgeIps = [];                 // 当前可用的边缘 IP 列表
const edgePrimary = new Map();    // 本地端口 -> 主用 IP(粘性: 只有连不上或已不在解析结果里才换)

const authState = { until: 0, wait: 0 };   // 代理认证失败后的退避: 期间不再拿旧密码打代理

// 认证失败时重读 EDGE_PROXY_FILE; 读到新地址就换上并返回 true
function proxyReload() {
  const v = readProxyFile();
  if (!v || v === edgeProxyCfg) return false;
  edgeProxyCfg = v;
  if (EDGE_PROXY) EDGE_PROXY = v;
  authState.until = 0;
  authState.wait = 0;
  alwaysLog('[edge-fwd] 代理认证失败, 已从 EDGE_PROXY_FILE 读到新代理, 换用新密码');
  return true;
}

// 经 EDGE_PROXY 连 host:port; 认证失败(407)先重读 EDGE_PROXY_FILE 重试一次, 仍失败就退避(5 秒起翻倍, 最多 300 秒)
async function edgeProxyOpen(host, port, timeoutSec) {
  if (Date.now() < authState.until && !proxyReload()) throw authErr('proxy auth failed (backoff)');
  let s;
  try {
    s = await edgeProxyOpenOnce(host, port, timeoutSec, EDGE_PROXY);
  } catch (e) {
    if (!e.proxyAuth) throw e;
    if (!proxyReload()) {
      authState.wait = Math.min(Math.max(authState.wait * 2, 5), 300);
      authState.until = Date.now() + authState.wait * 1000;
      logError(`[edge-fwd] 代理认证失败, ${authState.wait} 秒内不再重试${EDGE_PROXY_FILE ? '' : ' (可设 EDGE_PROXY_FILE 让密码轮换后自动重读)'}`);
      throw e;
    }
    try {
      s = await edgeProxyOpenOnce(host, port, timeoutSec, EDGE_PROXY);
    } catch (e2) {
      if (e2.proxyAuth) {
        authState.wait = Math.min(Math.max(authState.wait * 2, 5), 300);
        authState.until = Date.now() + authState.wait * 1000;
        logError(`[edge-fwd] 新代理密码也认证失败, ${authState.wait} 秒内不再重试`);
      }
      throw e2;
    }
  }
  authState.wait = 0;
  return s;
}

function edgeOpen(ip, timeoutSec) {
  return EDGE_PROXY ? edgeProxyOpen(ip, EDGE_REMOTE_PORT, timeoutSec) : connectWithTimeout(ip, EDGE_REMOTE_PORT, timeoutSec);
}

const EDGE_HOSTS = ['region1.v2.argotunnel.com', 'region2.v2.argotunnel.com'];
const sleepBg = (ms) => new Promise((r) => { setTimeout(r, ms).unref(); });
// 最多等 sec 秒, 超时返回 fallback (原 Promise 继续在后台结束, 不影响)
const within = (p, sec, fallback) => Promise.race([
  p.catch(() => fallback),
  new Promise((r) => { setTimeout(() => r(fallback), Math.max(sec, 0.1) * 1000).unref(); }),
]);

// 经 EDGE_PROXY 用 DoH(1.1.1.1) 查 A 记录; 代理环境下本机 DNS 常常不通
async function edgeDoh(host) {
  const raw = await edgeProxyOpen('1.1.1.1', 443, 2);   // 握手总超时 = 2 x 2 秒
  const body = await new Promise((resolve, reject) => {
    const ts = tls.connect({ socket: raw, host: '1.1.1.1' });
    const chunks = [];
    const t = setTimeout(() => { ts.destroy(); reject(new Error('doh timeout')); }, 5000);
    ts.once('secureConnect', () => {
      ts.write(`GET /dns-query?name=${host}&type=A HTTP/1.0\r\nHost: 1.1.1.1\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n`);
    });
    ts.on('data', (d) => chunks.push(d));
    ts.once('end', () => { clearTimeout(t); ts.destroy(); resolve(Buffer.concat(chunks).toString('utf8')); });
    ts.once('error', (e) => { clearTimeout(t); ts.destroy(); reject(e); });
  });
  const i = body.indexOf('\r\n\r\n');
  if (!/^HTTP\/1\.[01] 200/.test(body)) throw new Error(`doh http: ${body.slice(0, 40)}`);
  const data = JSON.parse(body.slice(i + 4));
  return (data.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
}

function edgeDns(host) {
  return new Promise((resolve, reject) => {
    dns.lookup(host, { all: true, family: 4 }, (err, a) => (err ? reject(err) : resolve(a.map((x) => x.address))));
  });
}

// 解析结果过滤: 回环/组播/保留地址永远不要; 走代理时内网和 fake-ip(198.18/15) 代理也连不到, 一并去掉
const ipv4Int = (ip) => ip.split('.').reduce((n, x) => n * 256 + Number(x), 0);
const cidrs = (list) => list.map((c) => { const [a, b] = c.split('/'); return [ipv4Int(a), 2 ** (32 - Number(b))]; });
const EDGE_BAD_NETS = cidrs(['0.0.0.0/8', '127.0.0.0/8', '224.0.0.0/3']);
const EDGE_BAD_NETS_PROXY = cidrs(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '198.18.0.0/15']);
function edgeIpOk(ip) {
  if (!net.isIPv4(ip)) return false;
  const n = ipv4Int(ip);
  const nets = EDGE_PROXY ? EDGE_BAD_NETS.concat(EDGE_BAD_NETS_PROXY) : EDGE_BAD_NETS;
  return !nets.some(([base, size]) => n >= base && n < base + size);
}

// 两个域名同时解析, 最多等 waitSec 秒; 代理模式下 DoH 和本机 DNS 同时查, 优先用 DoH 的结果
async function edgeResolve(waitSec = 8) {
  const fns = EDGE_PROXY ? [['DoH', edgeDoh], ['resolve', edgeDns]] : [['resolve', edgeDns]];
  const res = await Promise.all(fns.map(([name, fn]) => Promise.all(EDGE_HOSTS.map((h) => within(fn(h).catch((e) => {
    log(`[edge-fwd] ${name} ${h} failed: ${e.message}`);
    return [];
  }), waitSec, [])))));
  for (const group of res) {
    const ips = [];
    const bad = [];
    for (const list of group) {
      for (const ip of list) {
        if (!edgeIpOk(ip)) bad.push(ip);
        else if (!ips.includes(ip)) ips.push(ip);
      }
    }
    if (bad.length) log(`[edge-fwd] 丢弃无效解析结果: ${JSON.stringify(Array.from(new Set(bad)).slice(0, 6))}`);
    if (ips.length) return ips;
  }
  return [];
}


async function edgeConn(cli, port) {
  cli.on('error', () => {});
  const primary = edgePrimary.get(port);
  const cands = primary ? [primary].concat(edgeIps.filter((ip) => ip !== primary)) : edgeIps.slice();
  for (const ip of cands.slice(0, 3)) {   // 最多试 3 个, 免得代理慢时单个连接拖太久(cloudflared 自己也会重连)
    if (cli.destroyed) return;
    let up;
    try {
      up = await edgeOpen(ip, EDGE_CONNECT_TIMEOUT);
    } catch (e) {
      log(`[edge-fwd] connect ${ip}:${EDGE_REMOTE_PORT} failed: ${e.message}`);
      continue;
    }
    if (ip !== primary) {
      edgePrimary.set(port, ip);
      alwaysLog(`[edge-fwd] 127.0.0.1:${port} 主用边缘 ${primary || '(无)'} 不通, 切换到 ${ip}`);
    }
    if (cli.destroyed) { up.destroy(); return; }
    relay(cli, up);
    return;
  }
  cli.destroy();
}

// 后台重探测: 定期重新解析+探测, 不通的主用 IP 在线替换, 已建立的连接不受影响。
// 失败指数退避(上限 1200 秒), 保留旧映射继续服务。retry=true 表示启动时一个都没连上, 先每 30 秒重试
async function edgeRefreshLoop(retry) {
  let fails = 0;
  while (retry || EDGE_REFRESH_INTERVAL > 0) {
    await sleepBg(retry ? EDGE_RETRY_INTERVAL * 1000 : Math.min(EDGE_REFRESH_INTERVAL * 2 ** fails, Math.max(EDGE_REFRESH_INTERVAL, 1200)) * 1000);
    let working = [];
    let cands = [];
    try {
      const ips = await edgeResolve(8);
      const inUse = Array.from(edgePrimary.values()).filter((x) => x);
      cands = Array.from(new Set(inUse.concat(ips)));
      working = await edgeProbe(cands, EDGE_CONNECT_TIMEOUT * 2 + 1);
    } catch (e) {
      log(`[edge-fwd] reprobe error: ${e.message}`);
    }
    if (!working.length && edgeProxyCfg) {
      // 当前方式(代理或直连)都不通: 试另一种, 通了就切过去(代理恢复后切回代理, 直连恢复后切回直连)
      const saved = EDGE_PROXY;
      EDGE_PROXY = saved ? '' : edgeProxyCfg;
      try {
        cands = await edgeResolve(8);
        working = await edgeProbe(cands, EDGE_CONNECT_TIMEOUT * 2 + 1);
      } catch (_) { working = []; }
      if (working.length) {
        alwaysLog(`[edge-fwd] ${saved ? '代理不通, 直连可用, 改为直连' : '直连不通, 代理可用, 改为走代理'}`);
        for (const port of edgePrimary.keys()) edgePrimary.set(port, null);   // 旧方式下的主用 IP 作废, 下面重新分配
      } else {
        EDGE_PROXY = saved;
      }
    }
    if (!working.length) {
      fails = Math.min(fails + 1, 10);
      log(`[edge-fwd] 重探测没找到可用边缘 IP (连续 ${fails} 次), 保留旧映射`);
      continue;
    }
    if (retry) alwaysLog(`[edge-fwd] 已连上 CF 边缘: ${JSON.stringify(working.slice(0, 4))}`);
    fails = 0;
    retry = false;
    edgeIps = working.concat(cands.filter((ip) => !working.includes(ip)));
    const ports = Array.from(edgePrimary.keys()).sort((x, y) => x - y);
    ports.forEach((port, i) => {
      const old = edgePrimary.get(port);
      if (working.includes(old)) {
        const used = new Set(edgePrimary.values());
        const free = working.filter((ip) => !used.has(ip));
        // 主用 IP 还通但明显变慢(比最快的空闲 IP 慢一倍且多 50ms 以上), 新连接改用快的; 已建立的连接不受影响
        if (free.length && (edgeRtt.get(old) || 0) > 2 * (edgeRtt.get(free[0]) || 0) + 50) {
          edgePrimary.set(port, free[0]);
          alwaysLog(`[edge-fwd] 127.0.0.1:${port} ${old} 变慢(${edgeRtt.get(old)}ms), 换成 ${free[0]}(${edgeRtt.get(free[0])}ms)`);
        }
        return;
      }
      const used = new Set(edgePrimary.values());
      const free = working.filter((ip) => !used.has(ip));
      edgePrimary.set(port, free.length ? free[0] : working[i % working.length]);
      if (old) alwaysLog(`[edge-fwd] 127.0.0.1:${port} ${old} 探测不通, 换成 ${edgePrimary.get(port)}`);
    });
  }
}

const edgeRtt = new Map();   // 边缘 IP -> 最近一次探测的连接耗时(毫秒)
const EDGE_PROBE_TLS = !/^(0|false|no|off)$/i.test(String(env.EDGE_PROBE_TLS || '1').trim());   // 探测要完成 TLS 握手才算通(防网关假 SYN-ACK / 代理 200 后黑洞); 0=只看 TCP
const EDGE_PROBE_SNI = 'probe.cftunnel.com';   // cloudflared 自己做连通性预检用的 SNI

// 连一个边缘 IP 并(默认)完成 TLS 握手, 返回耗时毫秒
async function edgeProbeOne(ip) {
  const t = Date.now();
  const s = await edgeOpen(ip, EDGE_CONNECT_TIMEOUT);
  if (!EDGE_PROBE_TLS) { s.destroy(); return Date.now() - t; }
  return new Promise((resolve, reject) => {
    // cloudflared 用自带 CA 校验, 这里只确认对端真的会 TLS 握手
    const ts = tls.connect({ socket: s, servername: EDGE_PROBE_SNI, rejectUnauthorized: false });
    let fin = false;
    const done = (e) => { if (fin) return; fin = true; clearTimeout(tm); ts.destroy(); s.destroy(); if (e) reject(e); else resolve(Date.now() - t); };
    const tm = setTimeout(() => done(new Error('tls handshake timeout')), EDGE_CONNECT_TIMEOUT * 1000);
    ts.once('secureConnect', () => done(null));
    ts.once('error', (e) => done(new Error(`tls: ${e.message}`)));
    ts.once('close', () => done(new Error('tls: closed before handshake')));
  });
}

// 并行探测, 最多等 waitSec 秒(7844 被封时只等一个超时); 返回能连上的 IP, 按连接耗时从快到慢排序
async function edgeProbe(ips, waitSec) {
  const probe = ips.slice(0, 8);
  const rtts = await Promise.all(probe.map((ip) => {
    return within(edgeProbeOne(ip).then((ms) => ms, (e) => {
      log(`[edge-fwd] probe ${ip} failed: ${e.message}`);
      return null;
    }), waitSec, null);
  }));
  const res = probe.map((ip, i) => [rtts[i], ip]).filter((x) => x[0] !== null).sort((a, b) => a[0] - b[0]);
  for (const [rtt, ip] of res) edgeRtt.set(ip, rtt);
  if (res.length) log(`[edge-fwd] 探测耗时: ${res.slice(0, 6).map(([rtt, ip]) => `${ip} ${rtt}ms`).join(', ')}`);
  return res.map((x) => x[1]);
}

// 有代理先走代理, 不通再试直连; 整个过程最多 EDGE_START_BUDGET 秒
async function startEdgeForwarder() {
  if (!(ENABLE_ARGO && EDGE_FWD)) return;
  const want = EDGE_PROXY;
  const t0 = Date.now();
  let ips = [];
  let working = [];
  const modes = want ? [want, ''] : [''];
  for (let n = 0; n < modes.length; n++) {
    EDGE_PROXY = modes[n] ? edgeProxyCfg : '';   // 代理阶段用最新的配置(期间可能已从 EDGE_PROXY_FILE 重读)
    // 有代理时代理阶段用 60% 预算, 留 40% 给直连兜底
    const end = t0 + EDGE_START_BUDGET * 1000 * (modes[n] && n === 0 ? 0.6 : 1);
    if (end - Date.now() < 1000) break;
    ips = await edgeResolve((end - Date.now()) / 2000);
    working = await edgeProbe(ips, (end - Date.now()) / 1000);
    if (working.length) break;
    if (modes[n]) alwaysLog('[edge-fwd] 经代理连不上 CF 边缘, 试直连');
  }
  if (working.length && want && !EDGE_PROXY) alwaysLog('[edge-fwd] 代理不通但直连可用, 改为直连');
  let retry = false;
  if (!working.length) {
    if (!want) { log('[edge-fwd] no reachable edge IP, skip forwarder'); return; }
    // 有代理的环境(如封闭沙盒)直连本来就不通: 先把转发端口开起来, 后台重试连上后 cloudflared 自动重连成功
    EDGE_PROXY = edgeProxyCfg;
    retry = true;
    alwaysLog(`[edge-fwd] 启动时代理和直连都连不上 CF 边缘, 先开转发端口, 后台每 ${EDGE_RETRY_INTERVAL} 秒重试`);
  }
  edgeIps = working.concat(ips.filter((ip) => !working.includes(ip)));   // 探测通过的排前面, 其余留作备用
  edgeLocalAddrs = [];
  for (let i = 0; i < 4; i++) {
    const ip = working.length ? working[i % working.length] : null;
    const port = EDGE_LOCAL_BASE + i;
    const server = net.createServer({ allowHalfOpen: true, pauseOnConnect: true }, (c) => { edgeConn(c, port).catch(() => c.destroy()); });
    const err = await listenLocal(server, port);
    if (err) { log(`[edge-fwd] bind 127.0.0.1:${port} failed: ${err.message}`); continue; }
    server.on('error', (e) => logError(`[edge-fwd] server error: ${e.message}`));
    server.maxConnections = MAX_CONN;
    server.on('drop', () => connFull('edge-fwd'));
    edgePrimary.set(port, ip);
    edgeLocalAddrs.push(`127.0.0.1:${port}`);
    log(`[edge-fwd] 127.0.0.1:${port} -> ${ip || '(待重试)'}:${EDGE_REMOTE_PORT}${EDGE_PROXY ? ' (via proxy)' : ''}`);
  }
  if (edgeLocalAddrs.length) edgeRefreshLoop(retry).catch((e) => logError(`[edge-fwd] refresh loop: ${e.message}`));
  log(`[edge-fwd] 启动耗时 ${((Date.now() - t0) / 1000).toFixed(1)}s`);
}


// =========================== 初始化 ===========================

// USE_FORWARD=true 时启动调用一次(文件末尾): 切到 Node 出站 + 边缘转发, 算出实际使用的代理
function forwardSetup() {
  EGRESS_MODE = 'node';
  BLOCK_QUIC = true;   // 走 Node 出站时屏蔽 udp/443(QUIC)
  EDGE_FWD = true;
  const raw = String(EDGE_PROXY || '').trim();
  EDGE_PROXY = /^(0|false|none|off|no)$/i.test(raw) ? '' : (readProxyFile() || normProxy(raw || ['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy']
    .map((k) => String(env[k] || '').trim()).find((x) => x) || ''));
  edgeProxyCfg = EDGE_PROXY;
  alwaysLog('[forward] 转发已启用');
}

// 自动分配端口时要避开的本地端口(出站 3 个候选 + 边缘转发 4 个); 没启用转发时为空
function reservedPorts() {
  if (!EDGE_FWD) return [];
  return [EGRESS_PORT, EGRESS_PORT + 1, EGRESS_PORT + 2, EDGE_LOCAL_BASE, EDGE_LOCAL_BASE + 1, EDGE_LOCAL_BASE + 2, EDGE_LOCAL_BASE + 3];
}

// 测试用(合并进本文件的 default export)
const fwdTestApi = {
  startNodeEgress, startEdgeForwarder, s5ParseUdp, s5PackAddr, ipToBuf, bufToIp6,
  resolveHost, happyConnect, edgePrimary, edgeProxyOpen, s5Handle, edgeOpen, edgeResolve, edgeIpOk,
  get EDGE_PROXY() { return EDGE_PROXY; }, setEdgeProxy: (v) => { EDGE_PROXY = v; edgeProxyCfg = v; }, authState,
  edgeProbe, edgeProbeOne, edgeRtt, setEdgeIps: (ips) => { edgeIps = ips; }, getEgressPort: () => EGRESS_PORT, getEdgeLocalAddrs: () => edgeLocalAddrs,
};

// 同目录没有 package.json 时生成一个(声明 CommonJS, 方便面板执行 npm install / npm start)
// 本脚本只用 Node 内置模块, 没有 npm 依赖; 已有别人的 package.json 不改动, 旧版本脚本生成的(type: module)改成 commonjs
try {
  const selfUrl = globalThis.__ARGO_ENTRY_URL__ || pathToFileURL(__filename).href;   // 经启动文件运行时以启动文件为准
  const pkgPath = new URL('./package.json', selfUrl);
  const main = path.basename(new URL(selfUrl).pathname);
  let pkg = null;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch (_) { /* 没有或读不了 */ }
  if (!fs.existsSync(pkgPath)) {
    fs.writeFileSync(pkgPath, JSON.stringify({ name: 'argo-node', private: true, type: 'commonjs', main, scripts: { start: `node ${main}` }, dependencies: {} }, null, 2) + '\n');
  } else if (pkg && pkg.name === 'argo-node' && pkg.type === 'module') {
    pkg.type = 'commonjs';
    fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
  }
} catch (_) { /* 目录只读等情况忽略 */ }
const USE_FORWARD = cfgBool('USE_FORWARD');

// =========================== 全局变量 / 路径 ===========================
let privateKeyB64 = '';
let publicKeyB64 = '';
let subTxtContent = '';
let linkStatus = { total: 0, argo: 0, direct: 0, argoNote: '', ipNote: '', name: '' };   // 供 TG 推送说明节点情况
let shuttingDown = false;

const FILE_PATH = (() => {
  const p = path.resolve(String(cfg('FILE_PATH') || '').trim() || '.cache');
  const cwd = process.cwd();
  // 清理时会删光 FILE_PATH 里的文件: 不允许是当前目录/其上级/主目录/脚本目录/根目录
  const bad = p === path.parse(p).root || p === os.homedir() || p === path.dirname(path.resolve(process.argv[1] || '.')) || cwd === p || cwd.startsWith(p + path.sep);
  if (!bad) return p;
  console.log(`[warn] FILE_PATH=${p} 是当前目录/主目录/脚本目录/根目录, 清理时会删光里面的文件, 已改用 .cache`);
  return path.resolve('.cache');
})();

function randomName(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyz';
  let out = '';
  for (let i = 0; i < length; i++) out += chars[crypto.randomInt(chars.length)];
  return out;
}

const webName = randomName();
const botName = randomName();
const webPath = path.join(FILE_PATH, webName);
const botPath = path.join(FILE_PATH, botName);
const subPath = path.join(FILE_PATH, 'sub.txt');
const listPath = path.join(FILE_PATH, 'list.txt');
const bootLogPath = path.join(FILE_PATH, 'boot.log');
const configPath = path.join(FILE_PATH, 'config.json');
const certPath = path.join(FILE_PATH, 'cert.pem');
const keyPath = path.join(FILE_PATH, 'private.key');
const keyTxtPath = path.join(FILE_PATH, 'key.txt');
const autoPortsPath = path.join(FILE_PATH, 'auto_ports.json');   // 端口填 0 时自动分配的结果, 重启后尽量沿用
const tunnelJsonPath = path.join(FILE_PATH, 'tunnel.json');
const tunnelYmlPath = path.join(FILE_PATH, 'tunnel.yml');

const NODE_LINE_RE = /^(vless|vmess|trojan|hysteria2|socks):\/\//;
const SNIFFING = { enabled: true, destOverride: ['http', 'tls', 'quic'], metadataOnly: false };

// =========================== 工具函数 ===========================
function isValidPort(port) {
  if (port === null || port === undefined || port === '') return false;
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}
function b64(input) { return Buffer.from(input).toString('base64'); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
async function safeUnlink(p) { try { await fsp.unlink(p); } catch (_) { /* ignore */ } }
async function pathExists(p) { try { await fsp.access(p); return true; } catch (_) { return false; } }
function readText(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return null; } }
function isTunnelSecret() { return isFixedTunnel() && ARGO_AUTH.includes('TunnelSecret'); }   // ARGO_DOMAIN 为空时走临时隧道, 不能用 --config 跑一个没生成的 tunnel.yml
function isFixedTunnel() { return Boolean(ARGO_AUTH && ARGO_DOMAIN); }

// =========================== X25519 密钥对(Reality) ===========================
function generateX25519Keypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  // SPKI/PKCS8 DER 里 X25519 的原始 32 字节 key 固定在末尾
  const rawPub = publicKey.subarray(publicKey.length - 32);
  const rawPriv = privateKey.subarray(privateKey.length - 32);
  return { privateKey: rawPriv.toString('base64url'), publicKey: rawPub.toString('base64url') };
}

async function generateOrLoadKeypair() {
  const content = readText(keyTxtPath);
  if (content) {
    const priv = content.match(/PrivateKey:\s*(.*)/);
    const pub = content.match(/PublicKey:\s*(.*)/);
    if (priv && pub && priv[1].trim() && pub[1].trim()) {
      privateKeyB64 = priv[1].trim();
      publicKeyB64 = pub[1].trim();
      log(`Private Key: ${privateKeyB64}`);
      log(`Public Key: ${publicKeyB64}`);
      return;
    }
  }
  const kp = generateX25519Keypair();
  privateKeyB64 = kp.privateKey;
  publicKeyB64 = kp.publicKey;
  await fsp.writeFile(keyTxtPath, `PrivateKey: ${privateKeyB64}\nPublicKey: ${publicKeyB64}\n`, 'utf-8');
  log(`Private Key: ${privateKeyB64}`);
  log(`Public Key: ${publicKeyB64}`);
}

// =========================== TLS 证书 ===========================
const FALLBACK_EC_KEY = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM4792SEtPqIt1ywqTd/0bYidBqpYV/++siNnfBYsdUYoAoGCCqGSM49
AwEHoUQDQgAE1kHafPj07rJG+HboH2ekAI4r+e6TL38GWASANnngZreoQDF16ARa
/TsyLyFoPkhLxSbehH/NBEjHtSZGaDhMqQ==
-----END EC PRIVATE KEY-----
`;
const FALLBACK_CERT = `-----BEGIN CERTIFICATE-----
MIIBejCCASGgAwIBAgIUfWeQL3556PNJLp/veCFxGNj9crkwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIYmluZy5jb20wHhcNMjUwOTE4MTgyMDIyWhcNMzUwOTE2MTgy
MDIyWjATMREwDwYDVQQDDAhiaW5nLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNZB2nz49O6yRvh26B9npACOK/nuky9/BlgEgDZ54Ga3qEAxdegEWv07Mi8h
aD5IS8Um3oR/zQRIx7UmRmg4TKmjUzBRMB0GA1UdDgQWBBTV1cFID7UISE7PLTBR
BfGbgkrMNzAfBgNVHSMEGDAWgBTV1cFID7UISE7PLTBRBfGbgkrMNzAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAIDAJvg0vd/ytrQVvEcSm6XTlB+
eQ6OFb9LbLYL9f+sAiAffoMbi4y/0YUSlTtz7as9S8/lciBF5VCUoVIKS+vX2g==
-----END CERTIFICATE-----
`;

async function ensureTlsCertificates() {
  if (CERT_B64 && KEY_B64) {
    try {
      const certBuf = Buffer.from(CERT_B64, 'base64');
      const keyBuf = Buffer.from(KEY_B64, 'base64');
      // Buffer.from(base64) 遇到非法字符不会报错, 只会解出乱码: 这里自己校验 PEM 头
      if (!certBuf.includes('-----BEGIN CERTIFICATE-----') || !keyBuf.includes('PRIVATE KEY-----')) {
        throw new Error('not a PEM certificate/key');
      }
      await fsp.writeFile(certPath, certBuf);
      await fsp.writeFile(keyPath, keyBuf);
      log('Using custom certificate from CERT_B64/KEY_B64');
      return;
    } catch (e) {
      logError(`Failed to decode CERT_B64/KEY_B64, falling back to self-signed: ${e}`);
    }
  }
  if (await pathExists(certPath) && await pathExists(keyPath)) return;
  try {
    // 自签 EC 证书(CN=bing.com, 与 Hysteria2 节点里的 SNI 对应)
    execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', keyPath], { stdio: 'ignore' });
    execFileSync('openssl', ['req', '-new', '-x509', '-key', keyPath, '-out', certPath, '-days', '3650', '-subj', '/CN=bing.com'], { stdio: 'ignore' });
  } catch (e) {
    logError(`Failed to generate TLS certificate via openssl: ${e.message}`);
    await fsp.writeFile(keyPath, FALLBACK_EC_KEY, 'utf-8');
    await fsp.writeFile(certPath, FALLBACK_CERT, 'utf-8');
  }
}

async function getCertificateFingerprint(certFile) {
  try {
    const pem = await fsp.readFile(certFile, 'utf-8');
    const m = pem.match(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/);
    if (!m) return '';
    const der = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
    const digest = crypto.createHash('sha256').update(der).digest();
    return Array.from(digest).map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
  } catch (e) {
    logError(`Failed to calculate certificate fingerprint: ${e.message}`);
    return '';
  }
}

// =========================== 目录/清理 ===========================
async function createDirectory() {
  if (!SHOW_LOG) process.stdout.write('\x1bc');
  await fsp.mkdir(FILE_PATH, { recursive: true });
}

async function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;
    const content = readText(subPath);
    if (!content) return;
    const decoded = Buffer.from(content, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter((l) => NODE_LINE_RE.test(l));
    if (!nodes.length) return;
    await pfetch(`${UPLOAD_URL}/api/delete-nodes`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodes }), signal: AbortSignal.timeout(10000),
    });
  } catch (_) { /* ignore */ }
}

async function cleanupOldFiles() {
  const preserve = new Set([keyTxtPath, certPath, keyPath, autoPortsPath]);
  if (EDGE_PROXY_FILE) preserve.add(path.resolve(EDGE_PROXY_FILE));   // 代理密码文件放在 FILE_PATH 里也不能删
  try {
    for (const name of await fsp.readdir(FILE_PATH)) {
      const p = path.join(FILE_PATH, name);
      if (preserve.has(p)) continue;
      try { await fsp.rm(p, { recursive: true, force: true }); } catch (_) { /* ignore */ }
    }
  } catch (_) { /* ignore */ }
}

// =========================== 下载 ===========================
async function downloadToBuffer(url, timeoutMs = 180000) {
  const res = await pfetch(url, { redirect: 'follow', signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function downloadFile(fileName, fileUrl) {
  const filePath = path.join(FILE_PATH, fileName);
  try {
    const buf = await downloadToBuffer(fileUrl);
    if (buf.length < 1024) throw new Error(`file too small (${buf.length} bytes)`);
    await fsp.writeFile(filePath, buf);
    log(`Download ${fileName} successfully`);
    return true;
  } catch (e) {
    logError(`Download ${fileName} failed: ${e.message}`);
    await safeUnlink(filePath);
    return false;
  }
}

// 纯 JS 从 zip 里取出一个文件(只支持 store/deflate, 足够解 Xray 官方包), 不依赖系统 unzip
function extractFromZip(zipBuf, entryName) {
  let eocd = -1;
  for (let i = zipBuf.length - 22; i >= Math.max(0, zipBuf.length - 65557); i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const count = zipBuf.readUInt16LE(eocd + 10);
  let p = zipBuf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (zipBuf.readUInt32LE(p) !== 0x02014b50) throw new Error('zip: bad central directory');
    const method = zipBuf.readUInt16LE(p + 10);
    const compSize = zipBuf.readUInt32LE(p + 20);
    const nameLen = zipBuf.readUInt16LE(p + 28);
    const extraLen = zipBuf.readUInt16LE(p + 30);
    const commentLen = zipBuf.readUInt16LE(p + 32);
    const localOff = zipBuf.readUInt32LE(p + 42);
    const name = zipBuf.toString('utf8', p + 46, p + 46 + nameLen);
    if (name === entryName) {
      const lNameLen = zipBuf.readUInt16LE(localOff + 26);
      const lExtraLen = zipBuf.readUInt16LE(localOff + 28);
      const start = localOff + 30 + lNameLen + lExtraLen;
      const data = zipBuf.subarray(start, start + compSize);
      if (method === 0) return data;
      if (method === 8) return zlib.inflateRawSync(data);
      throw new Error(`zip: unsupported compression method ${method}`);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`zip: ${entryName} not found`);
}

function githubReleaseUrl(repo, version, asset) {
  return version === 'latest'
    ? `https://github.com/${repo}/releases/latest/download/${asset}`
    : `https://github.com/${repo}/releases/download/${version}/${asset}`;
}

async function downloadCloudflaredOfficial(archGh) {
  const url = githubReleaseUrl('cloudflare/cloudflared', CLOUDFLARED_VERSION, `cloudflared-linux-${archGh}`);
  log(`Downloading cloudflared (${CLOUDFLARED_VERSION}) from official source: ${url}`);
  return downloadFile(botName, url);
}

async function downloadWebOfficial(archZip) {
  const url = githubReleaseUrl('XTLS/Xray-core', XRAY_VERSION, `Xray-linux-${archZip}.zip`);
  log(`Downloading Xray-core (${XRAY_VERSION}) from official source: ${url}`);
  try {
    const zipBuf = await downloadToBuffer(url);
    await fsp.writeFile(webPath, extractFromZip(zipBuf, 'xray'));
    log(`Download ${webName} successfully`);
    return true;
  } catch (e) {
    logError(`Download/extract Xray-core failed: ${e.message}`);
    await safeUnlink(webPath);
    return false;
  }
}

async function downloadFromMirrors(fileName, segment, baseUrls) {
  for (const baseUrl of baseUrls) {
    if (await downloadFile(fileName, `${baseUrl}/${segment}`)) return true;
  }
  return false;
}

// needWeb/needBot: 进程崩溃且二进制已被清理时, 只重下需要的那个
async function downloadAllFiles(needWeb = true, needBot = true) {
  const isArm = ['arm64', 'arm'].includes(os.arch());
  const archGh = isArm ? 'arm64' : 'amd64';
  const archZip = isArm ? 'arm64-v8a' : '64';
  const mirrors = [`https://${archGh}.oooen.com`, `https://${archGh}.ssss.nyc.mn`];

  if (needWeb && !(await downloadWebOfficial(archZip))) {
    logError('Xray-core official download failed, falling back to mirror');
    await downloadFromMirrors(webName, 'web', mirrors);
  }
  if (needBot && ENABLE_ARGO && !(await downloadCloudflaredOfficial(archGh))) {
    logError('cloudflared official download failed, falling back to mirror');
    await downloadFromMirrors(botName, 'bot', mirrors);
  }
}

async function authorizeFiles(fileNames) {
  for (const name of fileNames) {
    const p = path.join(FILE_PATH, name);
    if (await pathExists(p)) {
      try {
        await fsp.chmod(p, 0o775);
        log(`Empowerment success for ${name}: 775`);
      } catch (e) {
        logError(`Empowerment failed for ${name}: ${e.message}`);
      }
    }
  }
}

// =========================== Argo 隧道配置 ===========================
function parseTunnelId(auth) {
  try {
    const obj = JSON.parse(auth);
    if (obj && obj.TunnelID) return String(obj.TunnelID);
  } catch (_) { /* 不是严格 JSON, 用正则兜底 */ }
  const m = auth.match(/"TunnelID"\s*:\s*"([^"]+)"/);
  return m ? m[1] : '';
}

async function argoType() {
  if (!ENABLE_ARGO) { log('ENABLE_ARGO is false, skip Argo tunnel setup'); return; }
  if (!isFixedTunnel()) { log('ARGO_DOMAIN or ARGO_AUTH variable is empty, use quick tunnels'); return; }
  if (isTunnelSecret()) {
    await fsp.writeFile(tunnelJsonPath, ARGO_AUTH, 'utf-8');
    const tunnelId = parseTunnelId(ARGO_AUTH);
    if (!tunnelId) logError('ARGO_AUTH contains TunnelSecret but TunnelID not found');
    const tunnelYaml = [
      `tunnel: ${tunnelId}`,
      `credentials-file: ${tunnelJsonPath}`,
      'protocol: http2',
      '',
      'ingress:',
      `  - hostname: ${ARGO_DOMAIN}`,
      `    service: http://localhost:${ARGO_PORT}`,
      '    originRequest:',
      '      noTLSVerify: true',
      '  - service: http_status:404',
      '',
    ].join('\n');
    await fsp.writeFile(tunnelYmlPath, tunnelYaml, 'utf-8');
  } else {
    log(`Using token connect to tunnel, please set ${ARGO_PORT} in cloudflare`);
  }
}

function makeReader(sock) {
  let buf = Buffer.alloc(0);
  let waiter = null;
  let ended = false;
  const check = () => {
    if (!waiter) return;
    if (buf.length >= waiter.n) {
      const w = waiter;
      waiter = null;
      const out = buf.subarray(0, w.n);
      buf = buf.subarray(w.n);
      w.resolve(out);
    } else if (ended) {
      const w = waiter;
      waiter = null;
      w.reject(new Error('closed'));
    }
  };
  const onData = (d) => { buf = buf.length ? Buffer.concat([buf, d]) : d; check(); };
  const onEnd = () => { ended = true; check(); };
  sock.on('data', onData);
  sock.on('end', onEnd);
  sock.on('close', onEnd);
  return {
    read(n) { return new Promise((resolve, reject) => { waiter = { n, resolve, reject }; check(); }); },
    detach() {
      sock.pause();
      sock.removeListener('data', onData);
      sock.removeListener('end', onEnd);
      sock.removeListener('close', onEnd);
      const rest = buf;
      buf = Buffer.alloc(0);
      return rest;
    },
  };
}

// =========================== Xray 配置生成 ===========================
function warnPortConflicts(config) {
  // Xray 只要有一个端口绑不上整个进程就起不来: 提前打印 TCP 端口撞车(HY2 是 UDP, 可以同号)
  const used = new Map();
  const add = (port, who) => {
    const n = Number(port);
    if (!Number.isInteger(n) || n <= 0) return;
    if (used.has(n)) alwaysLog(`[config] 端口冲突: ${n} 同时被 ${used.get(n)} 和 ${who} 使用, Xray 可能整体启动失败`);
    else used.set(n, who);
  };
  add(PORT, 'HTTP 订阅服务');
  if (EGRESS_MODE === 'node') add(EGRESS_PORT, 'node egress');
  if (ENABLE_ARGO && EDGE_FWD) {
    for (let i = 0; i < 4; i++) add(EDGE_LOCAL_BASE + i, 'edge-fwd');
  }
  for (const ib of config.inbounds) {
    if (ib.protocol !== 'hysteria') add(ib.port, ib.tag);
  }
}

async function generateXrayConfig() {
  const config = {
    log: { access: '/dev/null', error: '/dev/null', loglevel: 'none' },
    inbounds: [],
    dns: { servers: ['https+local://8.8.8.8/dns-query'] },
    outbounds: [
      { protocol: 'freedom', tag: 'direct' },
      { protocol: 'blackhole', tag: 'block' },
    ],
  };

  if (EGRESS_MODE === 'node') {
    // 默认出站走本机 SOCKS5(由 Node 代连), DNS 也由 Node 解析
    delete config.dns;
    config.outbounds.unshift({
      protocol: 'socks', tag: 'node-egress',
      settings: { servers: [{ address: '127.0.0.1', port: EGRESS_PORT }] },
    });
    if (BLOCK_QUIC) {
      // 屏蔽 udp/443(QUIC), 让浏览器/视频退回 TCP, 避免逐包转发大流量 UDP
      config.routing = { rules: [{ type: 'field', network: 'udp', port: '443', outboundTag: 'block' }] };
    }
  }

  if (ENABLE_ARGO) {
    config.inbounds.push(
      {
        tag: 'vless-fallback-in', listen: '::', port: ARGO_PORT, protocol: 'vless',
        settings: {
          clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none',
          fallbacks: [
            { dest: 51001 },
            { path: '/vless-argo', dest: 51002 },
            { path: '/vmess-argo', dest: 51003 },
            { path: '/trojan-argo', dest: 51004 },
            ...(PORT ? [{ path: `/${SUB_PATH}`, dest: PORT }] : []),   // Argo 域名/SUB_PATH 走 https 订阅
          ],
        },
        streamSettings: { network: 'tcp' },
      },
      {
        tag: 'vless-tcp-in', port: 51001, listen: '127.0.0.1', protocol: 'vless',
        settings: { clients: [{ id: UUID }], decryption: 'none' },
        streamSettings: { network: 'tcp', security: 'none' },
      },
      {
        tag: 'vless-ws-in', port: 51002, listen: '127.0.0.1', protocol: 'vless',
        settings: { clients: [{ id: UUID, level: 0 }], decryption: 'none' },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/vless-argo' } },
        sniffing: SNIFFING,
      },
      {
        tag: 'vmess-ws-in', port: 51003, listen: '127.0.0.1', protocol: 'vmess',
        settings: { clients: [{ id: UUID, alterId: 0 }] },
        streamSettings: { network: 'ws', wsSettings: { path: '/vmess-argo' } },
        sniffing: SNIFFING,
      },
      {
        tag: 'trojan-ws-in', port: 51004, listen: '127.0.0.1', protocol: 'trojan',
        settings: { clients: [{ password: UUID }] },
        streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/trojan-argo' } },
        sniffing: SNIFFING,
      },
    );
  }

  if (isValidPort(REALITY_PORT)) {
    config.inbounds.push({
      tag: 'vless-reality-in', listen: '::', port: Number(REALITY_PORT), protocol: 'vless',
      settings: { clients: [{ id: UUID, flow: 'xtls-rprx-vision' }], decryption: 'none' },
      streamSettings: {
        network: 'raw', security: 'reality',
        realitySettings: {
          show: false, dest: 'www.iij.ad.jp:443', xver: 0,
          serverNames: ['www.iij.ad.jp'], privateKey: privateKeyB64, shortIds: [''],
        },
      },
    });
  }

  if (isValidPort(HY2_PORT)) {
    config.inbounds.push({
      tag: 'hysteria-in', listen: '::', port: Number(HY2_PORT), protocol: 'hysteria',
      settings: { version: 2, clients: [{ auth: UUID }] },
      streamSettings: {
        network: 'hysteria',
        hysteriaSettings: { version: 2, masquerade: { type: 'proxy', url: 'https://bing.com' } },
        security: 'tls',
        tlsSettings: { alpn: ['h3'], certificates: [{ certificateFile: certPath, keyFile: keyPath }] },
      },
    });
  }

  if (isValidPort(S5_PORT)) {
    config.inbounds.push({
      tag: 's5-in', listen: '::', port: Number(S5_PORT), protocol: 'socks',
      settings: { auth: 'password', accounts: [{ user: UUID.slice(0, 8), pass: UUID.slice(-12) }], udp: true },
    });
  }

  warnPortConflicts(config);
  await fsp.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
}

// =========================== 代理隧道(pfetch 和 forward.js 共用) ===========================
const authErr = (m) => Object.assign(new Error(m), { proxyAuth: true });

// 经 proxyUrl (http CONNECT 或 socks5) 连 host:port, 成功返回已打通的 socket
function edgeProxyOpenOnce(host, port, timeoutSec, proxyUrl) {
  return new Promise((resolve, reject) => {
    const pu = new URL(proxyUrl);
    const isSocks = /^socks/i.test(pu.protocol);
    const user = decodeURIComponent(pu.username || '');
    const pass = decodeURIComponent(pu.password || '');
    const s = net.connect({ host: pu.hostname.replace(/^\[|\]$/g, ''), port: Number(pu.port) || (isSocks ? 1080 : 3128), allowHalfOpen: true });
    let done = false;
    let buf = Buffer.alloc(0);
    let need = null;     // { n, cb }: 攒够 n 字节后回调
    const fail = (e) => { if (done) return; done = true; clearTimeout(t); s.destroy(); reject(e); };
    const t = setTimeout(() => fail(new Error('proxy timeout')), timeoutSec * 2000);
    const finish = () => {
      done = true;
      clearTimeout(t);
      s.removeListener('data', onData);
      s.removeListener('error', fail);
      s.removeListener('close', onClose);
      s.removeListener('end', onClose);
      s.on('error', () => {});
      s.pause();
      if (buf.length) s.unshift(buf);   // 握手后多出来的隧道数据放回去
      resolve(s);
    };
    const take = (n, cb) => { need = { n, cb }; pump(); };
    const pump = () => {
      if (!need || done) return;
      if (need.n === -1) {          // http: 读到空行
        const i = buf.indexOf('\r\n\r\n');
        if (i < 0) { if (buf.length > 8192) fail(new Error('proxy header too long')); return; }
        const h = buf.slice(0, i + 4);
        buf = buf.slice(i + 4);
        const cb = need.cb; need = null; cb(h);
        return;
      }
      if (buf.length < need.n) return;
      const h = buf.slice(0, need.n);
      buf = buf.slice(need.n);
      const cb = need.cb; need = null; cb(h);
    };
    const onData = (d) => { buf = Buffer.concat([buf, d]); pump(); };
    const onClose = () => fail(new Error('proxy closed'));
    s.on('data', onData);
    s.once('error', fail);
    s.once('close', onClose);
    s.once('end', onClose);       // allowHalfOpen 下对端关闭只触发 end 不触发 close
    const socksRequest = () => {
      let addr;
      if (net.isIPv4(host)) addr = Buffer.concat([Buffer.from([1]), Buffer.from(host.split('.').map(Number))]);
      else { const hb = Buffer.from(host); addr = Buffer.concat([Buffer.from([3, hb.length]), hb]); }
      const pb = Buffer.alloc(2); pb.writeUInt16BE(port);
      s.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, pb]));
      take(4, (r) => {
        if (r[1] !== 0) { fail(new Error(`socks5 refused: code ${r[1]}`)); return; }
        if (r[3] === 1) take(6, finish);
        else if (r[3] === 4) take(18, finish);
        else take(1, (l) => take(l[0] + 2, finish));
      });
    };
    s.once('connect', () => {
      if (isSocks) {
        s.write(Buffer.from(user ? [5, 2, 0, 2] : [5, 1, 0]));
        take(2, (r) => {
          if (r[0] !== 5 || r[1] === 0xff) { fail(new Error('socks5 no acceptable auth')); return; }
          if (r[1] !== 2) { socksRequest(); return; }
          const ub = Buffer.from(user);
          const pw = Buffer.from(pass);
          s.write(Buffer.concat([Buffer.from([1, ub.length]), ub, Buffer.from([pw.length]), pw]));
          take(2, (a) => { if (a[1] !== 0) fail(authErr('socks5 auth failed')); else socksRequest(); });
        });
        return;
      }
      const hp = host.includes(':') ? `[${host}]:${port}` : `${host}:${port}`;   // IPv6 字面量要加方括号
      let req = `CONNECT ${hp} HTTP/1.1\r\nHost: ${hp}\r\n`;
      if (user) req += `Proxy-Authorization: Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}\r\n`;
      s.write(req + '\r\n');
      take(-1, (h) => {
        const first = h.slice(0, h.indexOf('\r\n')).toString('latin1');
        if (/^HTTP\/1\.[01] 407/.test(first)) { fail(authErr(`proxy auth failed: ${first.slice(0, 80)}`)); return; }
        if (!/^HTTP\/1\.[01] 200/.test(first)) { fail(new Error(`proxy refused: ${first.slice(0, 80)}`)); return; }
        finish();
      });
    });
  });
}

// =========================== HTTP 请求走系统代理 ===========================
// Node 的 fetch 不认 HTTPS_PROXY/ALL_PROXY/HTTP_PROXY(Python requests 认): 设了系统代理时改走代理, 没设就是原生 fetch
const NO_PROXY = String(env.NO_PROXY || env.no_proxy || '').split(',').map((x) => x.trim().toLowerCase().replace(/^\*?\./, '')).filter(Boolean);
function sysProxyFor(u) {
  const pick = (ks) => ks.map((k) => String(env[k] || '').trim()).find((x) => x) || '';
  const v = u.protocol === 'https:' || u.protocol === 'wss:' ? pick(['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy']) : pick(['HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy']);
  if (!v) return '';
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1' || NO_PROXY.includes('*')) return '';
  if (NO_PROXY.some((d) => h === d || h.endsWith(`.${d}`))) return '';
  return normProxy(v);
}

// 给 http(s).request 用的 createConnection: 经代理打隧道(http CONNECT 或 socks5), https 再套 TLS
function proxyConnector(u, proxy) {
  const secure = u.protocol === 'https:' || u.protocol === 'wss:';
  const port = Number(u.port) || (secure ? 443 : 80);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return (_opts, cb) => {
    edgeProxyOpenOnce(host, port, 5, proxy).then((sock) => {
      sock.resume();
      cb(null, secure ? tls.connect({ socket: sock, servername: net.isIP(host) ? undefined : host }) : sock);
    }, (e) => cb(e));
  };
}

async function pfetch(url, opts = {}, hops = 0) {
  const u = new URL(url);
  const proxy = sysProxyFor(u);
  if (!proxy) return fetch(url, opts);
  const res = await new Promise((resolve, reject) => {
    const secure = u.protocol === 'https:';
    const body = opts.body === undefined || opts.body === null ? null : Buffer.from(String(opts.body));
    const headers = Object.assign({ 'Accept-Encoding': 'identity' }, opts.headers || {});
    if (opts.body instanceof URLSearchParams) headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
    if (body) headers['Content-Length'] = body.length;
    const ro = { method: opts.method || 'GET', headers };   // 不传 agent: 有 createConnection 时 Node 才会用它
    const pu = new URL(proxy);
    if (!secure && !/^socks/i.test(pu.protocol)) {
      // 明文 http 经 http 代理: 直接发绝对地址, 不用 CONNECT(很多代理只放行 CONNECT 443)
      Object.assign(ro, { host: pu.hostname.replace(/^\[|\]$/g, ''), port: Number(pu.port) || 3128, path: u.href });
      if (pu.username) headers['Proxy-Authorization'] = `Basic ${Buffer.from(`${decodeURIComponent(pu.username)}:${decodeURIComponent(pu.password || '')}`).toString('base64')}`;
    } else {
      Object.assign(ro, { host: u.hostname, port: Number(u.port) || (secure ? 443 : 80), path: u.pathname + u.search, createConnection: proxyConnector(u, proxy) });
    }
    const req = (secure ? https : http).request(ro, (r) => {
      const chunks = [];
      r.on('data', (c) => chunks.push(c));
      r.on('end', () => { cleanup(); resolve({ status: r.statusCode, headers: r.headers, buf: Buffer.concat(chunks) }); });
      r.on('error', (e) => { cleanup(); reject(e); });
    });
    const onAbort = () => req.destroy(opts.signal.reason || new Error('aborted'));
    const cleanup = () => { if (opts.signal) opts.signal.removeEventListener('abort', onAbort); };
    if (opts.signal) {
      if (opts.signal.aborted) { reject(opts.signal.reason || new Error('aborted')); return; }
      opts.signal.addEventListener('abort', onAbort, { once: true });
    }
    req.on('error', (e) => { cleanup(); reject(e); });
    req.end(body || undefined);
  });
  if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location && opts.redirect !== 'manual' && hops < 5) {
    const next = Object.assign({}, opts);
    if (res.status === 303 || ((res.status === 301 || res.status === 302) && (opts.method || 'GET') !== 'GET')) { next.method = 'GET'; delete next.body; }
    return pfetch(new URL(res.headers.location, u).href, next, hops + 1);
  }
  const text = () => res.buf.toString('utf8');
  return {
    ok: res.status >= 200 && res.status < 300,
    status: res.status,
    headers: { get: (k) => { const v = res.headers[String(k).toLowerCase()]; return v === undefined ? null : String(v); } },
    text: async () => text(),
    json: async () => JSON.parse(text()),
    arrayBuffer: async () => res.buf.buffer.slice(res.buf.byteOffset, res.buf.byteOffset + res.buf.length),
  };
}

function connectWithTimeout(host, port, timeoutSec) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port, allowHalfOpen: true });
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutSec * 1000);
    s.once('connect', () => { clearTimeout(t); s.removeAllListeners('error'); s.on('error', () => {}); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); s.destroy(); reject(e); });
  });
}
// =========================== 进程管理 / 守护 ===========================
// 直接持有子进程句柄, 不依赖 pkill(精简镜像常常没有 procps)
const procs = {
  web: { name: 'xray', child: null, fails: 0, last: 0, timer: null },
  bot: { name: 'cloudflared', child: null, fails: 0, last: 0, timer: null },
};
let botBusy = false;   // 域名提取正在重启 cloudflared 时, watchdog 不插手

function edgeArgs() {
  const out = [];
  for (const a of edgeLocalAddrs) out.push('--edge', a);
  return out;
}

// cloudflared 协议: auto(先 QUIC, 不通退 http2) / quic / http2; 走边缘转发器时只能 http2(转发器只转 TCP)
const ARGO_PROTOCOL = (cfg('ARGO_PROTOCOL').trim().toLowerCase() || 'auto');
function argoProtocol() {
  if (edgeLocalAddrs.length) return 'http2';
  return ['auto', 'quic', 'http2'].includes(ARGO_PROTOCOL) ? ARGO_PROTOCOL : 'auto';
}

function botArgs() {
  const common = ['tunnel', '--edge-ip-version', 'auto', '--no-autoupdate', '--protocol', argoProtocol(), ...edgeArgs(),
    '--logfile', bootLogPath, '--loglevel', 'info'];
  if (isTunnelSecret()) return common.concat(['--config', tunnelYmlPath, 'run']);
  if (isFixedTunnel()) {
    // 固定隧道 token: 不按长度/字符集判断, 避免 token 稍长或带 +/_- 时被误当成临时隧道
    if (!/^[A-Za-z0-9+/=_-]{80,}$/.test(ARGO_AUTH)) logError('ARGO_AUTH does not look like a tunnel token, trying it as token anyway');
    return common.concat(['run', '--token', ARGO_AUTH]);
  }
  return common.concat(['--url', `http://localhost:${ARGO_PORT}`]);
}

function spawnTracked(key, command, args) {
  const p = procs[key];
  let child;
  try {
    child = spawn(command, args, { stdio: 'ignore' });   // 不 detached: 面板按进程组杀 node 时 xray/cloudflared 一起退出, 不残留占端口
  } catch (e) {
    logError(`Error executing command: ${e.message}`);
    scheduleRestart(key);
    return null;
  }
  child.unref();
  let reported = false;
  const onGone = (why) => {
    if (reported) return;
    reported = true;
    if (child.expectedExit || shuttingDown || p.child !== child) return;
    log(`[watchdog] ${p.name} exited (${why})`);
    scheduleRestart(key);
  };
  child.on('error', (e) => {
    logError(`${p.name} error: ${e.message}`);
    if (child.pid === undefined) child.gone = true;   // spawn 失败(ENOENT/EACCES): 不会再有 exit 事件
    onGone(e.code || 'error');
  });
  child.on('exit', (code, sig) => { child.gone = true; onGone(sig || `code ${code}`); });
  p.child = child;
  return child;
}

function isAlive(key) {
  const c = procs[key].child;
  return Boolean(c && !c.gone && c.pid !== undefined && c.exitCode === null && c.signalCode === null);
}

function killTracked(key) {
  const child = procs[key].child;
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.expectedExit = true;
  try { child.kill('SIGTERM'); } catch (_) { /* ignore */ }
}

// 等本地端口开始监听(Xray 起来了), 最多 timeoutMs; 起得快就不白等
async function waitPort(port, timeoutMs = 5000) {
  if (!isValidPort(port)) return false;
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    try { (await connectWithTimeout('127.0.0.1', Number(port), 0.5)).destroy(); return true; } catch (_) { /* not yet */ }
    if (!isAlive('web')) return false;
    await sleep(200);
  }
  return false;
}

function startWeb() {
  if (shuttingDown) return;
  spawnTracked('web', webPath, ['-c', configPath]);
  log(`${webName} is running`);
}

function startBot() {
  if (shuttingDown) return;
  spawnTracked('bot', botPath, botArgs());
  log(`${botName} is running`);
}

// 退避重启: 10s, 20s, 40s ... 最长 5 分钟; 稳定运行 5 分钟后清零
function scheduleRestart(key) {
  if (!WATCHDOG || shuttingDown) return;
  const p = procs[key];
  if (p.timer) return;
  const now = Date.now();
  if (now - p.last > 600000) p.fails = 0;   // 上次重启 10 分钟后还活着才清零(退避上限 5 分钟, 用 5 分钟会永远清零)
  p.fails++;
  p.last = now;
  const delay = Math.min(300, 10 * 2 ** (p.fails - 1));
  log(`[watchdog] ${p.name} is not running, restarting in ${delay}s (attempt ${p.fails})`);
  p.timer = setTimeout(() => {
    p.timer = null;
    const job = key === 'web' ? restartWeb() : restartBot();
    job.catch((e) => { logError(`[watchdog] ${p.name} restart error: ${e.message}`); scheduleRestart(key); });
  }, delay * 1000);
}

async function restartWeb() {
  if (isAlive('web')) return;   // 已被别的流程拉起, 不再起第二个(否则旧进程脱管、端口冲突)
  if (!(await pathExists(webPath))) {
    await downloadAllFiles(true, false);
    await authorizeFiles([webName]);
  }
  if (!(await pathExists(webPath))) {
    logError('[watchdog] xray binary download failed, retry later');
    scheduleRestart('web');
    return;
  }
  if (!(await pathExists(configPath))) await generateXrayConfig();
  startWeb();
  cleanSecretsLater();
}

// watchdog 重启会重写 config.json / tunnel.json, 首次 90 秒清理已经跑过, 这里 30 秒后再删一次
let cleanedOnce = false;
function cleanSecretsLater() {
  if (!cleanedOnce) return;
  setTimeout(async () => { for (const f of [configPath, tunnelJsonPath, tunnelYmlPath]) await safeUnlink(f); }, 30000).unref();
}

async function restartBot() {
  if (botBusy) { scheduleRestart('bot'); return; }
  if (isAlive('bot')) return;   // extractDomains 已重启过 cloudflared, 不再多起一个脱管进程
  botBusy = true;
  try {
    if (!(await pathExists(botPath))) {
      await downloadAllFiles(false, true);
      await authorizeFiles([botName]);
    }
    if (!(await pathExists(botPath))) {
      logError('[watchdog] cloudflared binary download failed, retry later');
      scheduleRestart('bot');
      return;
    }
    if (isTunnelSecret() && !(await pathExists(tunnelYmlPath))) await argoType();
    const quick = !isFixedTunnel();
    if (quick) await safeUnlink(bootLogPath);   // 删掉旧日志, 免得读到上一次的旧域名
    startBot();
    cleanSecretsLater();
    if (quick) {
      // 临时隧道重启后域名会变(extractDomains 自己轮询等域名): 先删订阅器里的旧节点, 再重新提取域名、推送
      await deleteNodes();
      await extractDomains(0, true);
      await sendTelegram();
      await uploadNodes();
      alwaysLog('[watchdog] quick tunnel restarted, subscription links refreshed');
    }
  } finally {
    botBusy = false;
  }
}

async function downloadFilesAndRun() {
  await downloadAllFiles();
  await authorizeFiles(ENABLE_ARGO ? [webName, botName] : [webName]);

  if (await pathExists(webPath)) {
    startWeb();
    // 等 Argo 入站端口开始监听再起 cloudflared(最多 5 秒), 不再固定 sleep
    if (ENABLE_ARGO && !(await waitPort(ARGO_PORT, 5000))) logError(`xray not listening on ${ARGO_PORT} after 5s, starting cloudflared anyway`);
  } else { logError('xray binary missing'); scheduleRestart('web'); }

  if (ENABLE_ARGO) {
    await startEdgeForwarder();
    if (await pathExists(botPath)) {
      startBot();
    } else {
      logError('cloudflared binary missing');   // 下载失败也交给 watchdog 稍后重下, 不再永久缺席
      scheduleRestart('bot');
    }
  }
  argoDiag();   // 后台跑, 不阻塞主流程
}

// =========================== Argo 诊断(SHOW_LOG 时打印) ===========================
async function argoDiag() {
  if (!(ENABLE_ARGO && SHOW_LOG)) return;
  try {
    await sleep(8000);
    log('[argo-diag] ---- cloudflared log (tail) ----');
    const txt = readText(bootLogPath);
    if (txt) {
      const lines = txt.replace(/eyJ[A-Za-z0-9=_-]{20,}/g, '<token>').trim().split('\n').slice(-25);
      for (const ln of lines) log(`[argo-diag] ${ln.slice(0, 300)}`);
    } else {
      log('[argo-diag] boot.log not found (cloudflared may have exited immediately)');
    }
    if (EDGE_PROXY && edgeLocalAddrs.length) log('[argo-diag] 边缘经代理转发, 跳过直连 7844 测试');
    for (const host of (EDGE_PROXY && edgeLocalAddrs.length) ? [] : EDGE_HOSTS) {
      const t0 = Date.now();
      try {
        const addrs = await new Promise((resolve, reject) => {
          dns.lookup(host, { all: true, family: 4 }, (err, a) => (err ? reject(err) : resolve(a)));
        });
        const list = Array.from(new Set(addrs.map((a) => a.address))).sort();
        log(`[argo-diag] dns ${host} -> ${JSON.stringify(list.slice(0, 3))}`);
        const s = await connectWithTimeout(list[0], EDGE_REMOTE_PORT, 5);
        s.destroy();
        log(`[argo-diag] node tcp ${list[0]}:${EDGE_REMOTE_PORT} ok ${((Date.now() - t0) / 1000).toFixed(2)}s`);
      } catch (e) {
        log(`[argo-diag] node tcp ${host}:${EDGE_REMOTE_PORT} FAILED ${e.message}`);
      }
    }
    const c = procs.bot.child;
    const alive = c && c.exitCode === null && c.signalCode === null;
    log(`[argo-diag] cloudflared pid: ${alive ? c.pid : 'NOT RUNNING'}`);
  } catch (e) {
    log(`[argo-diag] error: ${e.message}`);
  }
}

// =========================== 提取隧道域名 ===========================
const EXTRACT_WAIT = Math.max(1, cfgInt('EXTRACT_WAIT', '20'));   // 每次最多等多少秒拿临时隧道域名; 拿到立即继续

// 从 boot.log 找 xxx.trycloudflare.com; 排除报错行里的 api.trycloudflare.com(请求临时隧道失败时会打印)
function readQuickDomain() {
  const content = readText(bootLogPath);
  if (!content) return null;
  for (const m of content.matchAll(/https?:\/\/([a-z0-9-]+\.trycloudflare\.com)\b/gi)) {
    if (m[1].toLowerCase() !== 'api.trycloudflare.com') return m[1];
  }
  return null;
}

// 轮询 boot.log, 拿到域名就返回; cloudflared 已退出则不再白等
async function waitQuickDomain(timeoutSec) {
  const t0 = Date.now();
  for (;;) {
    const d = readQuickDomain();
    const el = Date.now() - t0;
    if (d || el >= timeoutSec * 1000 || shuttingDown) return d;
    if (!isAlive('bot') && el > 2000) return readQuickDomain();   // 进程没了: 给 2 秒把最后的日志写完
    await sleep(500);
  }
}

// 等被 kill 的子进程真正退出(最多 timeoutMs), 再起新的
async function waitExit(child, timeoutMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => {
    const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) { /* ignore */ } resolve(); }, timeoutMs);
    child.once('exit', () => { clearTimeout(t); resolve(); });
  });
}

// fromWatchdog=true 时调用方已持有 botBusy
async function extractDomains(retry = 0, fromWatchdog = false) {
  if (!ENABLE_ARGO) {
    log('ENABLE_ARGO is false, skip Argo domain extraction');
    await generateLinks(null, 'ENABLE_ARGO 已关闭, 未生成 Argo 节点');
    return;
  }
  if (isFixedTunnel()) {
    log(`ARGO_DOMAIN: ${ARGO_DOMAIN}`);
    log(`Argo 订阅: https://${ARGO_DOMAIN}/${SUB_PATH}`);
    await generateLinks(ARGO_DOMAIN);
    return;
  }
  try {
    const domain = await waitQuickDomain(EXTRACT_WAIT);
    if (domain) {
      log(`ArgoDomain: ${domain}`);
      await generateLinks(domain);
      return;
    }
    if (readText(bootLogPath) === null && !isAlive('bot')) { await generateLinks(null, '读取不到 boot.log, 获取不到临时隧道, 已跳过 Argo 节点'); return; }
    if (retry >= EXTRACT_MAX_RETRY) {
      logError(`ArgoDomain not found after ${retry} retries, generating non-Argo nodes only`);
      await generateLinks(null, `重试 ${retry} 次仍获取不到临时隧道域名, 已跳过 Argo 节点`);
      return;
    }
    log('ArgoDomain not found, re-running bot to obtain ArgoDomain');
    const own = !fromWatchdog;
    if (own) {
      while (botBusy) await sleep(500);
      botBusy = true;
    }
    try {
      const old = procs.bot.child;
      killTracked('bot');
      await waitExit(old);      // 等旧进程真正退出, 不再固定 sleep 3 秒
      await safeUnlink(bootLogPath);
      startBot();     // 复用 botArgs(), 保留 --edge 转发参数
    } finally {
      if (own) botBusy = false;
    }
    await extractDomains(retry + 1, fromWatchdog);
  } catch (e) {
    logError(`Error reading boot.log: ${e.message}`);
    await generateLinks(null, `提取隧道域名出错(${e.message}), 已跳过 Argo 节点`);
  }
}

// =========================== 获取 ISP / 公网 IP ===========================
async function getMetaInfo() {
  try {
    const res = await pfetch('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    if (data.country_code && data.isp) return `${data.country_code}-${data.isp}`.replace(/ /g, '_');
  } catch (_) { /* ignore */ }
  try {
    const res = await pfetch('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(3000) });
    const data = await res.json();
    if (data.status === 'success' && data.countryCode && data.org) return `${data.countryCode}-${data.org}`.replace(/ /g, '_');
  } catch (_) { /* ignore */ }
  return 'Unknown';
}

async function fetchPublicIpVersion(version = 'v4', timeoutMs = 3000) {
  const host = version === 'v4' ? 'ipv4.ip.sb' : 'ipv6.ip.sb';
  try {
    const res = await pfetch(`http://${host}`, { signal: AbortSignal.timeout(timeoutMs) });
    const ip = (await res.text()).trim();
    if (ip && net.isIP(ip) !== 0) return ip;
  } catch (_) { /* ignore */ }
  try {
    const { stdout } = await execFileP('curl', ['-sm', String(Math.ceil(timeoutMs / 1000) + 2), host], { timeout: timeoutMs + 3000 });
    const ip = stdout.trim();
    if (ip && net.isIP(ip) !== 0) return ip;
  } catch (_) { /* ignore */ }
  return null;
}

async function getServerIp() {
  const v4 = await fetchPublicIpVersion('v4');
  if (v4) return v4;
  const v6 = await fetchPublicIpVersion('v6');
  if (v6) return `[${v6}]`;
  logError('Failed to get IP address');
  return null;
}

// =========================== 生成节点链接 ===========================
async function generateLinks(argoDomain, argoNote = '') {
  const nodeName = NAME || await getMetaInfo();   // NAME 有值直接用, 为空才查 ISP
  const nn = encodeURIComponent(nodeName);        // # 后面的备注要 URL 编码, 防止 # % & 或中文把链接弄坏
  // 只有开了需要公网 IP 的直连节点才去取 IP; 一个都没开就不取, 也不报"获取不到公网 IP"
  const directTypes = [['HY2', HY2_PORT], ['Reality', REALITY_PORT], ['SOCKS5', S5_PORT]]
    .filter(([, p]) => isValidPort(p)).map(([n]) => n);
  const serverIp = directTypes.length ? await getServerIp() : null;
  let ipNote = '';
  if (directTypes.length && !serverIp) {
    ipNote = `获取不到公网 IP, 已跳过直连节点(${directTypes.join('/')})`;
    logError(`No public IP, skip direct nodes (${directTypes.join('/')})`);
  }

  let subTxt = '';

  const cfAddr = CFIP || argoDomain;   // CFIP 留空时直接连隧道域名, 不生成 @:443 的坏链接
  if (ENABLE_ARGO && argoDomain) {
    subTxt += `\nvless://${UUID}@${cfAddr}:${CFPORT}?encryption=none&security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Fvless-argo%3Fed%3D2560#${nn}-VLESS-Argo`;
    const vmessObj = {
      v: '2', ps: `${nodeName}-VMess-Argo`, add: cfAddr, port: CFPORT,
      id: UUID, aid: '0', scy: 'auto', net: 'ws',
      type: 'none', host: argoDomain, path: '/vmess-argo?ed=2560',
      tls: 'tls', sni: argoDomain, alpn: '', fp: 'firefox',
    };
    subTxt += `\nvmess://${b64(JSON.stringify(vmessObj))}`;
    subTxt += `\ntrojan://${UUID}@${cfAddr}:${CFPORT}?security=tls&sni=${argoDomain}&fp=firefox&type=ws&host=${argoDomain}&path=%2Ftrojan-argo%3Fed%3D2560#${nn}-Trojan-Argo`;
  }
  if (serverIp && isValidPort(HY2_PORT)) {
    const fingerprint = await getCertificateFingerprint(certPath);
    const fpParam = fingerprint ? `&pinSHA256=${encodeURIComponent(fingerprint)}` : '';
    subTxt += `\nhysteria2://${UUID}@${serverIp}:${HY2_PORT}/?sni=bing.com&insecure=1&alpn=h3${fpParam}#${nn}-HY2`;
  }
  if (serverIp && isValidPort(REALITY_PORT)) {
    subTxt += `\nvless://${UUID}@${serverIp}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=firefox&pbk=${publicKeyB64}&type=tcp&headerType=none#${nn}-Reality`;
  }
  if (serverIp && isValidPort(S5_PORT)) {
    const s5Auth = b64(`${UUID.slice(0, 8)}:${UUID.slice(-12)}`);
    subTxt += `\nsocks://${s5Auth}@${serverIp}:${S5_PORT}#${nn}-SOCKS5`;
  }

  const lines = subTxt.split('\n').filter(Boolean);
  const argoCount = lines.filter(l => /-(VLESS|Trojan)-Argo$/.test(l) || l.startsWith('vmess://')).length;
  linkStatus = {
    total: lines.length, argo: argoCount, direct: lines.length - argoCount,
    argoNote: ENABLE_ARGO && !argoDomain ? argoNote : '',
    ipNote,
    name: nodeName,
    subUrl: argoDomain && PORT ? `https://${argoDomain}/${SUB_PATH}` : (PROJECT_URL ? `${PROJECT_URL}/${SUB_PATH}` : ''),
  };
  if (!lines.length) logError('No nodes generated: 空节点');
  else if (linkStatus.argoNote) logError(linkStatus.argoNote);

  const subTxtB64 = b64(subTxt);
  if (SHOW_LOG && lines.length) {
    console.log(`\x1b[32m${subTxtB64}\x1b[0m`);
    console.log('\x1b[35mLogs will be deleted in 90 seconds, you can copy the above nodes\x1b[0m');
  }
  await fsp.writeFile(subPath, subTxtB64, 'utf-8');
  await fsp.writeFile(listPath, subTxt, 'utf-8');
  log(`${FILE_PATH}/sub.txt saved successfully`);
  subTxtContent = subTxtB64;
}

// =========================== Telegram 推送 ===========================
// MarkdownV2 普通文本转义(含反斜杠本身)
function escMd(t) { return String(t).replace(/[\\_*[\]()~`>#+=|{}.!-]/g, '\\$&'); }

async function tgSend(text, parseMode) {
  const params = { chat_id: TG_CHAT_ID, text };
  if (parseMode) params.parse_mode = parseMode;
  // 参数放在 POST body 里, 订阅很长时也不会超出 URL 长度限制
  // 网络错误/超时也返回失败而不是抛出: 否则不会退回纯文本, 后面的异常通知也会被跳过
  try {
    const res = await pfetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, {
      method: 'POST', body: new URLSearchParams(params), signal: AbortSignal.timeout(10000),
    });
    let body = '';
    if (!res.ok) { try { body = (await res.text()).slice(0, 200); } catch (_) { /* ignore */ } }
    return { ok: res.ok, status: res.status, body };
  } catch (e) {
    return { ok: false, status: 0, body: String(e.message).split(TG_BOT_TOKEN || '<token>').join('<token>') };   // 别把 bot token 打进日志
  }
}

// 先按 MarkdownV2 发, 失败(解析错误/超长)自动退回纯文本
async function tgPush(md, plain) {
  let r = md.length <= 4096 ? await tgSend(md, 'MarkdownV2') : { ok: false, status: 0, body: 'message too long' };
  if (!r.ok) {
    logError(`Telegram MarkdownV2 send failed: HTTP ${r.status} ${r.body}, retry as plain text`);
    r = await tgSend(plain.length > 4096 ? plain.slice(0, 4090) + '\n...' : plain, '');
  }
  if (r.ok) log('Telegram message sent successfully');
  else logError(`Telegram send failed: HTTP ${r.status} ${r.body}`);
}

async function sendTelegram() {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) { log('TG variables is empty, Skipping push nodes to TG'); return; }
  try {
    const message = (readText(subPath) || '').trim();
    const st = linkStatus;
    const nm = st.name || NAME;          // NAME 为空时用 ISP 名, 和节点备注一致
    const title = `${nm}节点推送通知`;

    // 1) 有节点: 先推节点
    if (st.total && message) {
      const info = `节点数: ${st.total} (Argo ${st.argo} / 直连 ${st.direct})`;
      await tgPush(
        `*${escMd(title)}*\n${escMd(info)}\n\`\`\`\n${message.replace(/[\\`]/g, '\\$&')}\n\`\`\`${st.subUrl ? `\n${escMd(`订阅地址: ${st.subUrl}`)}\n` : ''}`,
        `${title}\n${info}\n\n${message}\n${st.subUrl ? `\n订阅地址: ${st.subUrl}\n` : ''}`,
      );
    }

    // 2) 再单独推报错: 空节点 / 拿不到临时隧道 / 拿不到公网 IP
    const errs = [];
    if (!st.total) errs.push('空节点: 没有生成任何节点');
    if (st.argoNote) errs.push(st.argoNote);
    if (st.ipNote) errs.push(st.ipNote);
    if (errs.length) {
      const et = `${nm}节点异常通知`;
      await tgPush(
        `*⚠️ ${escMd(et)}*\n${errs.map(e => `• ${escMd(e)}`).join('\n')}`,
        `⚠️ ${et}\n${errs.map(e => `• ${e}`).join('\n')}`,
      );
    }
  } catch (e) {
    logError(`Failed to send Telegram message: ${e.message}`);
  }
}

// =========================== 上传节点到订阅器 ===========================
async function uploadNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    try {
      const res = await pfetch(`${UPLOAD_URL}/api/add-subscriptions`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subscription: [`${PROJECT_URL}/${SUB_PATH}`] }), signal: AbortSignal.timeout(10000),
      });
      if (res.ok) log('Subscription uploaded successfully');
    } catch (_) { /* ignore */ }
  } else if (UPLOAD_URL) {
    const content = readText(listPath);
    if (!content) return;
    const nodes = content.split('\n').filter((l) => NODE_LINE_RE.test(l));
    if (!nodes.length) return;
    try {
      const res = await pfetch(`${UPLOAD_URL}/api/add-nodes`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ nodes }), signal: AbortSignal.timeout(10000),
      });
      if (res.ok) log('Nodes uploaded successfully');
    } catch (_) { /* ignore */ }
  }
}

// =========================== 自动保活 ===========================
async function addVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) { log('Skipping adding automatic access task'); return; }
  try {
    await pfetch('https://oooo.serv00.net/add-url', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: PROJECT_URL }), signal: AbortSignal.timeout(10000),
    });
    log('automatic access task added successfully');
  } catch (e) {
    logError(`Add URL failed: ${e.message}`);
  }
}

// =========================== CF-Server-Monitor 探针(运行时从仓库拉取 botp.js) ===========================
// 探针代码不在本文件, 启动时拉取 PROBE_MODULE_URL 运行; 本文件只传 ID/地址/密钥
// 其它探针参数(上报间隔、三网测速节点等)用 botp 默认值, 需要改就设同名环境变量, botp 自己会读
async function probeFetchModule() {
  const res = await pfetch(PROBE_MODULE_URL, { redirect: 'follow', signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const code = Buffer.from(await res.arrayBuffer());
  if (PROBE_MODULE_SHA256 && crypto.createHash('sha256').update(code).digest('hex') !== PROBE_MODULE_SHA256) {
    throw new Error('SHA-256 不匹配, 拒绝运行');
  }
  // botp.js 是 CommonJS: 写成临时 .cjs 用 require 加载, 加载完立即删除(不留在 FILE_PATH, 不受 90 秒清理影响)
  const tmp = path.join(os.tmpdir(), `botp-${process.pid}-${Date.now()}.cjs`);
  fs.writeFileSync(tmp, code);
  try {
    const mod = require(tmp);
    delete require.cache[require.resolve(tmp)];
    if (!mod || typeof mod.start !== 'function') throw new Error('探针代码里没有 start()');
    return mod;
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) { /* ignore */ }
  }
}

function startProbe() {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) { log('PROBE variable is empty, skipping probe'); return; }
  (async () => {
    let delay = 30;
    let mod = null;
    while (!mod && !shuttingDown) {
      try {
        mod = await probeFetchModule();
      } catch (e) {
        logError(`[probe] 拉取探针代码失败: ${e.message}, ${delay}s 后重试`);
        await sleep(delay * 1000);
        delay = Math.min(delay * 2, 600);
      }
    }
    if (!mod) return;
    mod.start({ PROBE_ID, PROBE_SECRET, PROBE_URL }, {
      log, logError,
      fetch: pfetch,                                                      // POST / 查公网 IP 走系统代理
      wsConnector: (u) => { const p = sysProxyFor(u); return p ? proxyConnector(u, p) : null; },   // WSS 也走系统代理
    });
    log('[probe] 探针已从仓库加载并启动');
  })().catch((e) => logError(`[probe] 探针启动失败: ${e.message}`));
}

// =========================== 面板输入框 -> 执行 shell 命令 ===========================
function runShell(cmd, label = '') {
  return new Promise((resolve) => {
    const child = spawn(fs.existsSync('/bin/bash') ? '/bin/bash' : '/bin/sh', ['-c', cmd], { cwd: process.cwd(), env: process.env });   // alpine 等精简镜像没有 bash
    child.stdout.on('data', (d) => process.stdout.write(d));
    child.stderr.on('data', (d) => process.stderr.write(d));
    let finished = false;
    const finish = (code) => {
      if (finished) return;
      finished = true;
      alwaysLog(`[${timestamp()}] ${label}结束,退出码 ${code}`);
      resolve(code);
    };
    child.on('error', (e) => { alwaysLog(`[${timestamp()}] ${label}执行失败: ${e.message}`); finished = true; resolve(-1); });
    // 用 exit 而不是 close: 命令留下后台子进程占着输出管道时 close 会一直不触发
    child.on('close', (code) => finish(code));
    child.on('exit', (code) => setTimeout(() => finish(code), 500));
  });
}

const STDIN_SHELL = cfgBool('STDIN_SHELL', 'false');   // 把 stdin 每行当 shell 命令执行(面板控制台用), 默认关: 能写 stdin 的都能执行命令
function startStdinShell() {
  if (!STDIN_SHELL) return;
  let input;
  try { input = process.stdin; } catch (_) { return; }   // fd 0 被关闭时访问 stdin 可能抛错
  if (!input || input.destroyed) return;
  input.on('error', () => {});
  const rl = readline.createInterface({ input });
  rl.on('line', (line) => {
    const cmd = line.trim();
    if (!cmd) return;
    alwaysLog(`[${timestamp()}] $ ${cmd}`);
    runShell(cmd, '命令');
  });
  rl.on('error', () => {});
}

// =========================== 清理临时文件 ===========================
function cleanFiles() {
  setTimeout(async () => {
    for (const f of [bootLogPath, configPath, listPath, webPath, botPath, tunnelJsonPath, tunnelYmlPath]) await safeUnlink(f);
    cleanedOnce = true;
    if (SHOW_LOG) process.stdout.write('\x1bc');
    alwaysLog('App is running');
    log('Thank you for using this script, enjoy!');
  }, 90000).unref();
}

// =========================== HTTP 服务 ===========================
function requestHandler(req, res) {
  let pathname = '/';
  try { pathname = new URL(req.url, 'http://localhost').pathname; } catch (_) { /* ignore */ }
  if (pathname === `/${SUB_PATH}`) {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', Connection: 'close' });   // 不复用连接, 避免 cloudflared 把后续 WS 发到订阅端口
    res.end(subTxtContent);
    return;
  }
  if (pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('Hello world!');
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
}

function portBindTest(port, udp) {
  // 能绑定则 resolve 句柄(调用方关闭), 否则 resolve null; port=0 由系统分配
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    try {
      if (udp) {
        const s = dgram.createSocket('udp4');
        s.once('error', () => { try { s.close(); } catch (_) { /* ignore */ } finish(null); });
        s.bind(port, '0.0.0.0', () => finish({ port: s.address().port, close: () => { try { s.close(); } catch (_) { /* ignore */ } } }));
      } else {
        const s = net.createServer();
        s.once('error', () => { try { s.close(); } catch (_) { /* ignore */ } finish(null); });
        s.listen({ port: port, host: '0.0.0.0', exclusive: true }, () => finish({ port: s.address().port, close: () => { try { s.close(); } catch (_) { /* ignore */ } } }));
      }
    } catch (_) { finish(null); }
  });
}

async function resolveAutoPorts() {
  // 端口留空 = 不开启; 填 0 = 自动分配空闲端口(HY2 为 UDP, 其余 TCP)
  const cur = { S5_PORT: S5_PORT, HY2_PORT: HY2_PORT, REALITY_PORT: REALITY_PORT };
  const wanted = Object.keys(cur).filter((k) => String(cur[k]).trim() === '0');
  if (!wanted.length) return;
  let saved = {};
  try {
    saved = JSON.parse(await fsp.readFile(autoPortsPath, 'utf8'));
    if (!saved || typeof saved !== 'object') saved = {};
  } catch (_) { saved = {}; }
  const fixed = new Set();
  [S5_PORT, HY2_PORT, REALITY_PORT, PORT, ARGO_PORT,
    ...reservedPorts()].forEach((v) => {   // 转发用的本地端口(未启用转发时为空)
    const n = parseInt(String(v).trim(), 10);
    if (n > 0) fixed.add(n);
  });
  const held = [];
  const result = {};
  const used = () => Object.values(result);
  try {
    for (const key of wanted) {
      const udp = key === 'HY2_PORT';
      let h = null;
      const old = parseInt(saved[key], 10);
      if (old >= 1024 && old <= 65535 && !fixed.has(old) && !used().includes(old)) h = await portBindTest(old, udp);
      // 先在 20000-32767 里随机挑(低于系统临时端口段), 避免释放后到 Xray 绑定前被出站连接的源端口抢走
      let tries = 0;
      while (!h && tries < 60) {
        tries++;
        let c = null;
        if (tries <= 50) {
          const want = 20000 + Math.floor(Math.random() * 12768);
          if (fixed.has(want) || used().includes(want)) continue;
          c = await portBindTest(want, udp);
          if (!c) continue;
        } else {
          c = await portBindTest(0, udp);
          if (!c) break;
        }
        if (fixed.has(c.port) || used().includes(c.port)) { held.push(c); continue; }
        h = c;
      }
      if (!h) {
        log(`${key}=0 自动分配端口失败, 该节点不开启`);
        result[key] = '';
        continue;
      }
      held.push(h);
      result[key] = h.port;
    }
  } finally {
    held.forEach((h) => h.close());
  }
  await sleep(50);   // 等句柄真正释放, 再让 Xray 绑定
  for (const key of Object.keys(result)) {
    const v = result[key] ? String(result[key]) : '';
    if (key === 'S5_PORT') S5_PORT = v;
    else if (key === 'HY2_PORT') HY2_PORT = v;
    else if (key === 'REALITY_PORT') REALITY_PORT = v;
    if (v) log(`${key}=0 已自动分配端口: ${v}`);
    if (v) saved[key] = result[key];
  }
  try { await fsp.writeFile(autoPortsPath, JSON.stringify(saved)); } catch (_) { /* ignore */ }
}

// =========================== 主流程 ===========================
// 上次运行被 kill -9 时留下的 xray/cloudflared(程序文件在 FILE_PATH 里)还占着端口: 启动前先结束掉
async function killLeftovers() {
  let pids = [];
  try { pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d) && Number(d) !== process.pid); } catch (_) { return; }
  const prefix = FILE_PATH + path.sep;
  let n = 0;
  for (const pid of pids) {
    try {
      const argv0 = fs.readFileSync(`/proc/${pid}/cmdline`, 'latin1').split('\0')[0];
      if (argv0.startsWith(prefix)) { process.kill(Number(pid), 'SIGTERM'); n++; }
    } catch (_) { /* ignore */ }
  }
  if (n) { log(`结束了 ${n} 个上次残留的进程`); await sleep(1000); }
}

async function startServer() {
  await deleteNodes();
  await createDirectory();
  await killLeftovers();
  await cleanupOldFiles();
  await argoType();
  await resolveAutoPorts();   // 端口填 0 的自动分配空闲端口

  if (!UUID) {
    UUID = crypto.randomUUID();
    log(`UUID not set, generated a random one for this run: ${UUID}`);
  }
  if (!PROBE_ID) PROBE_ID = UUID;   // 与 app.py 一致: 探针 ID 默认等于 UUID
  if (isValidPort(REALITY_PORT)) await generateOrLoadKeypair();
  if (isValidPort(HY2_PORT)) await ensureTlsCertificates();

  await startNodeEgress();     // 先起出站(决定实际端口/是否退回 direct), 再生成 Xray 配置
  await generateXrayConfig();
  await downloadFilesAndRun();
  await extractDomains();

  await sendTelegram();
  await uploadNodes();
  await addVisitTask();
  startProbe();

  cleanFiles();
  if (WATCHDOG) log('[watchdog] started');
}

// =========================== 信号处理 ===========================
function stopAll() {
  if (shuttingDown) return;
  shuttingDown = true;
  log('\nShutting down...');
  killTracked('web');
  killTracked('bot');
  setTimeout(() => process.exit(0), 1000);
}

process.on('SIGINT', stopAll);
process.on('SIGTERM', stopAll);
process.on('uncaughtException', (err) => alwaysLog(`[${timestamp()}] 未捕获异常: ${(err && err.stack) || err}`));
process.on('unhandledRejection', (r) => alwaysLog(`[${timestamp()}] 未处理的 Promise 拒绝: ${(r && r.stack) || r}`));

// =========================== 入口 ===========================
// 启用转发(放在文件末尾: 转发用到的函数和变量都已初始化)
if (USE_FORWARD) forwardSetup();
else alwaysLog('[forward] USE_FORWARD=false, 跳过转发 (Xray / cloudflared 直连)');

if (!globalThis.__ARGO_NO_MAIN__) {   // 测试时设置 globalThis.__ARGO_NO_MAIN__ = true 可只加载不启动
  const server = http.createServer(requestHandler);
  server.headersTimeout = 15000;   // 慢连接/空连接 15 秒断开
  server.requestTimeout = 15000;
  // 等 HTTP 端口确定后再生成 Xray 配置, 否则 PORT=0 时 Argo 的 /SUB_PATH 分流拿不到实际端口
  const httpReady = new Promise((resolve) => {
    server.on('error', (e) => { alwaysLog(`[http] ${e.message}`); PORT = 0; resolve(); });   // 订阅没起来就不分流
    try {
      server.listen(PORT, '0.0.0.0', () => { PORT = server.address().port; alwaysLog(`server is running on ${PORT}!`); resolve(); });   // PORT=0 时取系统分配的实际端口
    } catch (e) {   // PORT 越界会同步抛错, 不能让整个脚本起不来
      alwaysLog(`[http] listen ${PORT} failed: ${e.message}`);
      PORT = 0;
      resolve();
    }
  });
  startStdinShell();
  httpReady.then(() => startServer()).catch((e) => alwaysLog(`start_server error: ${(e && e.stack) || e}`));
}

const __testApi = {
  pfetch, sysProxyFor, cfg, killLeftovers,
  // 测试用
  
  generateXrayConfig, botArgs, extractFromZip, parseTunnelId, startProbe, probeFetchModule,
  waitPort, startWeb, startBot, extractDomains, isAlive, killTracked, procs, webPath, botPath, bootLogPath,
  setUuid: (u) => { UUID = u; }, generateOrLoadKeypair, ensureTlsCertificates, configPath, resolveAutoPorts, generateLinks,
};
Object.defineProperties(__testApi, Object.getOwnPropertyDescriptors(fwdTestApi));   // 合并转发部分的测试接口(保留 getter)
module.exports = __testApi;
