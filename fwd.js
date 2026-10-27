'use strict';
/**
 * 转发模块(从 index.js 拆出, 与 index.js 放在同一目录, 同样是 ESM)
 *
 * 包含两部分:
 *   1. Node SOCKS5 出站: Xray 默认出站经 127.0.0.1:EGRESS_PORT 由 Node 代连(TCP + UDP ASSOCIATE)
 *   2. 边缘转发器: cloudflared 经 127.0.0.1:17844~17847 由 Node 连 CF 边缘, 支持 EDGE_PROXY / EDGE_PROXY_FILE
 *
 * 用法(index.js 已经写好):
 *   const fwd = await import('./forward.js');
 * 开关和代理配置都在下面的 FORWARD_CONF 里, index.js 不再有任何转发配置。
 *   fwd.setup({ enableArgo, showLog, log, logError, alwaysLog,
 *               isValidPort, makeReader, connectWithTimeout, proxyOpenOnce, normProxy });
 *   await fwd.startNodeEgress();      // 生成 Xray 配置之前
 *   await fwd.startEdgeForwarder();   // 启动 cloudflared 之前, 之后用 fwd.edgeLocalAddrs 拼 --edge
 * 会被改写的状态(EGRESS_MODE / EGRESS_PORT / EDGE_PROXY / edgeLocalAddrs)是 ESM 活绑定, 一律用 fwd.XXX 读。
 */
import fs from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns';
import tls from 'node:tls';

const env = process.env;

// ==================== 转发配置(只在这里改, 环境变量同名可覆盖) ====================
// index.js 发现同目录有本文件就直接启用转发; 临时关闭可设环境变量 USE_FORWARD=false
const FORWARD_CONF = {
  EDGE_PROXY: '',              // cloudflared 连 CF 边缘走的代理, 如 http://user:pass@host:3128 或 socks5://...; 留空读 HTTPS_PROXY/ALL_PROXY/HTTP_PROXY; 读到就走代理(不通再试直连), 读不到直连; 填 0 永不走代理
  EDGE_PROXY_FILE: '',         // 可选: 代理地址文件(一行, 如 http://user:pass@host:3128)。填了就以文件为准, 代理认证失败(407)时自动重读, 密码轮换不用重启
};

// =========================== 由 setup() 注入 / 计算 ===========================
let ENABLE_ARGO = true;
let SHOW_LOG = false;
let log = () => {};
let logError = () => {};
let alwaysLog = (msg) => { process.stdout.write(msg + '\n'); };
const deps = {};   // index.js 里共用的工具: isValidPort / makeReader / connectWithTimeout / proxyOpenOnce / normProxy
const isValidPort = (p) => deps.isValidPort(p);
const makeReader = (s) => deps.makeReader(s);
const connectWithTimeout = (h, p, t) => deps.connectWithTimeout(h, p, t);
const normProxy = (v) => deps.normProxy(v);

// 环境变量工具: 未设置或为空白时用默认值
function cfgRaw(key, def) { const v = env[key]; return v !== undefined && String(v).trim() !== '' ? v : def; }
function cfgInt(key, def) { const n = parseInt(cfgRaw(key, def), 10); return Number.isFinite(n) ? n : parseInt(def, 10); }
function cfgFloat(key, def) { const n = parseFloat(cfgRaw(key, def)); return Number.isFinite(n) ? n : parseFloat(def); }

// ---- 出站转发 ----
export let EGRESS_MODE = 'direct';                    // setup() 后 = node: Xray 默认出站经本机 SOCKS5 由 Node 代连(出站起不来时退回 direct); direct=Xray 自己直连
export let EGRESS_PORT = cfgInt('EGRESS_PORT', '10087');
export let BLOCK_QUIC = false;                       // setup() 后为 true: 走 Node 出站时屏蔽 udp/443(QUIC)
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
export let EDGE_PROXY_FILE = '';   // setup() 里赋值
export let EDGE_PROXY = '';        // 当前实际使用的代理(直连兜底时为空), setup() 里赋值
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
export let EDGE_FWD = false;   // setup() 后为 true
export const EDGE_LOCAL_BASE = cfgInt('EDGE_LOCAL_BASE', '17844');    // 本地监听起始端口, 共 4 个
export const EDGE_REMOTE_PORT = cfgInt('EDGE_REMOTE_PORT', '7844');
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
export async function startNodeEgress() {
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
export let edgeLocalAddrs = [];
export let edgeIps = [];                 // 当前可用的边缘 IP 列表
const edgePrimary = new Map();    // 本地端口 -> 主用 IP(粘性: 只有连不上或已不在解析结果里才换)

const authErr = (m) => Object.assign(new Error(m), { proxyAuth: true });
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
    s = await deps.proxyOpenOnce(host, port, timeoutSec, EDGE_PROXY);
  } catch (e) {
    if (!e.proxyAuth) throw e;
    if (!proxyReload()) {
      authState.wait = Math.min(Math.max(authState.wait * 2, 5), 300);
      authState.until = Date.now() + authState.wait * 1000;
      logError(`[edge-fwd] 代理认证失败, ${authState.wait} 秒内不再重试${EDGE_PROXY_FILE ? '' : ' (可设 EDGE_PROXY_FILE 让密码轮换后自动重读)'}`);
      throw e;
    }
    try {
      s = await deps.proxyOpenOnce(host, port, timeoutSec, EDGE_PROXY);
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

export const EDGE_HOSTS = ['region1.v2.argotunnel.com', 'region2.v2.argotunnel.com'];
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
export async function startEdgeForwarder() {
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
// 由 index.js 启动时调用一次: 传入 ENABLE_ARGO、日志函数和共用工具; 转发相关配置都读本文件的 FORWARD_CONF / 环境变量
export function setup(o) {
  ENABLE_ARGO = o.enableArgo === undefined ? true : Boolean(o.enableArgo);
  SHOW_LOG = Boolean(o.showLog);
  if (o.log) log = o.log;
  if (o.logError) logError = o.logError;
  if (o.alwaysLog) alwaysLog = o.alwaysLog;
  for (const k of ['isValidPort', 'makeReader', 'connectWithTimeout', 'proxyOpenOnce', 'normProxy']) {
    if (typeof o[k] !== 'function') throw new Error(`forward.setup: missing ${k}`);
    deps[k] = o[k];
  }
  EGRESS_MODE = 'node';
  BLOCK_QUIC = true;   // 走 Node 出站时屏蔽 udp/443(QUIC)
  EDGE_FWD = true;
  EDGE_PROXY_FILE = String(cfgRaw('EDGE_PROXY_FILE', FORWARD_CONF.EDGE_PROXY_FILE)).trim();
  const raw = String(cfgRaw('EDGE_PROXY', FORWARD_CONF.EDGE_PROXY)).trim();
  EDGE_PROXY = /^(0|false|none|off|no)$/i.test(raw) ? '' : (readProxyFile() || normProxy(raw || ['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy']
    .map((k) => String(env[k] || '').trim()).find((x) => x) || ''));
  edgeProxyCfg = EDGE_PROXY;
  alwaysLog('[forward] 检测到 forward.js, 已启用转发');
}

// 自动分配端口时要避开的本地端口(出站 3 个候选 + 边缘转发 4 个)
export function reservedPorts() {
  return [EGRESS_PORT, EGRESS_PORT + 1, EGRESS_PORT + 2, EDGE_LOCAL_BASE, EDGE_LOCAL_BASE + 1, EDGE_LOCAL_BASE + 2, EDGE_LOCAL_BASE + 3];
}

// 测试用(index.js 会合并进它的 default export)
export const testApi = {
  startNodeEgress, startEdgeForwarder, s5ParseUdp, s5PackAddr, ipToBuf, bufToIp6,
  resolveHost, happyConnect, edgePrimary, edgeProxyOpen, s5Handle, edgeOpen, edgeResolve, edgeIpOk,
  get EDGE_PROXY() { return EDGE_PROXY; }, setEdgeProxy: (v) => { EDGE_PROXY = v; edgeProxyCfg = v; }, authState,
  edgeProbe, edgeProbeOne, edgeRtt, setEdgeIps: (ips) => { edgeIps = ips; }, getEgressPort: () => EGRESS_PORT, getEdgeLocalAddrs: () => edgeLocalAddrs,
};
