// cf-probe (Node.js): CF-Server-Monitor 探针, 读 /proc 上报, 不需要 root/systemd/二进制/npm 依赖。Node >= 18。
// 合并版: 脚本内置探针(自带 WebSocket 客户端、DNS 只解析一次且 IPv4 优先、ack 容错、断线立即重连、curl 兜底查 IP)
//        + botp 的优点(独立模块、看门狗、三网并行测速)。
// 本文件不含任何密钥或上报地址, 配置全部由调用方传入:
//   require('./botp.js').start({ PROBE_ID, PROBE_SECRET, PROBE_URL, ... }, { log, logError, fetch, wsConnector })
//   ESM 里: createRequire(import.meta.url)('/path/botp.cjs').start(...)
// 也可单独运行: PROBE_ID=xx PROBE_SECRET=xx PROBE_URL=https://.../update node botp.js
'use strict';
const fs = require('fs');
const os = require('os');
const net = require('net');
const dns = require('dns');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { execFile, execFileSync } = require('child_process');
const { promisify } = require('util');
const execFileP = promisify(execFile);

const env = process.env;
const envInt = (k, d) => { const n = parseInt(String(env[k] || d).trim(), 10); return Number.isFinite(n) ? n : Number(d); };
const envFloat = (k, d) => { const n = parseFloat(String(env[k] || d).trim()); return Number.isFinite(n) ? n : Number(d); };
const envOn = (k, d) => !['false', '0', 'no', 'off', 'disable'].includes(String(env[k] || d).trim().toLowerCase());

// ---- 默认配置(start() 传入的 cfg 覆盖; 单独运行时读同名环境变量) ----
let PROBE_ID = env.PROBE_ID || '';
let PROBE_SECRET = env.PROBE_SECRET || '';
let PROBE_URL = env.PROBE_URL || '';
let PROBE_INTERVAL = Math.max(1, envInt('PROBE_INTERVAL', 60));
let PROBE_CT = env.PROBE_CT !== undefined ? env.PROBE_CT : 'gd-ct-dualstack.ip.zstaticcdn.com';
let PROBE_CU = env.PROBE_CU !== undefined ? env.PROBE_CU : 'gd-cu-dualstack.ip.zstaticcdn.com';
let PROBE_CM = env.PROBE_CM !== undefined ? env.PROBE_CM : 'gd-cm-dualstack.ip.zstaticcdn.com';
let PROBE_PING_COUNT = envInt('PROBE_PING_COUNT', 2);
let PROBE_PING_TIMEOUT = envFloat('PROBE_PING_TIMEOUT', 1.0);
let PROBE_IP_REFRESH_INTERVAL = envInt('PROBE_IP_REFRESH_INTERVAL', 1800);
let PROBE_WSS = envOn('PROBE_WSS', 'true');
let PROBE_PING_CACHE_TTL = envInt('PROBE_PING_CACHE_TTL', 120);
let PROBE_AGENT_VERSION = env.PROBE_AGENT_VERSION || 'nodejs';
let PROBE_WATCHDOG = envOn('PROBE_WATCHDOG', 'true');       // 看门狗开关
let PROBE_WATCHDOG_MISS = envInt('PROBE_WATCHDOG_MISS', 5); // 连续多少个上报周期没成功就重启上报循环
let DEBUG = envOn('DEBUG', 'false') && !!env.DEBUG;

const _ts = () => new Date().toLocaleString('zh-CN', { hour12: false });
let logInfo = (m) => process.stdout.write(`${_ts()} ${m}\n`);
let logError = (m) => process.stderr.write(`${_ts()} ${m}\n`);
const logDebug = (m) => { if (DEBUG) logInfo(m); };
let doFetch = (...a) => fetch(...a);   // 调用方可注入走代理的 fetch
let wsConnector = null;                // 调用方可注入 (URL) => createConnection, 让 WSS 走代理

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function readText(p) { try { return fs.readFileSync(p, 'utf8'); } catch (_) { return null; } }
function connectWithTimeout(host, port, timeoutSec) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port });
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutSec * 1000);
    s.once('connect', () => { clearTimeout(t); resolve(s); });
    s.once('error', (e) => { clearTimeout(t); s.destroy(); reject(e); });
  });
}

// 看门狗状态: gen 每次重启 +1, 旧循环发现 gen 变了就自行退出; lastOk 为最近一次上报成功时间
const wd = { gen: 0, lastOk: 0, ws: null, restarts: 0, running: false };

// =========================== 公网 IP ===========================
async function fetchPublicIpVersion(version = 'v4', timeoutMs = 3000) {
  const host = version === 'v4' ? 'ipv4.ip.sb' : 'ipv6.ip.sb';
  try {
    const res = await doFetch(`http://${host}`, { signal: AbortSignal.timeout(timeoutMs) });
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

// =========================== 采集 ===========================
function probeReadCpuTimes() {
  const line = (readText('/proc/stat') || '').split('\n')[0] || '';
  const nums = line.trim().split(/\s+/).slice(1, 9).map(Number);
  if (nums.length < 5) return { idle: 0, total: 0 };
  return { idle: nums[3] + nums[4], total: nums.reduce((a, b) => a + b, 0) };
}

function readIntFile(p) {
  const t = readText(p);
  if (t === null) return null;
  return t.trim();
}

function probeReadCgroupMemory() {
  const v2Used = readIntFile('/sys/fs/cgroup/memory.current');
  const v2Max = readIntFile('/sys/fs/cgroup/memory.max');
  if (v2Used !== null && v2Max !== null) {
    const limit = v2Max === 'max' ? null : Number(v2Max);
    let swapUsed = 0;
    let swapTotal = 0;
    const su = readIntFile('/sys/fs/cgroup/memory.swap.current');
    const sm = readIntFile('/sys/fs/cgroup/memory.swap.max');
    if (su !== null && sm !== null) {
      swapUsed = Number(su);
      swapTotal = sm === 'max' ? null : Number(sm);
    }
    return { used: Number(v2Used), limit, swapUsed, swapTotal };
  }
  const v1Used = readIntFile('/sys/fs/cgroup/memory/memory.usage_in_bytes');
  const v1Limit = readIntFile('/sys/fs/cgroup/memory/memory.limit_in_bytes');
  if (v1Used !== null && v1Limit !== null) {
    const used = Number(v1Used);
    let limit = Number(v1Limit);
    if (limit > 2 ** 62) limit = null;
    let swapUsed = 0;
    let swapTotal = 0;
    const mu = readIntFile('/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes');
    const ml = readIntFile('/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes');
    if (mu !== null && ml !== null) {
      swapUsed = Math.max(0, Number(mu) - used);
      if (Number(ml) <= 2 ** 62 && limit !== null) swapTotal = Math.max(0, Number(ml) - limit);
    }
    return { used, limit, swapUsed, swapTotal };
  }
  return null;
}

function probeReadMeminfo() {
  const MB = 1024 * 1024;
  const cg = probeReadCgroupMemory();
  if (cg && cg.limit) {
    const ramTotal = Math.floor(cg.limit / MB);
    const swapTotal = Math.floor((cg.swapTotal || 0) / MB);
    return {
      ramTotal,
      ramUsed: Math.min(Math.floor(cg.used / MB), ramTotal),
      swapTotal,
      swapUsed: swapTotal ? Math.min(Math.floor((cg.swapUsed || 0) / MB), swapTotal) : 0,
    };
  }
  const info = {};
  for (const line of (readText('/proc/meminfo') || '').split('\n')) {
    const m = line.match(/^(\w+):\s+(\d+)/);
    if (m) info[m[1]] = Number(m[2]);
  }
  const ramTotal = Math.floor((info.MemTotal || os.totalmem() / 1024) / 1024);
  const ramFree = Math.floor((info.MemAvailable !== undefined ? info.MemAvailable : (info.MemFree || os.freemem() / 1024)) / 1024);
  const swapTotal = Math.floor((info.SwapTotal || 0) / 1024);
  const swapFree = Math.floor((info.SwapFree || 0) / 1024);
  return { ramTotal, ramUsed: Math.max(0, ramTotal - ramFree), swapTotal, swapUsed: Math.max(0, swapTotal - swapFree) };
}

function probeReadDisk() {
  const MB = 1024 * 1024;
  try {
    if (typeof fs.statfsSync === 'function') {
      const st = fs.statfsSync('/');
      const total = st.blocks * st.bsize;
      const free = st.bavail * st.bsize;
      return { total: Math.floor(total / MB), used: Math.floor((total - free) / MB) };
    }
  } catch (_) { /* ignore */ }
  try {
    const out = execFileSync('df', ['-Pk', '/'], { encoding: 'utf8', timeout: 3000 }).trim().split('\n').pop().split(/\s+/);
    return { total: Math.floor(Number(out[1]) / 1024), used: Math.floor((Number(out[1]) - Number(out[3])) / 1024) };
  } catch (_) {
    return { total: 0, used: 0 };
  }
}

function probeReadNetBytes() {
  let rx = 0;
  let tx = 0;
  const lines = (readText('/proc/net/dev') || '').split('\n').slice(2);
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    if (line.slice(0, idx).trim() === 'lo') continue;
    const f = line.slice(idx + 1).trim().split(/\s+/);
    rx += Number(f[0]) || 0;
    tx += Number(f[8]) || 0;
  }
  return { rx, tx };
}

function probeBootTimeMs() {
  const m = (readText('/proc/stat') || '').match(/^btime\s+(\d+)/m);
  if (m) return Number(m[1]) * 1000;
  return Date.now() - os.uptime() * 1000;
}

function probeOsName() {
  const txt = readText('/etc/os-release');
  if (txt) {
    const info = {};
    for (const line of txt.split('\n')) {
      const i = line.indexOf('=');
      if (i > 0) info[line.slice(0, i).trim()] = line.slice(i + 1).trim().replace(/^"|"$/g, '');
    }
    if (info.PRETTY_NAME) return info.PRETTY_NAME;
    if (info.NAME) return `${info.NAME} ${info.VERSION || info.VERSION_ID || ''}`.trim();
  }
  return `${os.type()} ${os.release()}`;
}

function probeCpuInfo() {
  const m = (readText('/proc/cpuinfo') || '').match(/^model name\s*:\s*(.+)$/im);
  if (m) return m[1].trim();
  const c = os.cpus();
  return (c && c[0] && c[0].model) || 'unknown';
}

function probeMachine() {
  if (typeof os.machine === 'function') return os.machine();
  const map = { x64: 'x86_64', arm64: 'aarch64', arm: 'armv7l', ia32: 'i686' };
  return map[os.arch()] || os.arch();
}

function probeProcessCount() {
  try { return fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p)).length; } catch (_) { return 0; }
}

function probeConnCount(proto) {
  let n = 0;
  for (const name of [proto, `${proto}6`]) {    // 别漏掉 tcp6/udp6(Xray 监听 :: 的连接都在这里)
    const t = readText(`/proc/net/${name}`);
    if (t) n += Math.max(0, t.trim().split('\n').length - 1);
  }
  return n;
}

const probeIpCache = { v4: '0', v6: '0', ts: 0 };
async function probeGetPublicIps() {
  const now = Date.now();
  if (probeIpCache.ts > 0 && now - probeIpCache.ts < PROBE_IP_REFRESH_INTERVAL * 1000) return probeIpCache;
  probeIpCache.v4 = (await fetchPublicIpVersion('v4')) || '0';
  probeIpCache.v6 = (await fetchPublicIpVersion('v6')) || '0';
  probeIpCache.ts = now;
  return probeIpCache;
}

function probeParseHostPort(target, defaultPort) {
  const t = (target || '').trim();
  if (!t) return null;
  if (t.startsWith('[')) {
    const m = t.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (m) return { host: m[1], port: m[2] ? Number(m[2]) : defaultPort };
    return { host: t.replace(/^\[|\]$/g, ''), port: defaultPort };
  }
  const parts = t.split(':');
  if (parts.length === 2 && /^\d+$/.test(parts[1])) return { host: parts[0], port: Number(parts[1]) };
  return { host: t, port: defaultPort };
}

// TCP 连接耗时当 ping; 先解析一次再连 IP, 不把 DNS 时间算进去
async function probeTcpPing(target, count, timeoutSec) {
  const hp = probeParseHostPort(target, 443);
  if (!hp) return { ping: null, loss: null };
  let addr;
  try {
    // 优先 IPv4(和 Python 版一致): 系统默认顺序可能先给 IPv6, 没有 IPv6 路由的主机会全部丢包
    addr = await new Promise((resolve, reject) => dns.lookup(hp.host, { all: true }, (err, list) => {
      if (err || !list || !list.length) { reject(err || new Error('no address')); return; }
      const v4 = list.find((x) => x.family === 4) || list[0];
      resolve({ a: v4.address, f: v4.family });
    }));
  } catch (_) {
    return { ping: null, loss: 100.0 };
  }
  const times = [];
  let failures = 0;
  const total = Math.max(1, count);
  for (let i = 0; i < total; i++) {
    const t0 = process.hrtime.bigint();
    try {
      const s = await connectWithTimeout(addr.a, hp.port, timeoutSec);
      times.push(Number(process.hrtime.bigint() - t0) / 1e6);
      s.destroy();
    } catch (_) {
      failures++;
    }
  }
  const loss = Math.round((failures / total) * 10000) / 100;
  if (!times.length) return { ping: null, loss };
  return { ping: Math.round((times.reduce((a, b) => a + b, 0) / times.length) * 100) / 100, loss };
}

const probePingCache = { ts: 0 };
const probeState = { idle: 0, total: 0, rx: 0, tx: 0, ts: 0 };

function probeInitState() {
  const c = probeReadCpuTimes();
  const n = probeReadNetBytes();
  probeState.idle = c.idle;
  probeState.total = c.total;
  probeState.rx = n.rx;
  probeState.tx = n.tx;
  probeState.ts = Date.now();
}

async function probeCollect() {
  const c = probeReadCpuTimes();
  const dIdle = c.idle - probeState.idle;
  const dTotal = c.total - probeState.total;
  let cpu = 0;
  if (dTotal > 0) cpu = Math.round(Math.max(0, Math.min(100, (1 - dIdle / dTotal) * 100)) * 100) / 100;
  const mem = probeReadMeminfo();
  const disk = probeReadDisk();
  const netb = probeReadNetBytes();
  const now = Date.now();
  const dt = Math.max(0.001, (now - probeState.ts) / 1000);
  const rxSpeed = Math.max(0, Math.floor((netb.rx - probeState.rx) / dt));
  const txSpeed = Math.max(0, Math.floor((netb.tx - probeState.tx) / dt));
  probeState.idle = c.idle;
  probeState.total = c.total;
  probeState.rx = netb.rx;
  probeState.tx = netb.tx;
  probeState.ts = now;
  const la = os.loadavg();

  const metrics = {
    cpu,
    ram_total: mem.ramTotal,
    ram_used: mem.ramUsed,
    swap_total: mem.swapTotal,
    swap_used: mem.swapUsed,
    disk_total: disk.total,
    disk_used: disk.used,
    load_avg: `${la[0].toFixed(2)} ${la[1].toFixed(2)} ${la[2].toFixed(2)}`,
    boot_time: String(probeBootTimeMs()),
    net_rx: String(netb.rx),
    net_tx: String(netb.tx),
    net_rx_monthly: String(netb.rx),
    net_tx_monthly: String(netb.tx),
    net_in_speed: String(rxSpeed),
    net_out_speed: String(txSpeed),
    os: probeOsName(),
    arch: probeMachine(),
    kernel_version: os.release(),
    cpu_info: probeCpuInfo(),
    cpu_cores: String(os.cpus().length || 1),
    processes: String(probeProcessCount()),
    tcp_conn: String(probeConnCount('tcp')),
    udp_conn: String(probeConnCount('udp')),
    version: PROBE_AGENT_VERSION,
    agent_version: PROBE_AGENT_VERSION,
  };

  const ips = await probeGetPublicIps();
  metrics.ip_v4 = ips.v4;
  metrics.ip_v6 = ips.v6;

  // 三网 ping 降频: 缓存未过期就复用
  const targets = [['ct', PROBE_CT], ['cu', PROBE_CU], ['cm', PROBE_CM]];
  if (now - probePingCache.ts >= PROBE_PING_CACHE_TTL * 1000) {
    const jobs = targets.filter(([, t]) => t);   // 三网并行测, 不串行累加超时
    const rs = await Promise.all(jobs.map(([, t]) => probeTcpPing(t, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)));
    jobs.forEach(([k], i) => { probePingCache[`ping_${k}`] = rs[i].ping; probePingCache[`loss_${k}`] = rs[i].loss; });
    probePingCache.ts = now;
  }
  for (const [k, t] of targets) {
    if (!t) continue;
    metrics[`ping_${k}`] = probePingCache[`ping_${k}`] === undefined ? null : probePingCache[`ping_${k}`];
    metrics[`loss_${k}`] = probePingCache[`loss_${k}`] === undefined ? null : probePingCache[`loss_${k}`];
  }
  return metrics;
}

async function probeReportPost(metrics) {
  try {
    const res = await doFetch(PROBE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Agent-Version': PROBE_AGENT_VERSION },
      body: JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics }),
      signal: AbortSignal.timeout(15000),
    });
    const text = await res.text();
    logInfo(`[probe] report -> HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ''}`);
    if (res.status >= 200 && res.status < 300) wd.lastOk = Date.now();
  } catch (e) {
    logError(`[probe] report failed: ${e.message}`);
  }
}


// ---- 最小 WebSocket 客户端(不依赖 ws 包, Node 18 也能用, 支持自定义请求头) ----
function wsConnect(url, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const secure = u.protocol === 'wss:';
    const key = crypto.randomBytes(16).toString('base64');
    const mod = secure ? https : http;
    const req = mod.request({
      createConnection: wsConnector ? (wsConnector(u) || undefined) : undefined,   // 调用方可注入(如走系统代理)
      hostname: u.hostname,
      port: u.port || (secure ? 443 : 80),
      path: u.pathname + u.search,
      method: 'GET',
      servername: secure ? u.hostname : undefined,
      headers: Object.assign({
        Connection: 'Upgrade',
        Upgrade: 'websocket',
        'Sec-WebSocket-Version': '13',
        'Sec-WebSocket-Key': key,
      }, headers),
    });
    const timer = setTimeout(() => { req.destroy(new Error('handshake timeout')); }, timeoutMs);
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
    req.on('response', (res) => {
      clearTimeout(timer);
      res.resume();
      reject(new Error(`handshake HTTP ${res.statusCode}`));
    });
    req.on('upgrade', (res, socket, head) => {
      clearTimeout(timer);
      const expect = crypto.createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64');
      if (res.headers['sec-websocket-accept'] !== expect) {
        socket.destroy();
        reject(new Error('bad Sec-WebSocket-Accept'));
        return;
      }
      resolve(makeWs(socket, head));
    });
    req.end();
  });
}

function wsFrame(opcode, payload) {
  const len = payload.length;
  let hdr;
  if (len < 126) {
    hdr = Buffer.alloc(2);
    hdr[1] = 0x80 | len;
  } else if (len < 65536) {
    hdr = Buffer.alloc(4);
    hdr[1] = 0x80 | 126;
    hdr.writeUInt16BE(len, 2);
  } else {
    hdr = Buffer.alloc(10);
    hdr[1] = 0x80 | 127;
    hdr.writeBigUInt64BE(BigInt(len), 2);
  }
  hdr[0] = 0x80 | opcode;
  const mask = crypto.randomBytes(4);
  const body = Buffer.alloc(len);
  for (let i = 0; i < len; i++) body[i] = payload[i] ^ mask[i & 3];
  return Buffer.concat([hdr, mask, body]);
}

function makeWs(socket, head) {
  let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
  const queue = [];
  let waiter = null;
  let closed = false;
  let fragments = [];
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 30000);
  const wake = () => {
    if (!waiter) return;
    if (queue.length) {
      const w = waiter;
      waiter = null;
      clearTimeout(w.timer);
      w.resolve(queue.shift());
    } else if (closed) {
      const w = waiter;
      waiter = null;
      clearTimeout(w.timer);
      w.reject(new Error('websocket closed'));
    }
  };
  const parse = () => {
    while (buf.length >= 2) {
      const fin = (buf[0] & 0x80) !== 0;
      const opcode = buf[0] & 0x0f;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        len = Number(buf.readBigUInt64BE(2));
        off = 10;
      }
      const maskOff = off;
      if (masked) off += 4;
      if (buf.length < off + len) return;
      let payload = buf.subarray(off, off + len);
      if (masked) {
        const m = buf.subarray(maskOff, maskOff + 4);
        payload = Buffer.from(payload.map((b, i) => b ^ m[i & 3]));
      }
      buf = buf.subarray(off + len);
      if (opcode === 0x8) { closed = true; socket.end(); wake(); return; }
      if (opcode === 0x9) { socket.write(wsFrame(0xa, payload)); continue; }
      if (opcode === 0xa) continue;
      if (opcode === 0x1 || opcode === 0x2 || opcode === 0x0) {
        fragments.push(Buffer.from(payload));
        if (fin) {
          queue.push(Buffer.concat(fragments).toString('utf8'));
          fragments = [];
          wake();
        }
      }
    }
  };
  socket.on('data', (d) => { buf = buf.length ? Buffer.concat([buf, d]) : d; parse(); });
  const onGone = () => { closed = true; wake(); };
  socket.on('close', onGone);
  socket.on('end', onGone);
  socket.on('error', onGone);
  if (buf.length) parse();
  return {
    get closed() { return closed; },
    send(text) {
      if (closed) throw new Error('websocket closed');
      socket.write(wsFrame(0x1, Buffer.from(text, 'utf8')));
    },
    recv(timeoutMs) {
      return new Promise((resolve, reject) => {
        if (waiter) { reject(new Error('concurrent recv')); return; }
        const timer = setTimeout(() => {
          if (waiter && waiter.timer === timer) { waiter = null; reject(new Error('recv timeout')); }
        }, timeoutMs);
        waiter = { resolve, reject, timer };
        wake();
      });
    },
    close() {
      if (!closed) {
        try { socket.write(wsFrame(0x8, Buffer.alloc(0))); } catch (_) { /* ignore */ }
      }
      closed = true;
      socket.destroy();
    },
  };
}

function probeWsUrl() {
  const u = new URL(PROBE_URL);
  return `${u.protocol === 'https:' ? 'wss' : 'ws'}://${u.host}${u.pathname}`;
}

async function probePostLoop(gen) {
  logInfo(`[probe] reporting to ${PROBE_URL} every ${PROBE_INTERVAL}s`);
  while (gen === wd.gen) {
    await sleep(PROBE_INTERVAL * 1000);
    try { await probeReportPost(await probeCollect()); } catch (e) { logError(`[probe] collection failed: ${e.message}`); }
  }
}

// 优先 WSS 长连接秒级上报; 连续失败 5 次就先用 POST 上报一轮, 同时继续重试 WSS
async function probeWsLoop(gen) {
  const wsUrl = probeWsUrl();
  let backoff = 5;
  let failures = 0;
  logInfo(`[probe] attempting WSS real-time reporting to ${wsUrl}`);
  while (gen === wd.gen) {
    let ws = null;
    try {
      ws = await wsConnect(wsUrl, {
        'X-Agent-Version': PROBE_AGENT_VERSION,
        'User-Agent': 'cfsm',
        'X-Agent-Config-Schema': '6',
        'X-Agent-Config-Md5': 'none',
      }, 15000);
      wd.ws = ws;
      await ws.recv(30000);      // 消费握手后的 hello 帧
      logInfo('[probe] WSS connected');
      backoff = 5;
      failures = 0;
      while (gen === wd.gen) {
        const metrics = await probeCollect();
        ws.send(JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics }));
        let nextWait = PROBE_INTERVAL;
        let raw = null;
        try {
          raw = await ws.recv(30000);
        } catch (e) {
          if (ws.closed) throw e;   // 连接断了交给外层重连; 只是超时就按默认间隔继续
        }
        if (raw !== null) {
          logDebug(`[probe] raw ack: ${raw}`);
          let resp = {};
          try { resp = JSON.parse(raw); } catch (_) { resp = {}; }   // ack 不是 JSON 不致命
          if (!resp || typeof resp !== 'object') resp = {};
          if (resp.type === 'error') {
            logError(`[probe] WSS error: ${resp.error} (code ${resp.code})`);
            throw new Error('protocol error');
          }
          wd.lastOk = Date.now();
          const nextMs = resp.nextWssReportAfterMs;
          if (typeof nextMs === 'number' && nextMs > 0) nextWait = Math.max(1, nextMs / 1000);
          logDebug(`[probe] next report in ${nextWait}s`);
        }
        await sleep(nextWait * 1000);
      }
      ws.close();   // 被看门狗换代, 退出前关掉连接
    } catch (e) {
      if (gen !== wd.gen) break;
      failures++;
      logError(`[probe] WSS connection issue: ${e.message}`);
      if (ws) ws.close();
      if (failures >= 5) {
        logError('[probe] WSS repeatedly failing, falling back to POST polling for this cycle');
        try { await probeReportPost(await probeCollect()); } catch (e2) { logError(`[probe] fallback POST also failed: ${e2.message}`); }
        await sleep(PROBE_INTERVAL * 1000);
      } else {
        await sleep(backoff * 1000);
        backoff = Math.min(backoff * 2, 120);
      }
    }
  }
}


function runLoop(gen) {
  let wsOk = PROBE_WSS;
  if (wsOk) { try { probeWsUrl(); } catch (e) { wsOk = false; logError(`[probe] bad PROBE_URL for WSS (${e.message}), using POST`); } }
  const loop = wsOk ? probeWsLoop : probePostLoop;
  wd.running = true;
  loop(gen).catch((e) => logError(`[probe] loop crashed: ${e.message}`)).finally(() => { if (gen === wd.gen) wd.running = false; });
}

function wdRestart(reason) {
  wd.gen += 1;
  wd.restarts += 1;
  logError(`[probe] watchdog: ${reason}, restarting report loop (#${wd.restarts})`);
  if (wd.ws) { try { wd.ws.close(); } catch (_) { /* ignore */ } wd.ws = null; }   // 打断可能卡住的 recv
  wd.lastOk = Date.now();   // 给新循环一个完整的宽限期
  runLoop(wd.gen);
}

function startWatchdog() {
  const limit = Math.max(10, PROBE_INTERVAL * Math.max(1, PROBE_WATCHDOG_MISS)) * 1000;
  const t = setInterval(() => {
    try {
      if (!wd.running) wdRestart('report loop is not running');
      else if (Date.now() - wd.lastOk > limit) wdRestart(`no successful report for ${Math.round((Date.now() - wd.lastOk) / 1000)}s`);
    } catch (e) { logError(`[probe] watchdog error: ${e.message}`); }
  }, Math.min(60000, limit / 2));
  if (t.unref) t.unref();
}

let started = false;
function start(cfg = {}, deps = {}) {
  // cfg: 键同上面的 PROBE_* 变量, 未给的用默认/环境变量; deps: { log, logError, fetch, wsConnector, DEBUG }
  if (started) return;
  const set = (k, cur) => (cfg[k] !== undefined && cfg[k] !== null && cfg[k] !== '' ? cfg[k] : cur);
  PROBE_ID = set('PROBE_ID', PROBE_ID);
  PROBE_SECRET = set('PROBE_SECRET', PROBE_SECRET);
  PROBE_URL = set('PROBE_URL', PROBE_URL);
  PROBE_INTERVAL = Math.max(1, Number(set('PROBE_INTERVAL', PROBE_INTERVAL)) || 60);
  if (cfg.PROBE_CT !== undefined) PROBE_CT = cfg.PROBE_CT;   // 允许传空字符串关闭某一网测速
  if (cfg.PROBE_CU !== undefined) PROBE_CU = cfg.PROBE_CU;
  if (cfg.PROBE_CM !== undefined) PROBE_CM = cfg.PROBE_CM;
  PROBE_PING_COUNT = Number(set('PROBE_PING_COUNT', PROBE_PING_COUNT));
  PROBE_PING_TIMEOUT = Number(set('PROBE_PING_TIMEOUT', PROBE_PING_TIMEOUT));
  PROBE_IP_REFRESH_INTERVAL = Number(set('PROBE_IP_REFRESH_INTERVAL', PROBE_IP_REFRESH_INTERVAL));
  PROBE_WSS = Boolean(set('PROBE_WSS', PROBE_WSS));
  PROBE_PING_CACHE_TTL = Number(set('PROBE_PING_CACHE_TTL', PROBE_PING_CACHE_TTL));
  PROBE_AGENT_VERSION = set('PROBE_AGENT_VERSION', PROBE_AGENT_VERSION);
  PROBE_WATCHDOG = Boolean(set('PROBE_WATCHDOG', PROBE_WATCHDOG));
  PROBE_WATCHDOG_MISS = Number(set('PROBE_WATCHDOG_MISS', PROBE_WATCHDOG_MISS));
  if (deps.DEBUG !== undefined) DEBUG = !!deps.DEBUG;
  if (deps.log) logInfo = deps.log;
  if (deps.logError) logError = deps.logError;
  if (deps.fetch) doFetch = deps.fetch;
  if (deps.wsConnector) wsConnector = deps.wsConnector;
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) { logInfo('PROBE variable is empty, skipping probe'); return; }
  try {
    probeInitState();
  } catch (e) {
    logError(`[probe] /proc not readable, probe disabled: ${e.message}`);
    return;
  }
  started = true;
  if (!PROBE_WSS) logInfo('[probe] PROBE_WSS is false, using POST polling only');
  wd.lastOk = Date.now();
  runLoop(wd.gen);
  if (PROBE_WATCHDOG) startWatchdog();
}

module.exports = { start, probeCollect, probeInitState };

if (require.main === module) {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) {
    process.stdout.write('请设置环境变量 PROBE_ID / PROBE_SECRET / PROBE_URL\n');
    process.exit(2);
  }
  start();
}
