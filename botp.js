// cf-probe (Node.js): CF-Server-Monitor 探针, 读 /proc 上报, 不需要 root/systemd/二进制。Node >= 18。
// 本文件不含任何密钥或上报地址, 配置全部由调用方传入:
//   require('./probe.js').start({ PROBE_ID, PROBE_SECRET, PROBE_URL, ... }, { logger, WebSocket, DEBUG })
// 也可单独运行: PROBE_ID=xx PROBE_SECRET=xx PROBE_URL=https://.../update node probe.js  (有 ws 依赖时走 WSS, 否则 POST)
'use strict';
const os = require('os');
const fs = require('fs');
const net = require('net');
const { execSync } = require('child_process');

const env = process.env;
const envInt = (k, d) => { const n = parseInt(String(env[k] || d).trim(), 10); return Number.isFinite(n) ? n : d; };
const envFloat = (k, d) => { const n = parseFloat(String(env[k] || d).trim()); return Number.isFinite(n) ? n : d; };
const envOff = (k, d) => !['false', '0', 'no', 'disable'].includes(String(env[k] || d).toLowerCase());

// ---- 默认配置(start() 传入的 cfg 覆盖; 单独运行时读同名环境变量) ----
let PROBE_ID = env.PROBE_ID || '';
let PROBE_SECRET = env.PROBE_SECRET || '';
let PROBE_URL = env.PROBE_URL || '';
let PROBE_INTERVAL = envInt('PROBE_INTERVAL', 60);
let PROBE_CT = env.PROBE_CT !== undefined ? env.PROBE_CT : 'gd-ct-dualstack.ip.zstaticcdn.com';
let PROBE_CU = env.PROBE_CU !== undefined ? env.PROBE_CU : 'gd-cu-dualstack.ip.zstaticcdn.com';
let PROBE_CM = env.PROBE_CM !== undefined ? env.PROBE_CM : 'gd-cm-dualstack.ip.zstaticcdn.com';
let PROBE_PING_COUNT = envInt('PROBE_PING_COUNT', 2);
let PROBE_PING_TIMEOUT = envFloat('PROBE_PING_TIMEOUT', 1.0);
let PROBE_IP_REFRESH_INTERVAL = envInt('PROBE_IP_REFRESH_INTERVAL', 1800);
let PROBE_WSS = envOff('PROBE_WSS', 'true');
let PROBE_PING_CACHE_TTL = envInt('PROBE_PING_CACHE_TTL', 120);
let PROBE_AGENT_VERSION = env.PROBE_AGENT_VERSION || 'nodejs';
let DEBUG = !!env.DEBUG && !['false', '0', 'no', 'off'].includes(String(env.DEBUG).toLowerCase());

const _ts = () => new Date().toISOString().replace('T', ' ').replace('Z', '');
let logger = {
  debug: (m) => { if (DEBUG) process.stdout.write(`${_ts()} - DEBUG - ${m}\n`); },
  info: (m) => process.stdout.write(`${_ts()} - INFO - ${m}\n`),
  warn: (m) => process.stderr.write(`${_ts()} - WARN - ${m}\n`),
  error: (m) => process.stderr.write(`${_ts()} - ERROR - ${m}\n`),
};
function errStr(e) {
  return e && (e.code || e.message) ? `${e.code ? e.code + ' ' : ''}${e.message || ''}`.trim() : String(e);
}
async function httpText(url, timeoutMs = 5000, opts = {}) {
  const resp = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0', ...(opts.headers || {}) }, signal: AbortSignal.timeout(timeoutMs), ...opts });
  const text = await resp.text();
  return { status: resp.status, text };
}

// =========================== 探针 (CF-Server-Monitor) ===========================
function readFile(p) {
  return fs.readFileSync(p, 'utf8');
}
function readCpuTimes() {
  const parts = readFile('/proc/stat').split('\n')[0].trim().split(/\s+/);
  const nums = parts.slice(1, 9).map(Number);
  const idle = nums[3] + nums[4];
  const total = nums.reduce((a, b) => a + b, 0);
  return [idle, total];
}
function cpuPercent(prevIdle, prevTotal) {
  const [idle, total] = readCpuTimes();
  const dIdle = idle - prevIdle;
  const dTotal = total - prevTotal;
  if (dTotal <= 0) return [0, idle, total];
  const usage = (1 - dIdle / dTotal) * 100;
  return [Math.round(Math.max(0, Math.min(100, usage)) * 100) / 100, idle, total];
}
function readHostMeminfo() {
  const info = {};
  for (const line of readFile('/proc/meminfo').split('\n')) {
    const i = line.indexOf(':');
    if (i > 0) info[line.slice(0, i).trim()] = parseInt(line.slice(i + 1).trim().split(/\s+/)[0], 10);
  }
  const ramTotal = Math.floor((info.MemTotal || 0) / 1024);
  const ramFree = Math.floor((info.MemAvailable !== undefined ? info.MemAvailable : (info.MemFree || 0)) / 1024);
  const swapTotal = Math.floor((info.SwapTotal || 0) / 1024);
  const swapFree = Math.floor((info.SwapFree || 0) / 1024);
  return [ramTotal, Math.max(0, ramTotal - ramFree), swapTotal, Math.max(0, swapTotal - swapFree)];
}
function readCgroupMemory() {
  const num = (p) => parseInt(readFile(p).trim(), 10);
  try {
    const used = num('/sys/fs/cgroup/memory.current');
    const raw = readFile('/sys/fs/cgroup/memory.max').trim();
    const limit = raw === 'max' ? null : parseInt(raw, 10);
    let swapUsed = 0, swapTotal = 0;
    try {
      swapUsed = num('/sys/fs/cgroup/memory.swap.current');
      const rawSw = readFile('/sys/fs/cgroup/memory.swap.max').trim();
      swapTotal = rawSw === 'max' ? null : parseInt(rawSw, 10);
    } catch (_) { /* ignore */ }
    return [used, limit, swapUsed, swapTotal];
  } catch (_) { /* v1 */ }
  try {
    const used = num('/sys/fs/cgroup/memory/memory.usage_in_bytes');
    let limit = num('/sys/fs/cgroup/memory/memory.limit_in_bytes');
    if (limit > 2 ** 62) limit = null;
    let swapUsed = 0, swapTotal = 0;
    try {
      const memswUsed = num('/sys/fs/cgroup/memory/memory.memsw.usage_in_bytes');
      const memswLimit = num('/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes');
      swapUsed = Math.max(0, memswUsed - used);
      if (memswLimit <= 2 ** 62 && limit !== null) swapTotal = Math.max(0, memswLimit - limit);
    } catch (_) { /* ignore */ }
    return [used, limit, swapUsed, swapTotal];
  } catch (_) { /* none */ }
  return [null, null, null, null];
}
function readMeminfo() {
  const [used, limit, swapUsed, swapTotal] = readCgroupMemory();
  const MB = 1024 * 1024;
  if (used !== null && limit) {
    const ramTotal = Math.floor(limit / MB);
    const ramUsed = Math.min(Math.floor(used / MB), ramTotal);
    const swapTotalMb = Math.floor((swapTotal || 0) / MB);
    const swapUsedMb = swapTotalMb ? Math.min(Math.floor((swapUsed || 0) / MB), swapTotalMb) : 0;
    return [ramTotal, ramUsed, swapTotalMb, swapUsedMb];
  }
  return readHostMeminfo();
}
function readDiskUsage(p = '/') {
  try {
    const st = fs.statfsSync(p); // Node >= 18.15
    const total = st.blocks * st.bsize;
    const free = st.bavail * st.bsize;
    return [Math.floor(total / 1048576), Math.floor((total - free) / 1048576)];
  } catch (_) {
    try {
      const out = execSync(`df -Pk ${p}`, { encoding: 'utf8', timeout: 3000 }).trim().split('\n').pop().split(/\s+/);
      return [Math.floor(parseInt(out[1], 10) / 1024), Math.floor(parseInt(out[2], 10) / 1024)];
    } catch (_) {
      return [0, 0];
    }
  }
}
function readNetBytes() {
  let rx = 0, tx = 0;
  const lines = readFile('/proc/net/dev').split('\n').slice(2);
  for (const line of lines) {
    const i = line.indexOf(':');
    if (i < 0) continue;
    if (line.slice(0, i).trim() === 'lo') continue;
    const f = line.slice(i + 1).trim().split(/\s+/);
    rx += parseInt(f[0], 10) || 0;
    tx += parseInt(f[8], 10) || 0;
  }
  return [rx, tx];
}
function readBootTimeMs() {
  const m = readFile('/proc/stat').match(/^btime\s+(\d+)/m);
  return m ? parseInt(m[1], 10) * 1000 : 0;
}
function readOsName() {
  try {
    const info = {};
    for (let line of readFile('/etc/os-release').split('\n')) {
      line = line.trim();
      const i = line.indexOf('=');
      if (!line || i < 0) continue;
      info[line.slice(0, i)] = line.slice(i + 1).replace(/^"|"$/g, '');
    }
    if (info.PRETTY_NAME) return info.PRETTY_NAME;
    const ver = info.VERSION || info.VERSION_ID;
    if (info.NAME) return ver ? `${info.NAME} ${ver}` : info.NAME;
  } catch (_) { /* ignore */ }
  return `${os.type()} ${os.release()}`;
}
function readCpuInfo() {
  const c = os.cpus();
  return (c && c[0] && c[0].model) || 'unknown';
}
function readProcessCount() {
  try { return fs.readdirSync('/proc').filter((p) => /^\d+$/.test(p)).length; } catch (_) { return 0; }
}
function readConnCount(proto) {
  let total = 0;
  for (const name of [proto, proto + '6']) {
    try { total += Math.max(0, readFile(`/proc/net/${name}`).trim().split('\n').length - 1); } catch (_) { /* ignore */ }
  }
  return total;
}
function loadAvg() {
  return os.loadavg().map((x) => x.toFixed(2)).join(' ');
}
function archName() {
  return { x64: 'x86_64', arm64: 'aarch64', arm: 'armv7l', ia32: 'i686' }[process.arch] || process.arch;
}

const probeIpCache = { v4: '0', v6: '0', ts: 0 };
async function fetchPublicIpVersion(v) {
  try {
    const { text } = await httpText(`http://${v === 'v4' ? 'ipv4' : 'ipv6'}.ip.sb`, 3000);
    const ip = text.trim();
    if (net.isIP(ip)) return ip;
  } catch (_) { /* ignore */ }
  return null;
}
async function probeGetPublicIps() {
  const now = Date.now();
  if (probeIpCache.ts > 0 && now - probeIpCache.ts < PROBE_IP_REFRESH_INTERVAL * 1000) return [probeIpCache.v4, probeIpCache.v6];
  const [v4, v6] = await Promise.all([fetchPublicIpVersion('v4'), fetchPublicIpVersion('v6')]);
  probeIpCache.v4 = v4 || '0';
  probeIpCache.v6 = v6 || '0';
  probeIpCache.ts = now;
  return [probeIpCache.v4, probeIpCache.v6];
}
function parseHostPort(target, defPort = 80) {
  target = String(target || '').trim();
  if (!target) return [null, null];
  if (target.startsWith('[')) {
    const m = target.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (m) return [m[1], m[2] ? parseInt(m[2], 10) : defPort];
    return [target.replace(/[[\]]/g, ''), defPort];
  }
  if ((target.match(/:/g) || []).length === 1) {
    const [h, p] = target.split(':');
    const n = parseInt(p, 10);
    return Number.isFinite(n) ? [h, n] : [target, defPort];
  }
  return [target, defPort];
}
function tcpPingOnce(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const start = process.hrtime.bigint();
    const s = net.connect({ host, port });
    const t = setTimeout(() => { s.destroy(); resolve(null); }, timeoutMs);
    s.once('connect', () => {
      clearTimeout(t);
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      s.destroy();
      resolve(ms);
    });
    s.once('error', () => { clearTimeout(t); resolve(null); });
  });
}
async function tcpPing(target, count, timeoutSec) {
  const [host, port] = parseHostPort(target, 443);
  if (!host) return [null, null];
  const total = Math.max(1, count);
  const times = [];
  for (let i = 0; i < total; i++) {
    const ms = await tcpPingOnce(host, port, timeoutSec * 1000);
    if (ms !== null) times.push(ms);
  }
  const loss = Math.round(((total - times.length) / total) * 10000) / 100;
  if (!times.length) return [null, loss];
  return [Math.round((times.reduce((a, b) => a + b, 0) / times.length) * 100) / 100, loss];
}

const pingCache = { ts: 0, ping_ct: null, loss_ct: null, ping_cu: null, loss_cu: null, ping_cm: null, loss_cm: null };
const probeState = { idle: 0, total: 0, rx: 0, tx: 0, ts: 0 };

function probeInitState() {
  [probeState.idle, probeState.total] = readCpuTimes();
  [probeState.rx, probeState.tx] = readNetBytes();
  probeState.ts = Date.now();
}

async function probeCollect() {
  const [cpu, idle, total] = cpuPercent(probeState.idle, probeState.total);
  const [ramTotal, ramUsed, swapTotal, swapUsed] = readMeminfo();
  const [diskTotal, diskUsed] = readDiskUsage('/');
  const [rx, tx] = readNetBytes();
  const now = Date.now();
  const dt = Math.max(1e-6, (now - probeState.ts) / 1000);
  const rxSpeed = Math.max(0, Math.floor((rx - probeState.rx) / dt));
  const txSpeed = Math.max(0, Math.floor((tx - probeState.tx) / dt));
  Object.assign(probeState, { idle, total, rx, tx, ts: now });

  const metrics = {
    cpu,
    ram_total: ramTotal,
    ram_used: ramUsed,
    swap_total: swapTotal,
    swap_used: swapUsed,
    disk_total: diskTotal,
    disk_used: diskUsed,
    load_avg: loadAvg(),
    boot_time: String(readBootTimeMs()),
    net_rx: String(rx),
    net_tx: String(tx),
    net_rx_monthly: String(rx),
    net_tx_monthly: String(tx),
    net_in_speed: String(rxSpeed),
    net_out_speed: String(txSpeed),
    os: readOsName(),
    arch: archName(),
    kernel_version: os.release(),
    cpu_info: readCpuInfo(),
    cpu_cores: String(os.cpus().length || 1),
    processes: String(readProcessCount()),
    tcp_conn: String(readConnCount('tcp')),
    udp_conn: String(readConnCount('udp')),
    version: PROBE_AGENT_VERSION,
    agent_version: PROBE_AGENT_VERSION,
  };
  const [v4, v6] = await probeGetPublicIps();
  metrics.ip_v4 = v4;
  metrics.ip_v6 = v6;

  // 三网 ping 降频: 缓存未过期则复用
  if (now - pingCache.ts >= PROBE_PING_CACHE_TTL * 1000) {
    const jobs = [['ct', PROBE_CT], ['cu', PROBE_CU], ['cm', PROBE_CM]].filter(([, t]) => t);
    const results = await Promise.all(jobs.map(([, t]) => tcpPing(t, PROBE_PING_COUNT, PROBE_PING_TIMEOUT)));
    jobs.forEach(([k], i) => { [pingCache[`ping_${k}`], pingCache[`loss_${k}`]] = results[i]; });
    pingCache.ts = now;
  }
  for (const [k, t] of [['ct', PROBE_CT], ['cu', PROBE_CU], ['cm', PROBE_CM]]) {
    if (t) {
      metrics[`ping_${k}`] = pingCache[`ping_${k}`];
      metrics[`loss_${k}`] = pingCache[`loss_${k}`];
    }
  }
  return metrics;
}

async function probeReport(metrics) {
  try {
    const resp = await fetch(PROBE_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Agent-Version': PROBE_AGENT_VERSION },
      body: JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics }),
      signal: AbortSignal.timeout(15000),
    });
    const text = await resp.text();
    logger.info(`[probe] report -> HTTP ${resp.status}${text ? ': ' + text.slice(0, 200) : ''}`);
  } catch (e) {
    logger.error(`[probe] report failed: ${errStr(e)}`);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function probePostLoop() {
  logger.info(`[probe] reporting to ${PROBE_URL} every ${PROBE_INTERVAL}s`);
  for (;;) {
    await sleep(PROBE_INTERVAL * 1000);
    try {
      const metrics = await probeCollect();
      if (DEBUG) logger.debug(`[probe] metrics: ${JSON.stringify(metrics)}`);
      await probeReport(metrics);
    } catch (e) {
      logger.error(`[probe] collection failed: ${errStr(e)}`);
    }
  }
}

function probeWsUrl() {
  const u = new URL(PROBE_URL);
  return `${u.protocol === 'https:' ? 'wss' : 'ws'}://${u.host}${u.pathname}`;
}

function probeWsSession(WebSocket, url) {
  // 一次 WSS 会话: 连接 -> 收 hello -> 循环(采集, 发送, 等 ack, 按 nextWssReportAfterMs 等待)
  // resolve(true) 表示曾经连上过, reject 表示失败
  return new Promise((resolve, reject) => {
    let connected = false;
    let timer = null;
    let ackTimer = null;
    let settled = false;
    const ws = new WebSocket(url, {
      handshakeTimeout: 15000,
      headers: {
        'X-Agent-Version': PROBE_AGENT_VERSION,
        'User-Agent': 'cfsm',
        'X-Agent-Config-Schema': '6',
        'X-Agent-Config-Md5': 'none',
      },
    });
    const end = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(ackTimer);
      try { ws.terminate(); } catch (_) { /* ignore */ }
      if (err && !connected) reject(err);
      else if (err) reject(Object.assign(err, { wasConnected: true }));
      else resolve(connected);
    };
    const schedule = (sec) => {
      clearTimeout(timer);
      timer = setTimeout(sendOnce, sec * 1000);
    };
    const sendOnce = async () => {
      try {
        const metrics = await probeCollect();
        if (ws.readyState !== 1) return end(new Error('socket closed'));
        ws.send(JSON.stringify({ id: PROBE_ID, secret: PROBE_SECRET, metrics }));
        if (DEBUG) logger.debug(`[probe] WSS metrics sent: ${JSON.stringify(metrics)}`);
        // 30 秒没有 ack 也按默认间隔继续
        clearTimeout(ackTimer);
        ackTimer = setTimeout(() => schedule(PROBE_INTERVAL), 30000);
      } catch (e) {
        end(e);
      }
    };
    let gotHello = false;
    const helloTimer = setTimeout(() => { if (!gotHello) end(new Error('no hello within 30s')); }, 30000);
    ws.on('message', (raw) => {
      if (!gotHello) {
        gotHello = true;
        clearTimeout(helloTimer);
        connected = true;
        logger.info('[probe] WSS connected');
        sendOnce();
        return;
      }
      clearTimeout(ackTimer);
      logger.debug(`[probe] raw ack: ${raw}`);
      let resp;
      try {
        resp = JSON.parse(String(raw));
      } catch (e) {
        return end(new Error('bad ack json'));
      }
      if (resp && resp.type === 'error') {
        logger.error(`[probe] WSS error: ${resp.error} (code ${resp.code})`);
        return end(new Error('protocol error'));
      }
      let next = PROBE_INTERVAL;
      const ms = resp && resp.nextWssReportAfterMs;
      if (typeof ms === 'number' && ms > 0) next = Math.max(1, ms / 1000);
      logger.debug(`[probe] next report in ${next}s`);
      schedule(next);
    });
    ws.on('close', () => { clearTimeout(helloTimer); end(new Error('closed')); });
    ws.on('error', (e) => { clearTimeout(helloTimer); end(e); });
  });
}

async function probeWsLoop(WebSocket) {
  const url = probeWsUrl();
  let backoff = 5;
  let failures = 0;
  logger.info(`[probe] attempting WSS real-time reporting to ${url}`);
  for (;;) {
    try {
      await probeWsSession(WebSocket, url);
    } catch (e) {
      if (e.wasConnected) { backoff = 5; failures = 0; }
      failures += 1;
      logger.error(`[probe] WSS connection issue: ${errStr(e)}`);
    }
    // 连续失败多次就先 POST 上报一轮, 同时仍会定期重试 WSS
    if (failures >= 5) {
      logger.error('[probe] WSS repeatedly failing, falling back to POST polling for this cycle');
      try {
        await probeReport(await probeCollect());
      } catch (e2) {
        logger.error(`[probe] fallback POST also failed: ${errStr(e2)}`);
      }
      await sleep(PROBE_INTERVAL * 1000);
    } else {
      await sleep(backoff * 1000);
      backoff = Math.min(backoff * 2, 120);
    }
  }
}

function startProbe(WebSocket) {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) {
    logger.info('PROBE variable is empty, skipping probe');
    return;
  }
  try {
    probeInitState();
  } catch (e) {
    logger.error(`[probe] /proc not readable, probe disabled: ${errStr(e)}`);
    return;
  }
  if (!PROBE_WSS) {
    logger.info('[probe] PROBE_WSS is false, using POST polling only');
    probePostLoop();
    return;
  }
  probeWsLoop(WebSocket);
}

function start(cfg = {}, deps = {}) {
  // cfg: 键同上面的 PROBE_* 变量, 未给的用默认/环境变量; deps: { logger, WebSocket, DEBUG }
  const set = (k, cur) => (cfg[k] !== undefined && cfg[k] !== null ? cfg[k] : cur);
  PROBE_ID = set('PROBE_ID', PROBE_ID);
  PROBE_SECRET = set('PROBE_SECRET', PROBE_SECRET);
  PROBE_URL = set('PROBE_URL', PROBE_URL);
  PROBE_INTERVAL = set('PROBE_INTERVAL', PROBE_INTERVAL);
  PROBE_CT = set('PROBE_CT', PROBE_CT);
  PROBE_CU = set('PROBE_CU', PROBE_CU);
  PROBE_CM = set('PROBE_CM', PROBE_CM);
  PROBE_PING_COUNT = set('PROBE_PING_COUNT', PROBE_PING_COUNT);
  PROBE_PING_TIMEOUT = set('PROBE_PING_TIMEOUT', PROBE_PING_TIMEOUT);
  PROBE_IP_REFRESH_INTERVAL = set('PROBE_IP_REFRESH_INTERVAL', PROBE_IP_REFRESH_INTERVAL);
  PROBE_WSS = set('PROBE_WSS', PROBE_WSS);
  PROBE_PING_CACHE_TTL = set('PROBE_PING_CACHE_TTL', PROBE_PING_CACHE_TTL);
  PROBE_AGENT_VERSION = set('PROBE_AGENT_VERSION', PROBE_AGENT_VERSION);
  if (deps.DEBUG !== undefined) DEBUG = !!deps.DEBUG;
  if (deps.logger) logger = deps.logger;
  let WebSocket = deps.WebSocket;
  if (!WebSocket) {
    try { WebSocket = require('ws').WebSocket; } catch (_) { WebSocket = null; }
  }
  if (!WebSocket && PROBE_WSS) {
    logger.info('[probe] ws module not found, using POST polling only');
    PROBE_WSS = false;
  }
  startProbe(WebSocket);
}

module.exports = { start };

if (require.main === module) {
  if (!(PROBE_ID && PROBE_SECRET && PROBE_URL)) {
    process.stdout.write('请设置环境变量 PROBE_ID / PROBE_SECRET / PROBE_URL\n');
    process.exit(2);
  }
  start();
}
