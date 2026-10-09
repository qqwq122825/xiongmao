#!/usr/bin/env node
// ============================================================
// 熊猫工坊V5 复现面板 — 用户管理工具 (直接操作 SQLite)
// 支持: list / add / del / passwd / role / super / maxdev /
//       totp-off / unlock / assigned
// 运行方式 (在部署服务器上):
//   NODE_PATH=/opt/fisher-node/node_modules node user_mgmt.js <命令> [参数...]
// 与面板后端可同时运行 (SQLite WAL + busy timeout)。
// ============================================================
const Database = require('better-sqlite3');

const DB_PATH = process.env.FISHER_DB || '/opt/fisher-node/data/fisher.db';
const db = new Database(DB_PATH, { timeout: 5000 });
const bcrypt = require('bcryptjs');

function getUser(username) {
  return db.prepare('SELECT * FROM users WHERE username=?').get(username);
}
function superCount() {
  return db.prepare('SELECT COUNT(*) c FROM users WHERE is_super=1').get().c;
}
function guardSoleSuper(username, action) {
  const u = getUser(username);
  if (!u) return `用户 ${username} 不存在`;
  if (u.is_super === 1 && superCount() <= 1) {
    return `✋ 拒绝：${username} 是唯一的超级管理员，禁止${action}（防锁死面板）`;
  }
  return null;
}
function assignedCount(s) {
  if (!s) return 0;
  let arr = null;
  try { const j = JSON.parse(s); if (Array.isArray(j)) arr = j; } catch (e) {}
  if (arr) return arr.length;
  return s.split(',').filter(x => x.trim()).length;
}
function fmtTime(t) {
  if (!t) return '—';
  return new Date(t * 1000).toLocaleString('zh-CN', { hour12: false });
}
function list(json) {
  const rows = db.prepare('SELECT id, username, role, is_super, max_devices, created_at, assigned_devices, active_session, login_fail_count, locked_until, totp_enabled FROM users ORDER BY id').all();
  if (json) { console.log(JSON.stringify(rows, null, 2)); return; }
  console.log(`共 ${rows.length} 个账户\n`);
  console.log('ID   用户名              角色     超管  设备配额  分配设备  登录失败  锁定     TOTP  在线会话  创建时间');
  console.log('─'.repeat(115));
  for (const r of rows) {
    const locked = r.locked_until && r.locked_until * 1000 > Date.now() ? '锁定中' : '—';
    const online = r.active_session ? '有' : '—';
    console.log(
      String(r.id).padEnd(5) +
      (r.username || '').padEnd(20) +
      (r.role || 'user').padEnd(7) +
      (r.is_super ? '是' : '否').padEnd(6) +
      String(r.max_devices ?? 0).padEnd(9) +
      String(assignedCount(r.assigned_devices)).padEnd(10) +
      String(r.login_fail_count ?? 0).padEnd(9) +
      locked.padEnd(8) +
      (r.totp_enabled ? '开' : '关').padEnd(6) +
      online.padEnd(9) +
      fmtTime(r.created_at)
    );
  }
}
function show(username) {
  const u = getUser(username);
  if (!u) { console.log(`✗ 用户 ${username} 不存在`); process.exit(1); }
  console.log('用户名:     ' + u.username);
  console.log('ID:         ' + u.id);
  console.log('角色:       ' + u.role + (u.is_super ? ' (超管)' : ''));
  console.log('设备配额:   ' + u.max_devices);
  console.log('分配设备:   ' + (u.assigned_devices || '(无)'));
  console.log('TOTP:       ' + (u.totp_enabled ? '已开启' : '未开启'));
  console.log('登录失败:   ' + u.login_fail_count + ' 次' + (u.locked_until && u.locked_until * 1000 > Date.now() ? ' (锁定中)' : ''));
  console.log('在线会话:   ' + (u.active_session ? u.active_session : '(无)'));
  console.log('创建时间:   ' + fmtTime(u.created_at));
}

const [cmd, ...args] = process.argv.slice(2);
const flags = {};
const pos = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--super') flags.super = true;
  else if (a === '--user') flags.role = 'user';
  else if (a === '--role') { flags.role = args[++i]; }
  else if (a === '--json') flags.json = true;
  else if (a.startsWith('--max-devices=')) flags.max = parseInt(a.split('=')[1], 10);
  else pos.push(a);
}

switch (cmd) {
  case 'list': list(!!flags.json); break;

  case 'show': {
    if (!pos[0]) { console.log('用法: show <用户名>'); process.exit(1); }
    show(pos[0]); break;
  }

  case 'add': {
    const [username, password] = pos;
    if (!username || !password) { console.log('用法: add <用户名> <密码> [--role admin|user] [--super] [--max-devices=N]'); process.exit(1); }
    if (!/^[A-Za-z0-9_\-\u4e00-\u9fa5]{2,32}$/.test(username)) { console.log('✗ 用户名须为 2-32 位字母/数字/下划线/中文'); process.exit(1); }
    if (password.length < 6) { console.log('✗ 密码至少 6 位'); process.exit(1); }
    if (getUser(username)) { console.log('✗ 用户名已存在: ' + username); process.exit(1); }
    const role = flags.role || 'user';
    if (!['admin', 'user'].includes(role)) { console.log('✗ 角色只能是 admin 或 user'); process.exit(1); }
    const isSuper = flags.super ? 1 : 0;
    const maxDev = flags.max || (isSuper ? 999 : 100);
    db.prepare(`INSERT INTO users (username,password_hash,role,is_super,max_devices,created_at,assigned_devices,active_session,login_fail_count,locked_until,totp_secret,totp_enabled)
      VALUES (?,?,?,?,?,?,?,NULL,0,0,'',0)`)
      .run(username, bcrypt.hashSync(password, 10), role, isSuper, maxDev, Math.floor(Date.now() / 1000), '[]');
    console.log(`✅ 已创建: ${username}  角色=${role} 超管=${isSuper ? '是' : '否'} 配额=${maxDev}`);
    break;
  }

  case 'del': {
    const username = pos[0];
    if (!username) { console.log('用法: del <用户名>'); process.exit(1); }
    const g = guardSoleSuper(username, '删除');
    if (g) { console.log(g); process.exit(1); }
    const r = db.prepare('DELETE FROM users WHERE username=?').run(username);
    console.log(r.changes ? `✅ 已删除: ${username}` : `✗ 用户不存在: ${username}`);
    break;
  }

  case 'passwd': {
    const [username, password] = pos;
    if (!username || !password) { console.log('用法: passwd <用户名> <新密码>'); process.exit(1); }
    if (password.length < 6) { console.log('✗ 密码至少 6 位'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    db.prepare('UPDATE users SET password_hash=?, active_session=NULL WHERE username=?').run(bcrypt.hashSync(password, 10), username);
    console.log(`✅ 已修改 ${username} 的密码 (其旧会话已全部踢下线)`);
    break;
  }

  case 'role': {
    const [username, role] = pos;
    if (!username || !['admin', 'user'].includes(role)) { console.log('用法: role <用户名> admin|user'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    db.prepare('UPDATE users SET role=? WHERE username=?').run(role, username);
    console.log(`✅ ${username} 的角色已改为 ${role}`);
    break;
  }

  case 'super': {
    const [username, onoff] = pos;
    if (!username || !['on', 'off'].includes(onoff)) { console.log('用法: super <用户名> on|off'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    if (onoff === 'off') {
      const g = guardSoleSuper(username, '降级');
      if (g) { console.log(g); process.exit(1); }
      db.prepare('UPDATE users SET is_super=0 WHERE username=?').run(username);
      console.log(`✅ ${username} 已降为普通管理员`);
    } else {
      db.prepare('UPDATE users SET is_super=1 WHERE username=?').run(username);
      console.log(`✅ ${username} 已升为超管`);
    }
    break;
  }

  case 'maxdev': {
    const [username, n] = pos;
    if (!username || !/^\d+$/.test(n || '')) { console.log('用法: maxdev <用户名> <配额>'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    db.prepare('UPDATE users SET max_devices=? WHERE username=?').run(parseInt(n, 10), username);
    console.log(`✅ ${username} 设备配额已设为 ${n}`);
    break;
  }

  case 'totp-off': {
    const username = pos[0];
    if (!username) { console.log('用法: totp-off <用户名>   (强制解绑二次验证)'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    db.prepare("UPDATE users SET totp_enabled=0, totp_secret='' WHERE username=?").run(username);
    db.prepare('DELETE FROM user_totp WHERE user_id=(SELECT id FROM users WHERE username=?)').run(username);
    console.log(`✅ 已解绑 ${username} 的 TOTP`);
    break;
  }

  case 'unlock': {
    const username = pos[0];
    if (!username) { console.log('用法: unlock <用户名>   (清除登录失败计数与锁定)'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    db.prepare('UPDATE users SET login_fail_count=0, locked_until=0 WHERE username=?').run(username);
    console.log(`✅ 已解锁 ${username}`);
    break;
  }

  case 'assigned': {
    const [username, devices] = pos;
    if (!username) { console.log('用法: assigned <用户名>            — 查看分配的设备'); console.log('      assigned <用户名> <id1,id2>  — 设置分配的设备(逗号分隔)'); process.exit(1); }
    if (!getUser(username)) { console.log('✗ 用户不存在: ' + username); process.exit(1); }
    if (devices === undefined) {
      const u = getUser(username);
      console.log(`${username} 分配的设备: ${u.assigned_devices || '(无)'}`);
    } else {
      const arr = devices.split(',').map(s => s.trim()).filter(Boolean);
      db.prepare('UPDATE users SET assigned_devices=? WHERE username=?').run(JSON.stringify(arr), username);
      console.log(`✅ ${username} 已分配 ${arr.length} 台设备`);
    }
    break;
  }

  default:
    console.log(`
熊猫工坊V5 复现面板 — 用户管理工具

用法:  NODE_PATH=/opt/fisher-node/node_modules node user_mgmt.js <命令> [参数]

  list                                  列出全部账户 (加 --json 输出机器可读)
  show  <用户名>                        查看单个账户详情
  add   <用户名> <密码> [选项]          创建账户
           --role admin|user (默认 user)   --super (超管)   --max-devices=N (默认 超管999/普通100)
  del   <用户名>                        删除账户 (拒绝删除唯一超管)
  passwd <用户名> <新密码>              重置密码 (同时踢掉该用户所有在线会话)
  role  <用户名> admin|user             修改角色
  super <用户名> on|off                 升/降超管 (拒绝降级唯一超管)
  maxdev <用户名> <配额>                修改设备配额
  totp-off <用户名>                     强制解绑 TOTP 二次验证
  unlock <用户名>                       解除登录锁定 (清失败计数)
  assigned <用户名> [设备id,id,...]     查看/设置该用户分配的设备

环境变量: FISHER_DB 可指定库路径 (默认 /opt/fisher-node/data/fisher.db)
`);
}

db.close();
