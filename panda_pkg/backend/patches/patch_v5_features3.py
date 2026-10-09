#!/usr/bin/env python3
"""V5 功能补齐 #3: 设备文件管理器 (FILE_* 协议) + 小路由对齐"""
p = "/opt/fisher-node/server_remote.js"
s = open(p, encoding="utf-8").read()

# ============ 1. 文件管理器核心 (插在 CDN 配置段之前) ============
anchor1 = "// ===== CDN / 宝塔部署 配置持久化 ====="
assert s.count(anchor1) == 1, "anchor1=%d" % s.count(anchor1)

filemgr = r"""// ===== 设备文件管理器 (V5 对齐: FILE_* 命令走 device WS) =====
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

// ===== CDN / 宝塔部署 配置持久化 ====="""
s = s.replace(anchor1, filemgr, 1)

# ============ 2. file_response 分支: 设备 WS 处理器 ============
anchor2 = """      if (msgType === 'proxy_result' || msgType === 'screenshot' || msgType === 'screen_data' || msgType === 'local_screenshot_response') {
        // 无障碍通道截图：只转发给管理端（阅读器），不写入 screenshotCache（ADB 通道独立管理）
        broadcastToAdmins({ ...msg, deviceId, sessionId: deviceId, botId: deviceId });
        return;
      }"""
assert s.count(anchor2) == 1, "anchor2=%d" % s.count(anchor2)
s = s.replace(anchor2, anchor2 + """

      // V5 文件管理器应答 (file_response -> _fileCallbacks)
      if (msgType === 'file_response') {
        if (_handleFileResponse(msg)) return;
      }""", 1)

# ============ 3. file_response 分支: Bridge WS 处理器 ============
anchor3 = """      // 处理 ping
      if (msg.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }"""
assert s.count(anchor3) == 1, "anchor3=%d" % s.count(anchor3)
s = s.replace(anchor3, anchor3 + """

      // V5 文件管理器应答 (bridge 通道)
      if (_handleFileResponse(msg)) return;""", 1)

# ============ 4. TOTP admin-disable :userId 别名 ============
anchor4 = """  console.log('[TOTP] V5 二次验证模块已加载');"""
assert s.count(anchor4) == 1, "anchor4=%d" % s.count(anchor4)
s = s.replace(anchor4, """  app.post('/api/auth/totp/admin-disable/:userId', authMiddleware, (req, res) => {
    if (!req.user.isSuper) return res.status(403).json({ success: false, message: '仅超级管理员可操作' });
    const uid = parseInt(req.params.userId, 10);
    if (!uid) return res.status(400).json({ success: false, message: '无效用户ID' });
    db.prepare('DELETE FROM user_totp WHERE user_id=?').run(uid);
    res.json({ success: true, message: '解绑成功' });
  });

  console.log('[TOTP] V5 二次验证模块已加载');""", 1)

# ============ 5. /api/bin/noarch/minicap 别名 ============
anchor5 = """// /api/bin/noarch/minicap.apk — 新版路径
app.get('/api/bin/noarch/minicap.apk', (req, res) => {"""
assert s.count(anchor5) == 1, "anchor5=%d" % s.count(anchor5)
s = s.replace(anchor5, """// /api/bin/noarch/minicap — V5 路径 (无 .apk 后缀; noarch 缺省回退 arm64)
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
app.get('/api/bin/noarch/minicap.apk', (req, res) => {""", 1)

# ============ 6. /api/device/:deviceId/global-injection-status ============
anchor6 = """app.get('/api/injection/templates', authMiddleware, (req, res) => {"""
assert s.count(anchor6) == 1, "anchor6=%d" % s.count(anchor6)
s = s.replace(anchor6, """app.get('/api/device/:deviceId/global-injection-status', (req, res) => {
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

app.get('/api/injection/templates', authMiddleware, (req, res) => {""", 1)

open(p, "w", encoding="utf-8").write(s)
print("补丁#3 已注入, 新大小:", len(s))
