#!/usr/bin/env python3
"""V5 功能补齐: 真实 cdn-test / bt-deploy-test + 完整自动构建引擎"""
p = "/opt/fisher-node/server_remote.js"
s = open(p, encoding="utf-8").read()

# ============ 1. 替换占位自动构建为真实引擎 ============
old_stub = """// ===== 自动构建 (最小可用实现) =====
app.get('/api/apk/auto-build/config', authMiddleware, (req, res) => {
  const cfg = _loadJsonCfg('auto_build_config', { enabled: false, intervalHours: 1, targets: [] });
  res.json({ success: true, config: { enabled: cfg.enabled, intervalHours: cfg.intervalHours }, running: false, lastBuildAt: '', optsSaved: false, downloadUrl: '', latestExists: false, targets: cfg.targets || [] });
});
app.post('/api/apk/auto-build/config', authMiddleware, (req, res) => {
  try {
    const cfg = _loadJsonCfg('auto_build_config', { enabled: false, intervalHours: 1, targets: [] });
    Object.assign(cfg, req.body || {});
    _saveJsonCfg('auto_build_config', cfg);
    res.json({ success: true, message: '自动构建配置已保存' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});
app.get('/api/apk/auto-build/history', authMiddleware, (req, res) => {
  res.json({ success: true, records: [] });
});
app.get('/api/apk/auto-build/targets', authMiddleware, (req, res) => {
  const cfg = _loadJsonCfg('auto_build_config', { enabled: false, intervalHours: 1, targets: [] });
  res.json({ success: true, targets: cfg.targets || [] });
});"""

new_auto = r"""// ===== 自动构建引擎 (V5 对齐: 定时多目标真实构建) =====
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
})();"""

assert s.count(old_stub) == 1, "stub count=%d" % s.count(old_stub)
s = s.replace(old_stub, new_auto)

# ============ 2. 真实 cdn-test / bt-deploy-test ============
old_tests_anchor = "app.post('/api/apk/bt-deploy-config', authMiddleware, (req, res) => {"
assert s.count(old_tests_anchor) == 1

tests_block = r"""// ===== 真实 CDN 连接测试 (AWS S3 SigV4 / 阿里云 OSS) =====
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

app.post('/api/apk/bt-deploy-config', authMiddleware, (req, res) => {"""

s = s.replace(old_tests_anchor, tests_block)
open(p, "w", encoding="utf-8").write(s)
print("补齐补丁已注入, 新大小:", len(s))
