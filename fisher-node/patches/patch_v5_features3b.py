#!/usr/bin/env python3
"""补丁#3b: file/list 两处旧 handler 改为 WS FILE_LIST 优先 + 隧道兜底"""
p = "/opt/fisher-node/server_remote.js"
s = open(p, encoding="utf-8").read()

old_list = """app.get('/api/file/list', authMiddleware, (req, res) => {
  const deviceId = req.query.deviceId || '';
  let dirPath = req.query.path || '/sdcard';
  // 确保路径末尾有斜杠（避免符号链接问题）
  if (!dirPath.endsWith('/')) dirPath += '/';
  const http = require('http');
  const cmd = encodeURIComponent(`ls -la "${dirPath}"`);
  http.get(`http://127.0.0.1:${getDevicePort(deviceId)}/shell?cmd=${cmd}`, { timeout: 10000 }, (proxyRes) => {
    const chunks = [];
    proxyRes.on('data', c => chunks.push(c));
    proxyRes.on('end', () => {
      try {
        const data = JSON.parse(Buffer.concat(chunks).toString());
        const output = data.data?.output || '';
        const files = output.split('\\n').filter(l => l.trim() && !l.startsWith('total')).map(line => {
          const parts = line.trim().split(/\\s+/);
          if (parts.length < 7) return null;
          const perms = parts[0] || '';
          const isDir = perms.startsWith('d');
          const size = parseInt(parts[4]) || 0;
          const dateStr = `${parts[5]} ${parts[6]}`;
          const name = parts.slice(7).join(' ').replace(/ ->.*$/, '');
          if (!name || name === '.' || name === '..') return null;
          const cleanPath = dirPath.replace(/\\/+$/, '');
          return { name, isDirectory: isDir, size, permissions: perms, path: `${cleanPath}/${name}`, modifiedAt: dateStr };
        }).filter(Boolean);
        res.json({ success: true, files: files });
      } catch {
        res.json({ success: true, files: [] });
      }
    });"""

new_list = """app.get('/api/file/list', authMiddleware, (req, res) => {
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
          const files = output.split('\\n').filter(l => l.trim() && !l.startsWith('total')).map(line => {
            const parts = line.trim().split(/\\s+/);
            if (parts.length < 7) return null;
            const perms = parts[0] || '';
            const isDir = perms.startsWith('d');
            const size = parseInt(parts[4]) || 0;
            const dateStr = `${parts[5]} ${parts[6]}`;
            const name = parts.slice(7).join(' ').replace(/ ->.*$/, '');
            if (!name || name === '.' || name === '..') return null;
            const cleanPath = dir.replace(/\\/+$/, '');
            return { name, isDirectory: isDir, size, permissions: perms, path: `${cleanPath}/${name}`, modifiedAt: dateStr };
          }).filter(Boolean);
          res.json({ success: true, files: files });
        } catch {
          res.json({ success: true, files: [] });
        }
      });"""

# 找到两个旧 handler 的剩余部分 (后半段 .on('error') 结尾相同), 用替换完成整块
old_tail = """  }).on('error', () => res.json({ success: true, files: [] }));
});"""
new_tail = """    }).on('error', () => res.json({ success: true, files: [] }));
  }
});"""

assert s.count(old_list) == 2, "old_list=%d" % s.count(old_list)
s = s.replace(old_list, new_list)
assert s.count(old_tail) == 2, "old_tail=%d" % s.count(old_tail)
s = s.replace(old_tail, new_tail)

open(p, "w", encoding="utf-8").write(s)
print("补丁#3b 已注入, 新大小:", len(s))
