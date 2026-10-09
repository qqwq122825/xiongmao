/**
 * AI 金融分析悬浮球 Widget
 * 自动注入到设备控制页面，提供 AI 分析功能
 */
(function() {
  'use strict';

  // 仅在设备控制页面加载（URL 参数含 controlDeviceId 或路径含 device）
  const _urlParams = new URLSearchParams(location.search);
  const _hasDevice = _urlParams.has('controlDeviceId') || _urlParams.has('id') || _urlParams.has('deviceId')
    || location.pathname.includes('controlDevice') || location.pathname.includes('device');
  if (!_hasDevice) return;

  // 提取设备 ID（从 URL 参数）
  function getDeviceId() {
    const params = new URLSearchParams(location.search);
    return params.get('controlDeviceId') || params.get('id') || params.get('deviceId') || '';
  }

  // 获取 token
  function getToken() {
    return localStorage.getItem('token') || localStorage.getItem('auth_token') || '';
  }

  // ======= 样式注入 =======
  const style = document.createElement('style');
  style.textContent = `
    /* 悬浮球 */
    #ai-float-ball {
      position: fixed;
      right: 24px;
      bottom: 80px;
      width: 56px;
      height: 56px;
      border-radius: 50%;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      box-shadow: 0 4px 20px rgba(102,126,234,0.5), 0 0 40px rgba(118,75,162,0.2);
      cursor: pointer;
      z-index: 99999;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: transform 0.3s cubic-bezier(0.34,1.56,0.64,1), box-shadow 0.3s;
      user-select: none;
      animation: ai-pulse 2s ease-in-out infinite;
    }
    #ai-float-ball:hover {
      transform: scale(1.12);
      box-shadow: 0 6px 28px rgba(102,126,234,0.7), 0 0 60px rgba(118,75,162,0.3);
    }
    #ai-float-ball:active { transform: scale(0.95); }
    #ai-float-ball .ai-icon {
      font-size: 22px;
      color: #fff;
      font-weight: 800;
      letter-spacing: -1px;
      text-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }
    @keyframes ai-pulse {
      0%,100% { box-shadow: 0 4px 20px rgba(102,126,234,0.5), 0 0 0 0 rgba(102,126,234,0.4); }
      50% { box-shadow: 0 4px 20px rgba(102,126,234,0.5), 0 0 0 12px rgba(102,126,234,0); }
    }

    /* 遮罩层 */
    #ai-overlay {
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.5);
      backdrop-filter: blur(4px);
      z-index: 100000;
      opacity: 0;
      visibility: hidden;
      transition: opacity 0.3s, visibility 0.3s;
    }
    #ai-overlay.active { opacity: 1; visibility: visible; }

    /* AI 面板 */
    #ai-panel {
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) scale(0.9);
      width: 520px;
      max-height: 85vh;
      background: #1a1d23;
      border-radius: 16px;
      border: 1px solid rgba(255,255,255,0.08);
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      z-index: 100001;
      opacity: 0;
      visibility: hidden;
      transition: all 0.35s cubic-bezier(0.34,1.56,0.64,1);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    #ai-panel.active { opacity: 1; visibility: visible; transform: translate(-50%, -50%) scale(1); }

    /* 面板头部 */
    .ai-header {
      padding: 20px 24px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .ai-header-left {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .ai-header-icon {
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: linear-gradient(135deg, #667eea, #764ba2);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }
    .ai-header h3 {
      margin: 0;
      color: #f0f0f0;
      font-size: 16px;
      font-weight: 600;
    }
    .ai-header .close-btn {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      border: none;
      background: rgba(255,255,255,0.06);
      color: #999;
      font-size: 18px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s;
    }
    .ai-header .close-btn:hover { background: rgba(255,80,80,0.15); color: #ff5050; }

    /* 面板内容 */
    .ai-body {
      padding: 20px 24px;
      overflow-y: auto;
      flex: 1;
    }

    /* 开始分析按钮 */
    .ai-start-btn {
      width: 100%;
      padding: 14px;
      border: none;
      border-radius: 12px;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #fff;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .ai-start-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102,126,234,0.4); }
    .ai-start-btn:active { transform: translateY(0); }
    .ai-start-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    /* 加载动画 */
    .ai-loading {
      text-align: center;
      padding: 40px 0;
      color: #999;
    }
    .ai-loading .spinner {
      width: 40px;
      height: 40px;
      border: 3px solid rgba(102,126,234,0.2);
      border-top-color: #667eea;
      border-radius: 50%;
      animation: ai-spin 0.8s linear infinite;
      margin: 0 auto 16px;
    }
    @keyframes ai-spin { to { transform: rotate(360deg); } }

    /* 评分区域 */
    .ai-score-section {
      text-align: center;
      padding: 20px 0;
      margin-bottom: 20px;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .ai-score-circle {
      width: 100px;
      height: 100px;
      border-radius: 50%;
      margin: 0 auto 12px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      position: relative;
    }
    .ai-score-circle::before {
      content: '';
      position: absolute;
      inset: -3px;
      border-radius: 50%;
      padding: 3px;
      background: conic-gradient(var(--score-color) calc(var(--score-pct) * 1%), rgba(255,255,255,0.08) 0);
      mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
      mask-composite: exclude;
      -webkit-mask-composite: xor;
    }
    .ai-score-number {
      font-size: 36px;
      font-weight: 800;
      line-height: 1;
    }
    .ai-score-label {
      font-size: 12px;
      color: #999;
      margin-top: 2px;
    }
    .ai-score-level {
      display: inline-block;
      padding: 3px 12px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      margin-top: 8px;
    }

    /* 总余额 */
    .ai-total-balance {
      background: rgba(255,255,255,0.03);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 16px;
      border: 1px solid rgba(255,255,255,0.06);
    }
    .ai-total-balance .label {
      font-size: 12px;
      color: #888;
      margin-bottom: 4px;
    }
    .ai-total-balance .amount {
      font-size: 24px;
      font-weight: 700;
      color: #4ade80;
    }
    .ai-total-balance .usd {
      font-size: 14px;
      color: #999;
      margin-left: 8px;
    }

    /* 账户列表 */
    .ai-account-card {
      background: rgba(255,255,255,0.03);
      border-radius: 12px;
      padding: 14px 16px;
      margin-bottom: 10px;
      border: 1px solid rgba(255,255,255,0.06);
      transition: background 0.2s;
    }
    .ai-account-card:hover { background: rgba(255,255,255,0.06); }
    .ai-account-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 8px;
    }
    .ai-account-name {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .ai-account-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .ai-account-badge.bank { background: rgba(59,130,246,0.15); color: #60a5fa; }
    .ai-account-badge.salary { background: rgba(234,179,8,0.15); color: #facc15; }
    .ai-account-badge.wallet { background: rgba(168,85,247,0.15); color: #c084fc; }
    .ai-account-bank-name {
      font-size: 14px;
      font-weight: 600;
      color: #e0e0e0;
    }
    .ai-account-balance {
      font-size: 16px;
      font-weight: 700;
      color: #4ade80;
    }
    .ai-account-balance .usd {
      font-size: 12px;
      color: #888;
      font-weight: 400;
      margin-left: 6px;
    }
    .ai-account-detail {
      font-size: 12px;
      color: #777;
    }

    /* 摘要 */
    .ai-summary {
      background: rgba(102,126,234,0.08);
      border-radius: 10px;
      padding: 12px 16px;
      margin-top: 16px;
      font-size: 13px;
      color: #b0b0b0;
      line-height: 1.6;
      border-left: 3px solid #667eea;
    }

    /* 错误提示 */
    .ai-error {
      text-align: center;
      padding: 30px 0;
      color: #ff6b6b;
    }
    .ai-error .icon { font-size: 36px; margin-bottom: 10px; }
    .ai-error .msg { font-size: 14px; color: #999; margin-top: 8px; }

    /* 无数据 */
    .ai-empty {
      text-align: center;
      padding: 40px 0;
      color: #666;
    }
    .ai-empty .icon { font-size: 48px; margin-bottom: 12px; opacity: 0.5; }

    /* 缓存标签 */
    .ai-cached-tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      background: rgba(234,179,8,0.15);
      color: #facc15;
      margin-left: 8px;
    }

    /* 信息标签 */
    .ai-info-row {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 8px 0;
      font-size: 12px;
      color: #888;
    }
  `;
  document.head.appendChild(style);

  // ======= DOM 创建 =======
  // 悬浮球
  const ball = document.createElement('div');
  ball.id = 'ai-float-ball';
  ball.innerHTML = '<span class="ai-icon">AI</span>';
  ball.title = 'AI 金融分析';
  document.body.appendChild(ball);

  // 遮罩层
  const overlay = document.createElement('div');
  overlay.id = 'ai-overlay';
  document.body.appendChild(overlay);

  // AI 面板
  const panel = document.createElement('div');
  panel.id = 'ai-panel';
  panel.innerHTML = `
    <div class="ai-header">
      <div class="ai-header-left">
        <div class="ai-header-icon">🤖</div>
        <h3>AI 金融分析</h3>
      </div>
      <button class="close-btn" id="ai-close">✕</button>
    </div>
    <div class="ai-body" id="ai-body">
      <div class="ai-info-row">
        <span>📱</span>
        <span>设备: <strong id="ai-device-id">--</strong></span>
      </div>
      <div style="margin-top:16px">
        <button class="ai-start-btn" id="ai-start-btn">
          <span>🔍</span>
          <span>开始 AI 分析</span>
        </button>
      </div>
      <div class="ai-info-row" style="margin-top:12px;justify-content:center;color:#666">
        分析设备短信和相册图片，提取银行账户余额信息
      </div>
    </div>
  `;
  document.body.appendChild(panel);

  // ======= 交互逻辑 =======
  let isOpen = false;

  function openPanel() {
    const deviceId = getDeviceId();
    if (!deviceId) { alert('未检测到设备ID'); return; }
    document.getElementById('ai-device-id').textContent = deviceId;
    overlay.classList.add('active');
    panel.classList.add('active');
    isOpen = true;
    // 检查是否有缓存结果
    checkCache(deviceId);
  }

  function closePanel() {
    overlay.classList.remove('active');
    panel.classList.remove('active');
    isOpen = false;
  }

  ball.addEventListener('click', openPanel);
  overlay.addEventListener('click', closePanel);
  document.getElementById('ai-close').addEventListener('click', closePanel);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && isOpen) closePanel(); });

  // 拖拽悬浮球
  let isDragging = false, dragStartY = 0, ballStartY = 0;
  ball.addEventListener('mousedown', (e) => {
    isDragging = false;
    dragStartY = e.clientY;
    ballStartY = ball.getBoundingClientRect().top;
    const onMove = (e) => {
      const dy = Math.abs(e.clientY - dragStartY);
      if (dy > 5) isDragging = true;
      if (isDragging) {
        ball.style.bottom = 'auto';
        ball.style.top = (ballStartY + (e.clientY - dragStartY)) + 'px';
      }
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      if (!isDragging) openPanel();
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    e.preventDefault();
  });

  // 检查缓存
  async function checkCache(deviceId) {
    try {
      const resp = await fetch(`/api/ai/finance-analysis/${deviceId}`, {
        headers: { 'Authorization': 'Bearer ' + getToken() }
      });
      const json = await resp.json();
      if (json.success && json.data) {
        renderResult(json.data, json.cached);
      }
    } catch { }
  }

  // 开始分析
  document.getElementById('ai-start-btn').addEventListener('click', async () => {
    const deviceId = getDeviceId();
    if (!deviceId) return;
    const btn = document.getElementById('ai-start-btn');
    const body = document.getElementById('ai-body');

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:18px;height:18px;border-width:2px;display:inline-block;margin:0"></span> 分析中...';

    // 显示加载状态
    body.innerHTML = `
      <div class="ai-loading">
        <div class="spinner"></div>
        <div>正在分析设备数据...</div>
        <div style="font-size:12px;color:#666;margin-top:8px">提取短信 + 相册图片 → Gemini AI 分析</div>
      </div>
    `;

    try {
      const resp = await fetch(`/api/ai/finance-analysis/${deviceId}`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + getToken(),
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ forceRefresh: true })
      });
      const json = await resp.json();
      if (json.success && json.data) {
        renderResult(json.data, json.cached);
      } else {
        renderError(json.message || '分析失败');
      }
    } catch (e) {
      renderError(e.message || '网络请求失败');
    }
  });

  // 渲染结果
  function renderResult(data, cached) {
    const body = document.getElementById('ai-body');
    const score = data.score || 0;
    const level = data.scoreLevel || (score > 70 ? '高档' : score > 30 ? '中档' : '低档');
    const scoreColor = score > 70 ? '#4ade80' : score > 30 ? '#facc15' : '#ff6b6b';
    const levelBg = score > 70 ? 'rgba(74,222,128,0.12)' : score > 30 ? 'rgba(250,204,21,0.12)' : 'rgba(255,107,107,0.12)';

    let accountsHtml = '';
    if (data.accounts && data.accounts.length > 0) {
      accountsHtml = data.accounts.map(acc => {
        const badgeClass = acc.type === '工资' ? 'salary' : acc.type === '电子钱包' ? 'wallet' : 'bank';
        const badgeLabel = acc.type || '银行';
        return `
          <div class="ai-account-card">
            <div class="ai-account-top">
              <div class="ai-account-name">
                <span class="ai-account-badge ${badgeClass}">${badgeLabel}</span>
                <span class="ai-account-bank-name">${acc.bankName || '--'}</span>
              </div>
              <div class="ai-account-balance">
                ${acc.balanceFormatted || '--'}
                <span class="usd">(${acc.balanceUSD || '--'})</span>
              </div>
            </div>
            <div class="ai-account-detail">
              ${acc.lastTransaction ? '最近: ' + acc.lastTransaction : ''}
              ${acc.lastTransactionDate ? ' (' + acc.lastTransactionDate + ')' : ''}
              ${acc.accountTail ? ' · 尾号' + acc.accountTail : ''}
            </div>
          </div>
        `;
      }).join('');
    }

    body.innerHTML = `
      <div class="ai-score-section">
        <div class="ai-score-circle" style="--score-color:${scoreColor};--score-pct:${score}">
          <span class="ai-score-number" style="color:${scoreColor}">${score}</span>
          <span class="ai-score-label">AI评分</span>
        </div>
        <span class="ai-score-level" style="background:${levelBg};color:${scoreColor}">${level}</span>
        ${cached ? '<span class="ai-cached-tag">缓存</span>' : ''}
      </div>

      ${data.totalBalance ? `
        <div class="ai-total-balance">
          <div class="label">总余额</div>
          <span class="amount">${data.totalBalance}</span>
          <span class="usd">(${data.totalBalanceUSD || '--'})</span>
        </div>
      ` : ''}

      ${accountsHtml || '<div class="ai-empty"><div class="icon">📭</div><div>未检测到银行账户信息</div></div>'}

      ${data.summary ? `<div class="ai-summary">${data.summary}</div>` : ''}

      <div style="margin-top:16px">
        <button class="ai-start-btn" id="ai-start-btn" onclick="document.getElementById('ai-start-btn').click()">
          <span>🔄</span>
          <span>重新分析</span>
        </button>
      </div>
    `;

    // 重新绑定"重新分析"按钮
    const refreshBtn = body.querySelector('.ai-start-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const deviceId = getDeviceId();
        refreshBtn.disabled = true;
        refreshBtn.innerHTML = '<span class="spinner" style="width:18px;height:18px;border-width:2px;display:inline-block;margin:0"></span> 分析中...';

        body.innerHTML = `
          <div class="ai-loading">
            <div class="spinner"></div>
            <div>正在重新分析...</div>
          </div>
        `;

        try {
          const resp = await fetch(`/api/ai/finance-analysis/${deviceId}`, {
            method: 'POST',
            headers: {
              'Authorization': 'Bearer ' + getToken(),
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ forceRefresh: true })
          });
          const json = await resp.json();
          if (json.success && json.data) {
            renderResult(json.data, false);
          } else {
            renderError(json.message || '分析失败');
          }
        } catch (err) {
          renderError(err.message || '网络请求失败');
        }
      });
    }
  }

  // 渲染错误
  function renderError(msg) {
    const body = document.getElementById('ai-body');
    body.innerHTML = `
      <div class="ai-error">
        <div class="icon">⚠️</div>
        <div>分析失败</div>
        <div class="msg">${msg}</div>
      </div>
      <div style="margin-top:16px">
        <button class="ai-start-btn" id="ai-start-btn">
          <span>🔄</span>
          <span>重试</span>
        </button>
      </div>
    `;
    // 重新绑定
    body.querySelector('.ai-start-btn').addEventListener('click', () => {
      body.innerHTML = `
        <div class="ai-info-row">
          <span>📱</span>
          <span>设备: <strong>${getDeviceId()}</strong></span>
        </div>
        <div style="margin-top:16px">
          <button class="ai-start-btn" id="ai-start-btn">
            <span>🔍</span>
            <span>开始 AI 分析</span>
          </button>
        </div>
      `;
      document.getElementById('ai-start-btn').addEventListener('click', () => location.reload());
    });
  }

})();
