package observability

// CustomAuthScreenHTML is the standalone, cyber-styled, mobile-optimized authentication screen
// presented when RouteWarden SOC Dashboard is protected with Basic Auth.
const CustomAuthScreenHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0">
  <meta name="theme-color" content="#07090e">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="description" content="RouteWarden SOC Intelligence Console - Secure Operator Login">
  <title>ROUTEWARDEN SOC — Access Verification</title>
  <link rel="icon" type="image/svg+xml" href="/icon.svg">
  <link rel="alternate icon" type="image/x-icon" href="/favicon.ico">
  <link rel="shortcut icon" href="/favicon.ico">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --crust: #07090e;
      --base: #0c0f17;
      --panel: #111522;
      --surface: #182035;
      --surface-hi: #222c4a;
      --line: #1c243d;
      --line-hi: #2d3b63;
      --overlay: #64748b;
      --subtext: #94a3b8;
      --text: #e2e8f0;
      --text-hi: #ffffff;
      --green: #00ff9d;
      --green-bg: rgba(0, 255, 157, 0.08);
      --green-border: rgba(0, 255, 157, 0.3);
      --teal: #00e5ff;
      --teal-bg: rgba(0, 229, 255, 0.1);
      --teal-border: rgba(0, 229, 255, 0.3);
      --yellow: #ffb800;
      --pink: #ff3366;
      --pink-bg: rgba(255, 51, 102, 0.12);
      --pink-border: rgba(255, 51, 102, 0.4);
      --glow-green: 0 0 16px rgba(0, 255, 157, 0.4);
      --glow-teal: 0 0 16px rgba(0, 229, 255, 0.4);
      --glow-pink: 0 0 16px rgba(255, 51, 102, 0.4);
      --mono: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background: var(--crust);
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0, 229, 255, 0.12), transparent),
        radial-gradient(circle at 50% 100%, rgba(0, 255, 157, 0.05), transparent);
      color: var(--text);
      font-family: var(--mono);
      min-height: 100vh;
      min-height: -webkit-fill-available;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 20px 16px;
      position: relative;
      overflow-x: hidden;
    }

    /* Ambient Cyber Scanlines */
    body::before {
      content: "";
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%);
      background-size: 100% 4px;
      pointer-events: none;
      z-index: 1;
      opacity: 0.35;
    }

    .auth-container {
      width: 100%;
      max-width: 440px;
      position: relative;
      z-index: 2;
    }

    /* Cyber Brand Header */
    .brand-header {
      text-align: center;
      margin-bottom: 24px;
    }

    .brand-icon-wrap {
      width: 64px;
      height: 64px;
      margin: 0 auto 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--panel);
      border: 1px solid var(--teal-border);
      border-radius: 12px;
      box-shadow: var(--glow-teal), inset 0 0 12px rgba(0, 229, 255, 0.15);
      position: relative;
    }

    .brand-icon {
      width: 38px;
      height: 38px;
      filter: drop-shadow(0 0 6px var(--teal));
    }

    .brand-title {
      font-size: 20px;
      font-weight: 800;
      letter-spacing: 2px;
      color: var(--text-hi);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }

    .brand-title .bracket {
      color: var(--teal);
      text-shadow: var(--glow-teal);
    }

    .brand-subtitle {
      font-size: 11px;
      color: var(--subtext);
      letter-spacing: 1px;
      text-transform: uppercase;
      margin-top: 6px;
    }

    .brand-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--pink-bg);
      border: 1px solid var(--pink-border);
      color: var(--pink);
      padding: 3px 9px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.8px;
      margin-top: 10px;
      text-shadow: var(--glow-pink);
    }

    /* Cyber Card */
    .auth-card {
      background: var(--panel);
      border: 1px solid var(--line-hi);
      border-radius: 8px;
      box-shadow: 0 16px 48px rgba(0, 0, 0, 0.7), 0 0 0 1px rgba(0, 229, 255, 0.1);
      overflow: hidden;
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
    }

    .card-cap {
      background: var(--base);
      border-bottom: 1px solid var(--line);
      padding: 10px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 11px;
      color: var(--subtext);
    }

    .card-cap-dots {
      display: flex;
      gap: 6px;
    }

    .cap-dot {
      width: 9px;
      height: 9px;
      border-radius: 50%;
      background: var(--surface-hi);
      border: 1px solid var(--line-hi);
    }

    .cap-dot.red { background: rgba(255, 51, 102, 0.7); border-color: var(--pink); }
    .cap-dot.yellow { background: rgba(255, 184, 0, 0.7); border-color: var(--yellow); }
    .cap-dot.green { background: rgba(0, 255, 157, 0.7); border-color: var(--green); }

    .card-body {
      padding: 24px 20px;
    }

    /* Error Alert */
    .auth-alert {
      display: none;
      background: var(--pink-bg);
      border: 1px solid var(--pink-border);
      color: var(--pink);
      padding: 10px 14px;
      border-radius: 5px;
      font-size: 11.5px;
      margin-bottom: 18px;
      align-items: center;
      gap: 10px;
      animation: alertShake 0.35s ease;
    }

    @keyframes alertShake {
      0%, 100% { transform: translateX(0); }
      20%, 60% { transform: translateX(-6px); }
      40%, 80% { transform: translateX(6px); }
    }

    /* Form Fields */
    .form-group {
      margin-bottom: 18px;
    }

    .form-label {
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.8px;
      color: var(--subtext);
      text-transform: uppercase;
      margin-bottom: 7px;
    }

    .form-label .prompt-char {
      color: var(--green);
    }

    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }

    .input-icon {
      position: absolute;
      left: 12px;
      color: var(--overlay);
      font-size: 13px;
      pointer-events: none;
      line-height: 1;
    }

    .form-input {
      width: 100%;
      height: 44px;
      background: var(--base);
      border: 1px solid var(--line-hi);
      color: var(--text-hi);
      font-family: var(--mono);
      font-size: 14px;
      padding: 0 42px 0 38px;
      border-radius: 5px;
      outline: none;
      transition: all 0.16s ease;
      -webkit-appearance: none;
    }

    .form-input:hover {
      border-color: var(--overlay);
    }

    .form-input:focus {
      border-color: var(--teal);
      box-shadow: 0 0 0 2px var(--teal-bg), var(--glow-teal);
      background: #0f1422;
    }

    .input-toggle-btn {
      position: absolute;
      right: 10px;
      background: transparent;
      border: none;
      color: var(--overlay);
      cursor: pointer;
      padding: 6px;
      font-size: 14px;
      line-height: 1;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: color 0.15s ease;
    }

    .input-toggle-btn:hover {
      color: var(--text-hi);
    }

    /* Action Button */
    .btn-submit {
      width: 100%;
      height: 46px;
      background: linear-gradient(135deg, rgba(0, 229, 255, 0.2), rgba(0, 255, 157, 0.15));
      border: 1px solid var(--teal);
      color: var(--text-hi);
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      border-radius: 5px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-top: 8px;
      box-shadow: 0 4px 14px rgba(0, 229, 255, 0.2);
      transition: all 0.18s ease;
      -webkit-tap-highlight-color: transparent;
    }

    .btn-submit:hover:not(:disabled) {
      background: linear-gradient(135deg, rgba(0, 229, 255, 0.35), rgba(0, 255, 157, 0.25));
      border-color: var(--green);
      box-shadow: 0 6px 20px rgba(0, 255, 157, 0.35);
      transform: translateY(-1px);
    }

    .btn-submit:active:not(:disabled) {
      transform: translateY(0);
      box-shadow: 0 2px 8px rgba(0, 229, 255, 0.3);
    }

    .btn-submit:disabled {
      opacity: 0.6;
      cursor: wait;
      border-color: var(--line-hi);
    }

    /* Footer Info */
    .auth-footer {
      margin-top: 24px;
      text-align: center;
      font-size: 11px;
      color: var(--overlay);
      line-height: 1.6;
    }

    .footer-status {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      color: var(--green);
      font-size: 10.5px;
      margin-top: 6px;
    }

    .status-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--green);
      box-shadow: 0 0 6px var(--green);
      animation: pulseDot 2s infinite;
    }

    @keyframes pulseDot {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(1.2); }
    }

    /* Responsive adjustments for mobile devices */
    @media (max-width: 480px) {
      .card-body {
        padding: 20px 16px;
      }
      .brand-title {
        font-size: 18px;
      }
      .brand-icon-wrap {
        width: 56px;
        height: 56px;
      }
      .brand-icon {
        width: 32px;
        height: 32px;
      }
      .form-input {
        font-size: 16px; /* Prevents auto-zoom on iOS */
      }
      .btn-submit {
        height: 48px;
        font-size: 13.5px;
      }
    }
  </style>
</head>
<body>
  <div class="auth-container">
    <div class="brand-header">
      <div class="brand-icon-wrap">
        <img class="brand-icon" src="/icon.svg" alt="RouteWarden Logo">
      </div>
      <h1 class="brand-title">
        <span class="bracket">[</span> ROUTEWARDEN SOC <span class="bracket">]</span>
      </h1>
      <p class="brand-subtitle">Reverse Proxy Security & Traffic Monitor</p>
      <div class="brand-badge">
        🔒 RESTRICTED CONSOLE // AUTH REQUIRED
      </div>
    </div>

    <div class="auth-card">
      <div class="card-cap">
        <div class="card-cap-dots">
          <div class="cap-dot red"></div>
          <div class="cap-dot yellow"></div>
          <div class="cap-dot green"></div>
        </div>
        <span>terminal.login.v5.1.0</span>
      </div>

      <div class="card-body">
        <div class="auth-alert" id="auth-alert">
          <span id="alert-icon">🛑</span>
          <span id="alert-text">Access Denied: Invalid username or password</span>
        </div>

        <form id="auth-form" onsubmit="handleAuthSubmit(event)">
          <div class="form-group">
            <label class="form-label" for="username">
              <span><span class="prompt-char">&gt;</span> USERNAME</span>
            </label>
            <div class="input-wrap">
              <span class="input-icon">👤</span>
              <input 
                type="text" 
                class="form-input" 
                id="username" 
                name="username" 
                placeholder="Enter username" 
                autocomplete="username" 
                autocapitalize="none"
                autocorrect="off"
                required 
                autofocus>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label" for="password">
              <span><span class="prompt-char">&gt;</span> PASSWORD</span>
            </label>
            <div class="input-wrap">
              <span class="input-icon">🔑</span>
              <input 
                type="password" 
                class="form-input" 
                id="password" 
                name="password" 
                placeholder="Enter password" 
                autocomplete="current-password" 
                required>
              <button 
                type="button" 
                class="input-toggle-btn" 
                id="toggle-pass" 
                title="Toggle password visibility" 
                onclick="togglePasswordVisibility()">👁</button>
            </div>
          </div>

          <button type="submit" class="btn-submit" id="btn-submit">
            <span id="btn-icon">⚡</span>
            <span id="btn-text">SIGN IN TO DASHBOARD</span>
          </button>
        </form>
      </div>
    </div>

    <div class="auth-footer">
      <div>Encrypted Gateway Logs & Live Traffic Monitoring</div>
      <div class="footer-status">
        <span class="status-dot"></span>
        <span>ROUTEWARDEN SECURITY RUNNING</span>
      </div>
    </div>
  </div>

  <script>
    function togglePasswordVisibility() {
      var passInput = document.getElementById('password');
      var toggleBtn = document.getElementById('toggle-pass');
      if (passInput.type === 'password') {
        passInput.type = 'text';
        toggleBtn.textContent = '🔒';
      } else {
        passInput.type = 'password';
        toggleBtn.textContent = '👁';
      }
    }

    function showAlert(msg) {
      var alertBox = document.getElementById('auth-alert');
      var alertText = document.getElementById('alert-text');
      alertText.textContent = msg || 'Access Denied: Invalid username or password';
      alertBox.style.display = 'flex';
      // Retrigger shake animation
      alertBox.style.animation = 'none';
      void alertBox.offsetWidth;
      alertBox.style.animation = 'alertShake 0.35s ease';
    }

    function hideAlert() {
      var alertBox = document.getElementById('auth-alert');
      alertBox.style.display = 'none';
    }

    function handleAuthSubmit(event) {
      event.preventDefault();
      hideAlert();

      var username = document.getElementById('username').value.trim();
      var password = document.getElementById('password').value;
      var btn = document.getElementById('btn-submit');
      var btnText = document.getElementById('btn-text');
      var btnIcon = document.getElementById('btn-icon');

      if (!username || !password) {
        showAlert('Please enter both operator ID and access key.');
        return;
      }

      btn.disabled = true;
      btnIcon.textContent = '⏳';
      btnText.textContent = 'VERIFYING CREDENTIALS...';

      var payload = JSON.stringify({ username: username, password: password });

      fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: payload
      })
      .then(function(res) {
        if (!res.ok) {
          throw new Error('Invalid credentials');
        }
        return res.json();
      })
      .then(function(data) {
        btnIcon.textContent = '✅';
        btnText.textContent = 'ACCESS GRANTED — REDIRECTING...';
        btn.style.borderColor = 'var(--green)';
        btn.style.boxShadow = '0 0 20px rgba(0, 255, 157, 0.4)';

        // Store token in localStorage as client-side backup
        if (data.token) {
          try {
            localStorage.setItem('routewarden_auth', data.token);
          } catch(e) {}
        }

        // Redirect to destination (or /)
        var urlParams = new URLSearchParams(window.location.search);
        var dest = urlParams.get('redirect') || '/';
        setTimeout(function() {
          window.location.href = dest;
        }, 350);
      })
      .catch(function(err) {
        btn.disabled = false;
        btnIcon.textContent = '⚡';
        btnText.textContent = 'AUTHENTICATE & ENTER CONSOLE';
        showAlert('ACCESS DENIED: Invalid username or access key');
        var passInput = document.getElementById('password');
        passInput.value = '';
        passInput.focus();
      });
    }
  </script>
</body>
</html>
`
