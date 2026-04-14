<?php
// login.php — Login & Register with bcrypt password hashing & CSRF Protection
// required_once in config.php already starts session
require_once 'config.php';

$mode    = $_GET['mode'] ?? 'login';   // 'login' | 'register'
$errors  = [];
$success = '';
$form_data = []; // Keep form data for re-populate
$already_logged_in = false;

// Check if already logged in - show message instead of auto-redirect
if (isset($_SESSION['user_id'])) {
    $already_logged_in = true;
    $current_user_name = escapeHTML($_SESSION['user_name'] ?? 'User');
}

// Check if session expired
if (isset($_GET['expired']) && $_GET['expired'] == 1) {
    $errors[] = '⏱️ Your session has expired. Please log in again.';
}

// ════════════════════════════════════════════════════════════════════════════════
// HANDLE POST REQUESTS
// ════════════════════════════════════════════════════════════════════════════════
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // ── LOGIN FORM ──────────────────────────────────────────────────────────────
    if (isset($_POST['action']) && $_POST['action'] === 'login_submit') {
        
        // CSRF Token Verification
        if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
            $errors[] = 'Security token expired. Please try again.';
            $mode = 'login';
        } else {
            
            $email    = trim($_POST['email'] ?? '');
            $password = $_POST['password'] ?? '';
            $form_data['email'] = sanitizeInput($email);
            
            // Rate limiting check
            $rateLimitKey = 'login_' . getClientIP();
            if (!checkRateLimit($rateLimitKey, 5, 900)) {
                $errors[] = '❌ Too many login attempts. Please try again in 15 minutes.';
                logSecurityEvent('LOGIN_RATE_LIMIT', ['email' => $email]);
            } elseif (!$email || !$password) {
                $errors[] = 'Email and password are required.';
            } elseif (!validateEmail($email)) {
                $errors[] = 'Please enter a valid email address.';
            } else {
                // Use prepared statement to prevent SQL injection
                $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ? LIMIT 1");
                if (!$stmt) {
                    if (DEBUG_MODE) {
                        $errors[] = 'Database error: ' . $conn->error;
                    } else {
                        $errors[] = 'An error occurred. Please try again later.';
                    }
                } else {
                    $stmt->bind_param('s', $email);
                    $stmt->execute();
                    $user = $stmt->get_result()->fetch_assoc();
                    $stmt->close();

                    if ($user && password_verify($password, $user['password'])) {
                        // Successful login
                        // Regenerate session ID to prevent fixation attack
                        session_regenerate_id(true);
                        $_SESSION['user_id']         = $user['id'];
                        $_SESSION['user_name']       = $user['name'];
                        $_SESSION['user_email']      = $email;
                        $_SESSION['last_activity']   = time();
                        $_SESSION['login_time']      = time();
                        
                        logSecurityEvent('LOGIN_SUCCESS', ['email' => $email]);
                        header('Location: dashboard.php'); exit;
                    } else {
                        // Failed login attempt
                        logSecurityEvent('LOGIN_FAILED', [
                            'email' => $email,
                            'reason' => 'Invalid credentials'
                        ]);
                        $errors[] = 'Email or password is incorrect.';
                    }
                }
            }
            
            $mode = 'login'; // Stay on login mode if error
        }

        if (!$email || !$password) {
            $errors[] = 'Email and password are required.';
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        } else {
            $stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ? LIMIT 1");
            if (!$stmt) {
                $errors[] = 'Database error: ' . $conn->error;
            } else {
                $stmt->bind_param('s', $email);
                $stmt->execute();
                $user = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if ($user && password_verify($password, $user['password'])) {
                    // Regenerate session ID to prevent fixation
                    session_regenerate_id(true);
                    $_SESSION['user_id']      = $user['id'];
                    $_SESSION['user_name']    = $user['name'];
                    $_SESSION['last_activity'] = time(); // Track session activity
                    header('Location: dashboard.php'); exit;
                } else {
                    $errors[] = 'Email or password is incorrect.';
                }
            }
        }
        
        $mode = 'login'; // Stay on login mode if error
    }

    // ── REGISTER FORM ───────────────────────────────────────────────────────────
    elseif (isset($_POST['action']) && $_POST['action'] === 'register_submit') {
        $name     = trim($_POST['name'] ?? '');
        $email    = trim($_POST['email'] ?? '');
        $phone    = trim($_POST['phone'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';

        // Keep form data
        $form_data = [
            'name'  => $name,
            'email' => $email,
            'phone' => $phone
        ];

        // Validation
        if (!$name) {
            $errors[] = 'Full name is required.';
        } elseif (strlen($name) < 3) {
            $errors[] = 'Full name must be at least 3 characters.';
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        }

        if (!preg_match('/^[0-9]{9,15}$/', $phone)) {
            $errors[] = 'Phone number must be 9–15 digits (numbers only).';
        }

        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters.';
        }

        if ($password !== $confirm) {
            $errors[] = 'Passwords do not match.';
        }

        // Check if validation passed
        if (empty($errors)) {
            // Check if email already exists
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
            if (!$stmt) {
                $errors[] = 'Database error: ' . $conn->error;
            } else {
                $stmt->bind_param('s', $email);
                $stmt->execute();
                $exists = $stmt->get_result()->num_rows > 0;
                $stmt->close();

                if ($exists) {
                    $errors[] = 'Email address is already registered. Please use a different email.';
                } else {
                    // Hash password with bcrypt
                    $hashed = password_hash($password, PASSWORD_DEFAULT);

                    // INSERT user
                    $stmt = $conn->prepare(
                        "INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)"
                    );
                    if (!$stmt) {
                        $errors[] = 'Database error: ' . $conn->error;
                    } else {
                        $stmt->bind_param('ssss', $name, $email, $phone, $hashed);

                        if ($stmt->execute()) {
                            // Registration berhasil - jangan set session, hanya tampilkan success message
                            $success = '✅ Account created successfully! You can now log in with your email and password.';
                            logSecurityEvent('REGISTER_SUCCESS', ['email' => $email, 'name' => $name]);
                            $mode = 'login'; // Force switch to login
                            $form_data = []; // Clear register form
                        } else {
                            $errors[] = 'Registration failed: ' . $stmt->error;
                            logSecurityEvent('REGISTER_FAILED', ['email' => $email, 'error' => $stmt->error]);
                        }
                        $stmt->close();
                    }
                }
            }
        }
        
        // Stay on register mode if error
        if (!empty($errors)) {
            $mode = 'register';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title><?= $mode === 'register' ? 'Register' : 'Login' ?> — Sulut Fishery GIT JENKINS</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,700;0,900;1,400&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    :root {
      --navy:  #0a1628;
      --teal:  #0f7b6c;
      --tealL: #14a896;
      --gold:  #e8c56d;
      --goldL: #f5d98a;
      --white: #fdfcfa;
    }
    *, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
    body {
      font-family:'DM Sans',sans-serif;
      min-height:100vh; background:var(--navy);
      color:var(--white); display:flex; flex-direction:column;
    }

    /* ── NAV ── */
    nav {
      position:fixed; top:0; left:0; right:0; z-index:100;
      padding:.9rem 2rem;
      display:flex; align-items:center; justify-content:space-between;
      background:rgba(10,22,40,.92); backdrop-filter:blur(16px);
      border-bottom:1px solid rgba(232,197,109,.12);
    }
    .nav-logo { display:flex; align-items:center; gap:.7rem; text-decoration:none; }
    .logo-box {
      width:34px; height:34px; border-radius:8px;
      background:linear-gradient(135deg,var(--teal),#0d2647);
      border:1.5px solid var(--gold);
      display:flex; align-items:center; justify-content:center;
      font-family:'Playfair Display',serif; font-weight:700; font-size:.82rem; color:var(--gold);
    }
    .nav-brand { font-family:'Playfair Display',serif; font-size:1.05rem; font-weight:700; color:#fff; }
    .nav-links  { display:flex; gap:.6rem; }
    .nav-btn {
      padding:.42rem 1.1rem; border-radius:6px; font-size:.84rem;
      text-decoration:none; transition:all .2s;
    }
    .nav-outline { border:1px solid rgba(232,197,109,.4); color:var(--gold); }
    .nav-outline:hover { background:rgba(232,197,109,.1); }
    .nav-filled  { background:var(--gold); color:var(--navy); font-weight:600; }
    .nav-filled:hover { background:var(--goldL); }

    /* ── LAYOUT ── */
    .auth-wrapper {
      flex:1; display:flex; padding-top:62px;
    }

    /* Left visual panel */
    .auth-visual {
      display:none; flex:1; position:relative; overflow:hidden;
    }
    @media(min-width:900px){ .auth-visual{ display:block; } }
    .av-bg {
      position:absolute; inset:0;
      background:linear-gradient(160deg,#0d3a28 0%,#051910 55%,#061220 100%);
    }
    .av-content {
      position:relative; z-index:2; height:100%;
      display:flex; flex-direction:column; align-items:center; justify-content:center;
      padding:3rem;
    }
    .av-emoji { font-size:5.5rem; margin-bottom:1.8rem; animation:float 5s ease-in-out infinite; }
    @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-14px)} }
    .av-title {
      font-family:'Playfair Display',serif;
      font-size:clamp(2.2rem,4vw,3.2rem); font-weight:900;
      color:#fff; text-align:center; line-height:1.1;
    }
    .av-title em { color:var(--gold); font-style:italic; }
    .av-sub { margin-top:1rem; font-size:.95rem; color:rgba(255,255,255,.5); text-align:center; line-height:1.7; max-width:340px; }
    .av-stats { margin-top:2.5rem; display:flex; gap:2rem; }
    .avs-item { text-align:center; }
    .avs-num { font-family:'Playfair Display',serif; font-size:1.7rem; font-weight:900; color:var(--gold); }
    .avs-lbl { font-size:.72rem; color:rgba(255,255,255,.4); margin-top:.15rem; }

    /* Right form panel */
    .auth-panel {
      width:100%; max-width:460px;
      padding:2.5rem 2rem;
      display:flex; flex-direction:column; justify-content:center;
      background:rgba(13,38,71,.4); backdrop-filter:blur(20px);
      border-left:1px solid rgba(255,255,255,.06);
    }
    @media(min-width:900px){ .auth-panel{ padding:3.5rem 2.8rem; } }

    /* Tab switcher */
    .tab-bar {
      display:flex; background:rgba(255,255,255,.05);
      border:1px solid rgba(255,255,255,.08); border-radius:10px;
      padding:4px; margin-bottom:2.2rem;
    }
    .tab-btn {
      flex:1; padding:.6rem; border-radius:7px; border:none;
      background:transparent; color:rgba(253,252,250,.45);
      font-family:'DM Sans',sans-serif; font-size:.88rem; cursor:pointer; transition:all .25s;
    }
    .tab-btn.active {
      background:var(--gold); color:var(--navy);
      font-weight:700; box-shadow:0 3px 12px rgba(232,197,109,.3);
    }

    /* Headings */
    .form-title { font-family:'Playfair Display',serif; font-size:1.75rem; font-weight:900; color:#fff; margin-bottom:.35rem; }
    .form-sub   { font-size:.85rem; color:rgba(253,252,250,.42); margin-bottom:1.8rem; }

    /* Alerts */
    .alert {
      border-radius:9px; padding:.75rem 1rem; font-size:.84rem; margin-bottom:1.4rem;
    }
    .alert-error   { background:rgba(220,50,50,.14); border:1px solid rgba(220,50,50,.3); color:#fca5a5; }
    .alert-success { background:rgba(15,123,108,.2);  border:1px solid rgba(15,123,108,.4); color:var(--tealL); }
    .alert ul { margin-left:1rem; list-style:disc; }
    .alert ul li { margin-top:.25rem; }

    /* Fields */
    .field      { margin-bottom:1.1rem; }
    .f-label    { display:block; font-size:.79rem; font-weight:500; color:rgba(253,252,250,.55); margin-bottom:.42rem; letter-spacing:.04em; }
    .f-label .req { color:#f87171; margin-left:2px; }
    .f-wrap     { position:relative; }
    .f-icon     { position:absolute; left:.85rem; top:50%; transform:translateY(-50%); font-size:.95rem; pointer-events:none; }
    .f-input {
      width:100%; padding:.72rem 1rem .72rem 2.5rem;
      background:rgba(255,255,255,.06); border:1.5px solid rgba(255,255,255,.1);
      border-radius:9px; color:#fff; font-family:'DM Sans',sans-serif;
      font-size:.9rem; outline:none; transition:all .22s;
    }
    .f-input::placeholder { color:rgba(253,252,250,.28); }
    .f-input:focus { border-color:var(--tealL); background:rgba(20,168,150,.09); box-shadow:0 0 0 3px rgba(20,168,150,.12); }
    .f-hint { font-size:.72rem; color:rgba(253,252,250,.3); margin-top:.32rem; }

    /* Password toggle */
    .f-eye {
      position:absolute; right:.85rem; top:50%; transform:translateY(-50%);
      background:none; border:none; color:rgba(255,255,255,.35);
      cursor:pointer; font-size:.9rem; padding:.2rem;
    }
    .f-eye:hover { color:rgba(255,255,255,.7); }
    .f-input.has-eye { padding-right:2.4rem; }

    .field-row { display:grid; grid-template-columns:1fr 1fr; gap:.85rem; }
    @media(max-width:480px){ .field-row{ grid-template-columns:1fr; } }

    /* Submit */
    .btn-submit {
      width:100%; padding:.85rem; border-radius:10px; border:none;
      background:linear-gradient(135deg,var(--teal),var(--tealL));
      color:#fff; font-family:'DM Sans',sans-serif; font-size:.95rem; font-weight:700;
      cursor:pointer; transition:all .28s; letter-spacing:.04em; margin-top:.5rem;
      box-shadow:0 5px 20px rgba(15,123,108,.35);
    }
    .btn-submit:hover { transform:translateY(-2px); box-shadow:0 10px 28px rgba(15,123,108,.45); }
    .btn-submit:active { transform:translateY(0); }

    .form-footer { text-align:center; font-size:.82rem; color:rgba(253,252,250,.38); margin-top:1.4rem; }
    .form-footer a { color:var(--gold); text-decoration:none; }
    .form-footer a:hover { text-decoration:underline; }

    /* Show/hide form */
    .form-section { display:none; }
    .form-section.active { display:block; }
  </style>
</head>
<body>

<!-- NAV -->
<nav>
  <a href="index.html" class="nav-logo">
    <div class="logo-box">SF</div>
    <span class="nav-brand">Sulut Fishery</span>
  </a>
  <div class="nav-links">
    <a href="login.php"              class="nav-btn nav-outline">Login</a>
    <a href="login.php?mode=register" class="nav-btn nav-filled">Register</a>
  </div>
</nav>

<div class="auth-wrapper">

  <!-- Visual side -->
  <div class="auth-visual">
    <div class="av-bg"></div>
    <div class="av-content">
      <div class="av-emoji">🎣</div>
      <h2 class="av-title">Join<br><em>Sulut Fishery</em></h2>
      <p class="av-sub">Digital fish auction platform for North Sulawesi. Get the best price for every catch.</p>
      <div class="av-stats">
        <div class="avs-item"><div class="avs-num">1.2K+</div><div class="avs-lbl">Users</div></div>
        <div class="avs-item"><div class="avs-num">3.7K</div><div class="avs-lbl">Tons Auctioned</div></div>
        <div class="avs-item"><div class="avs-num">890T</div><div class="avs-lbl">Exported</div></div>
      </div>
    </div>
  </div>

  <!-- Form panel -->
  <div class="auth-panel">

    <!-- Already logged in alert -->
    <?php if ($already_logged_in): ?>
      <div class="alert alert-success" style="margin-bottom:1.4rem; background:rgba(15,123,108,.25); border:1.5px solid rgba(15,123,108,.5); padding:1.2rem;">
        <div style="font-weight:600; margin-bottom:.5rem;">✅ You're already logged in!</div>
        <div style="font-size:.82rem; color:rgba(253,252,250,.7); margin-bottom:1rem;">Welcome back, <strong><?= $current_user_name ?></strong></div>
        <div style="display:flex; gap:.6rem;">
          <a href="dashboard.php" style="flex:1; padding:.65rem; background:rgba(15,123,108,.4); border:1px solid rgba(15,123,108,.6); color:var(--tealL); text-decoration:none; border-radius:8px; text-align:center; font-weight:600; font-size:.84rem; transition:all .2s;" onmouseover="this.style.background='rgba(15,123,108,.6)'" onmouseout="this.style.background='rgba(15,123,108,.4)'">Go to Dashboard →</a>
          <a href="logout.php" style="flex:1; padding:.65rem; background:rgba(220,50,50,.15); border:1px solid rgba(220,50,50,.3); color:#fca5a5; text-decoration:none; border-radius:8px; text-align:center; font-weight:600; font-size:.84rem; transition:all .2s;" onmouseover="this.style.background='rgba(220,50,50,.25)'" onmouseout="this.style.background='rgba(220,50,50,.15)'">Logout</a>
        </div>
      </div>
    <?php endif; ?>

    <!-- Tab bar -->
    <div class="tab-bar" style="<?= $already_logged_in ? 'display:none;' : '' ?>">
      <button type="button" class="tab-btn <?= $mode !== 'register' ? 'active' : '' ?>" onclick="switchTab('login'); return false;">Login</button>
      <button type="button" class="tab-btn <?= $mode === 'register' ? 'active' : '' ?>" onclick="switchTab('register'); return false;">Register</button>
    </div>

    <!-- Alerts -->
    <?php if (!$already_logged_in && !empty($errors)): ?>
      <div class="alert alert-error">
        <?php if (count($errors) === 1): ?>
          ⚠️ <?= htmlspecialchars($errors[0]) ?>
        <?php else: ?>
          ⚠️ Please fix the following:<ul>
          <?php foreach($errors as $e): ?><li><?= htmlspecialchars($e) ?></li><?php endforeach; ?>
          </ul>
        <?php endif; ?>
      </div>
    <?php endif; ?>

    <?php if ($success): ?>
      <div class="alert alert-success">✅ <?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

    <!-- ── LOGIN FORM ── -->
    <div class="form-section <?= $mode !== 'register' ? 'active' : '' ?>" id="form-login" style="<?= $already_logged_in ? 'display:none;' : '' ?>">
      <h2 class="form-title">Welcome Back</h2>
      <p class="form-sub">Sign in to your Sulut Fishery account</p>

      <form method="POST" novalidate>
        <input type="hidden" name="action" value="login_submit"/>
        <?= getCSRFTokenInput() ?>

        <div class="field">
          <label class="f-label">Email Address <span class="req">*</span></label>
          <div class="f-wrap">
            <span class="f-icon">📧</span>
            <input type="email" name="email" class="f-input"
              placeholder="you@example.com"
              value="<?= htmlspecialchars($form_data['email'] ?? '') ?>" required autocomplete="email"/>
          </div>
        </div>

        <div class="field">
          <label class="f-label">Password <span class="req">*</span></label>
          <div class="f-wrap">
            <span class="f-icon">🔒</span>
            <input type="password" name="password" id="pw-login" class="f-input has-eye"
              placeholder="Enter your password" required autocomplete="current-password"/>
            <button type="button" class="f-eye" onclick="togglePw('pw-login',this)">👁</button>
          </div>
        </div>

        <button type="submit" class="btn-submit">Sign In →</button>
      </form>

      <p class="form-footer">Don't have an account? <a href="#" onclick="switchTab('register'); return false;">Register here</a></p>
    </div>

    <!-- ── REGISTER FORM ── -->
    <div class="form-section <?= $mode === 'register' ? 'active' : '' ?>" id="form-register" style="<?= $already_logged_in ? 'display:none;' : '' ?>">
      <h2 class="form-title">Create Account</h2>
      <p class="form-sub">Join and start auctioning today</p>

      <form method="POST" novalidate>
        <input type="hidden" name="action" value="register_submit"/>
        <?= getCSRFTokenInput() ?>

        <div class="field">
          <label class="f-label">Full Name <span class="req">*</span></label>
          <div class="f-wrap">
            <span class="f-icon">👤</span>
            <input type="text" name="name" class="f-input"
              placeholder="Your full name"
              value="<?= htmlspecialchars($form_data['name'] ?? '') ?>" required autocomplete="name"/>
          </div>
        </div>

        <div class="field-row">
          <div class="field">
            <label class="f-label">Email <span class="req">*</span></label>
            <div class="f-wrap">
              <span class="f-icon">📧</span>
              <input type="email" name="email" class="f-input"
                placeholder="you@example.com"
                value="<?= htmlspecialchars($form_data['email'] ?? '') ?>" required autocomplete="email"/>
            </div>
          </div>
          <div class="field">
            <label class="f-label">Phone <span class="req">*</span></label>
            <div class="f-wrap">
              <span class="f-icon">📱</span>
              <input type="tel" name="phone" class="f-input"
                placeholder="08xxxxxxxxxx"
                value="<?= htmlspecialchars($form_data['phone'] ?? '') ?>" required autocomplete="tel"/>
            </div>
          </div>
        </div>

        <div class="field">
          <label class="f-label">Password <span class="req">*</span></label>
          <div class="f-wrap">
            <span class="f-icon">🔒</span>
            <input type="password" name="password" id="pw-reg" class="f-input has-eye"
              placeholder="Min. 8 characters" minlength="8" required autocomplete="new-password"
              oninput="checkStrength(this.value)"/>
            <button type="button" class="f-eye" onclick="togglePw('pw-reg',this)">👁</button>
          </div>
          <div id="pw-strength" class="f-hint" style="margin-top:.4rem;"></div>
        </div>

        <div class="field">
          <label class="f-label">Confirm Password <span class="req">*</span></label>
          <div class="f-wrap">
            <span class="f-icon">🔒</span>
            <input type="password" name="confirm_password" id="pw-confirm" class="f-input has-eye"
              placeholder="Repeat password" required autocomplete="new-password"/>
            <button type="button" class="f-eye" onclick="togglePw('pw-confirm',this)">👁</button>
          </div>
        </div>

        <button type="submit" class="btn-submit">Create Account →</button>
      </form>

      <p class="form-footer">Already have an account? <a href="#" onclick="switchTab('login'); return false;">Sign in</a></p>
    </div>

  </div><!-- /auth-panel -->
</div><!-- /auth-wrapper -->

<script>
  // Auto-switch ke login tab kalau ada success message dan mode sudah login
  <?php if ($success && $mode === 'login'): ?>
  document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
      switchTab('login');
    }, 500);
  });
  <?php endif; ?>

  function switchTab(tab) {
    // Validate tab name
    if (tab !== 'login' && tab !== 'register') {
      console.error('Invalid tab:', tab);
      return false;
    }
    
    // Toggle active button
    document.querySelectorAll('.tab-btn').forEach((b, i) => {
      b.classList.toggle('active', (tab === 'login' && i === 0) || (tab === 'register' && i === 1));
    });
    
    // Hide all forms, show selected form
    document.querySelectorAll('.form-section').forEach(f => f.classList.remove('active'));
    const formEl = document.getElementById('form-' + tab);
    if (formEl) {
      formEl.classList.add('active');
    } else {
      console.error('Form not found:', 'form-' + tab);
      return false;
    }
    
    // Update URL
    history.replaceState(null, '', '?mode=' + tab);
    
    return false; // Prevent default link behavior
  }

  function togglePw(id, btn) {
    const inp = document.getElementById(id);
    const show = inp.type === 'password';
    inp.type = show ? 'text' : 'password';
    btn.textContent = show ? '🙈' : '👁';
  }

  function checkStrength(val) {
    const el = document.getElementById('pw-strength');
    if (!val) { el.textContent=''; return; }
    let score = 0;
    if (val.length >= 8)  score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    const levels = [
      {txt:'Very weak',   col:'#ef4444'},
      {txt:'Weak',        col:'#f97316'},
      {txt:'Fair',        col:'#eab308'},
      {txt:'Strong',      col:'#22c55e'},
      {txt:'Very strong', col:'#16a34a'},
    ];
    const l = levels[score] || levels[0];
    el.innerHTML = `Password strength: <strong style="color:${l.col}">${l.txt}</strong>`;
  }
</script>
</body>
</html>