<?php
// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD.PHP — Main user dashboard for buying/selling fish
// ═══════════════════════════════════════════════════════════════════════════════

require_once 'config.php'; // config.php already calls session_start()

// Require user to be logged in
if (!isset($_SESSION['user_id'])) {
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: login.php');
    exit;
}

// Security: Check session timeout (30 minutes)
$MAX_SESSION_TIMEOUT = SESSION_TIMEOUT;
if (isset($_SESSION['last_activity'])) {
    $time_passed = time() - $_SESSION['last_activity'];
    if ($time_passed > $MAX_SESSION_TIMEOUT) {
        // Session expired, destroy and redirect
        session_unset();
        session_destroy();
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Location: login.php?expired=1');
        exit;
    }
}
$_SESSION['last_activity'] = time(); // Update last activity

$user_id   = (int)$_SESSION['user_id'];
$user_name = escapeHTML($_SESSION['user_name'] ?? 'User');

// ── GENERATE CSRF TOKEN ONCE ──────────────────────────────────────────────────
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

$errors  = [];
$success = '';
$tab     = $_GET['tab'] ?? 'dashboard';  // dashboard | my_sales | purchases | add_listing

// ── GET USER PROFILE ──────────────────────────────────────────────────────────
$stmt = $conn->prepare("SELECT name, email, phone, address, city, province FROM users WHERE id = ? LIMIT 1");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

// NOTE: Add listing is now handled by process/add_listing.php

// ── HANDLE AJAX: Buy Product (Create Purchase) ───────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['buy_product'])) {
    header('Content-Type: application/json');
    
    // CSRF Token Verification
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $csrf_token) {
        echo json_encode(['success' => false, 'message' => 'Security token invalid. Please refresh page.']);
        exit;
    }

    $post_id    = (int)($_POST['post_id'] ?? 0);
    $quantity   = floatval($_POST['quantity'] ?? 0);
    $notes      = sanitizeInput($_POST['notes'] ?? '');

    // Get post details
    $stmt = $conn->prepare("
        SELECT id, user_id, product_name, quantity, price_per_unit, status 
        FROM posts WHERE id = ? LIMIT 1
    ");
    $stmt->bind_param('i', $post_id);
    $stmt->execute();
    $post = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$post) {
        echo json_encode(['success' => false, 'message' => 'Post not found']); exit;
    }
    if ($post['status'] !== 'active') {
        echo json_encode(['success' => false, 'message' => 'This listing is not active']); exit;
    }
    if ($post['user_id'] == $user_id) {
        echo json_encode(['success' => false, 'message' => 'Cannot buy your own listing']); exit;
    }
    if ($quantity <= 0 || $quantity > $post['quantity']) {
        echo json_encode(['success' => false, 'message' => 'Invalid quantity']); exit;
    }

    $total_amount = $quantity * $post['price_per_unit'];
    $seller_id    = $post['user_id'];

    // Create purchase record
    $stmt = $conn->prepare(
        "INSERT INTO purchases (post_id, seller_id, buyer_id, quantity_bought, price_per_unit, total_amount, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param('iiiidds', 
        $post_id, $seller_id, $user_id, $quantity, $post['price_per_unit'], $total_amount, $notes
    );

    if ($stmt->execute()) {
        $purchase_id = $stmt->insert_id;

        // Update post quantity
        $new_quantity = $post['quantity'] - $quantity;
        $update_stmt = $conn->prepare("UPDATE posts SET quantity = ?, status = ? WHERE id = ?");
        $new_status = ($new_quantity <= 0) ? 'sold' : 'active';
        $update_stmt->bind_param('dsi', $new_quantity, $new_status, $post_id);
        $update_stmt->execute();
        $update_stmt->close();

        // Log transaction
        $trans_stmt = $conn->prepare(
            "INSERT INTO transactions (purchase_id, user_id, type, amount, description)
             VALUES (?, ?, 'purchase', ?, ?)"
        );
        $desc = 'Purchase: ' . $post['product_name'];
        $trans_stmt->bind_param('iids', $purchase_id, $user_id, $total_amount, $desc);
        $trans_stmt->execute();
        $trans_stmt->close();

        logSecurityEvent('PURCHASE_CREATED', [
            'post_id' => $post_id, 
            'product' => $post['product_name'],
            'quantity' => $quantity,
            'seller_id' => $seller_id
        ]);

        echo json_encode(['success' => true, 'message' => 'Purchase created!']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Database error']);
    }
    $stmt->close();
    exit;
}

// NOTE: Update listing is now handled by process/update_listing.php

// NOTE: Delete listing is now handled by process/delete_listing.php

// ── GET DATA: All active posts (for buying) ───────────────────────────────────
$stmt = $conn->prepare("
    SELECT id, user_id, product_name, description, category, location, quantity, 
           price_per_unit, total_price, photo, status, created_at
    FROM posts 
    WHERE status = 'active'
    ORDER BY created_at DESC
");
$stmt->execute();
$all_posts = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// ── GET DATA: My sales/listings ───────────────────────────────────────────────
$stmt = $conn->prepare("
    SELECT id, product_name, description, category, location, quantity, 
           price_per_unit, total_price, photo, status, created_at
    FROM posts 
    WHERE user_id = ?
    ORDER BY created_at DESC
");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$my_posts = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// ── GET DATA: My purchases ────────────────────────────────────────────────────
$stmt = $conn->prepare("
    SELECT pur.id, pur.post_id, pur.seller_id, p.product_name, p.location, 
           pur.quantity_bought, pur.price_per_unit, pur.total_amount, 
           pur.payment_status, pur.delivery_status, pur.notes, pur.created_at,
           u.name AS seller_name
    FROM purchases pur
    JOIN posts p ON p.id = pur.post_id
    JOIN users u ON u.id = pur.seller_id
    WHERE pur.buyer_id = ?
    ORDER BY pur.created_at DESC
");
$stmt->bind_param('i', $user_id);
$stmt->execute();
$my_purchases = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

?><!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard — Sulut Fishery</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@700;900&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --navy: #0a1628;
      --teal: #0f7b6c;
      --teal-light: #14a896;
      --gold: #e8c56d;
      --sand: #f5ede0;
      --white: #fdfcfa;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'DM Sans', sans-serif;
      background: var(--navy);
      color: var(--white);
    }
    nav {
      position: sticky; top: 0; z-index: 50;
      background: rgba(10,22,40,0.95); backdrop-filter: blur(16px);
      border-bottom: 1px solid rgba(232,197,109,0.12);
      padding: 1rem 2rem;
      display: flex; align-items: center; justify-content: space-between;
    }
    .nav-logo { display: flex; align-items: center; gap: 0.8rem; text-decoration: none; }
    .logo-box {
      width: 36px; height: 36px; border-radius: 8px;
      background: linear-gradient(135deg, var(--teal), #0d2647);
      border: 1.5px solid var(--gold);
      display: flex; align-items: center; justify-content: center;
      font-family: 'Playfair Display', serif;
      font-weight: 700; font-size: 0.8rem; color: var(--gold);
    }
    .nav-brand { font-family: 'Playfair Display', serif; font-size: 1rem; font-weight: 700; }
    .nav-right { display: flex; align-items: center; gap: 1rem; }
    .nav-user {
      display: flex; align-items: center; gap: 0.5rem;
      padding: 0.5rem 1rem; background: rgba(232,197,109,0.1);
      border-radius: 8px; font-size: 0.9rem;
    }
    .nav-btn {
      padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none;
      background: var(--gold); color: var(--navy); font-weight: 600;
      transition: all 0.2s;
    }
    .nav-btn:hover { transform: translateY(-2px); }

    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

    .tabs {
      display: flex; gap: 1rem; margin-bottom: 2rem;
      border-bottom: 1px solid rgba(255,255,255,0.1);
      padding-bottom: 1rem;
    }
    .tab-btn {
      padding: 0.7rem 1.5rem; background: none; border: none;
      color: rgba(255,255,255,0.5); cursor: pointer; transition: all 0.2s;
      font-weight: 500; border-bottom: 2px solid transparent;
      margin-bottom: -1rem;
    }
    .tab-btn.active {
      color: var(--gold); border-bottom-color: var(--gold);
    }

    .tab-content { display: none; }
    .tab-content.active { display: block; animation: fadeIn 0.3s ease; }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    .alert {
      padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;
      font-size: 0.9rem;
    }
    .alert-success { background: rgba(15,123,108,0.2); border: 1px solid rgba(15,123,108,0.4); }
    .alert-error { background: rgba(220,50,50,0.2); border: 1px solid rgba(220,50,50,0.4); }

    .grid-posts {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
      gap: 2rem; margin-bottom: 2rem;
    }

    .card {
      background: rgba(13,38,71,0.4); border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px; overflow: hidden; transition: all 0.3s;
    }
    .card:hover { border-color: rgba(232,197,109,0.3); transform: translateY(-4px); }

    .card-img {
      width: 100%; height: 200px; background: rgba(15,123,108,0.2);
      display: flex; align-items: center; justify-content: center;
      overflow: hidden;
    }
    .card-img img { width: 100%; height: 100%; object-fit: cover; }

    .card-body { padding: 1.5rem; }
    .card-title {
      font-family: 'Playfair Display', serif;
      font-size: 1.1rem; font-weight: 700; margin-bottom: 0.5rem;
    }
    .card-cat {
      display: inline-block; font-size: 0.75rem;
      background: rgba(232,197,109,0.2); color: var(--gold);
      padding: 0.3rem 0.7rem; border-radius: 4px; margin-bottom: 0.8rem;
    }
    .card-meta {
      font-size: 0.85rem; color: rgba(255,255,255,0.5);
      margin-bottom: 0.8rem;
    }
    .card-price {
      font-size: 1.2rem; font-weight: 700; color: var(--gold);
      margin-bottom: 0.5rem;
    }
    .card-qty { font-size: 0.9rem; color: rgba(255,255,255,0.7); margin-bottom: 1rem; }

    .btn {
      padding: 0.6rem 1rem; border: none; border-radius: 6px;
      cursor: pointer; font-weight: 600; transition: all 0.2s;
      font-size: 0.85rem;
    }
    .btn-primary {
      background: linear-gradient(135deg, var(--teal), var(--teal-light));
      color: #fff;
    }
    .btn-primary:hover { transform: translateY(-2px); }
    .btn-danger {
      background: rgba(220,50,50,0.3); color: #fca5a5; border: 1px solid rgba(220,50,50,0.4);
    }
    .btn-danger:hover { background: rgba(220,50,50,0.5); }
    .btn-sm { padding: 0.4rem 0.8rem; font-size: 0.8rem; }

    .form-group { margin-bottom: 1.2rem; }
    .form-label {
      display: block; font-size: 0.85rem; font-weight: 600;
      color: rgba(255,255,255,0.7); margin-bottom: 0.4rem;
    }
    .form-input, .form-select, .form-textarea {
      width: 100%; padding: 0.75rem;
      background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px; color: #fff; font-family: 'DM Sans', sans-serif;
      font-size: 0.95rem;
    }
    .form-input::placeholder, .form-textarea::placeholder {
      color: rgba(255,255,255,0.3);
    }
    .form-input:focus, .form-select:focus, .form-textarea:focus {
      outline: none; border-color: var(--teal-light); background: rgba(20,168,150,0.1);
    }

    .modal { display: none; }
    .modal.show {
      position: fixed; inset: 0; background: rgba(0,0,0,0.7);
      z-index: 100; display: flex; align-items: center; justify-content: center;
      animation: fadeIn 0.3s ease;
    }
    .modal-content {
      background: var(--navy); border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px; padding: 2rem; width: 90%; max-width: 500px;
      max-height: 90vh; overflow-y: auto;
    }
    .modal-header {
      font-size: 1.3rem; font-weight: 700; margin-bottom: 1.5rem;
      font-family: 'Playfair Display', serif;
    }
    .modal-close {
      position: absolute; top: 1rem; right: 1rem;
      background: none; border: none; color: #fff;
      font-size: 1.5rem; cursor: pointer;
    }

    .status-badge {
      display: inline-block; padding: 0.3rem 0.8rem; border-radius: 20px;
      font-size: 0.75rem; font-weight: 600;
    }
    .status-active { background: rgba(34,197,94,0.2); color: #86efac; }
    .status-sold { background: rgba(220,50,50,0.2); color: #fca5a5; }
    .status-pending { background: rgba(232,197,109,0.2); color: var(--gold); }
    .status-completed { background: rgba(15,123,108,0.2); color: var(--teal-light); }

    .empty-state {
      text-align: center; padding: 3rem 1rem;
      color: rgba(255,255,255,0.4);
    }
    .empty-state-icon { font-size: 3rem; margin-bottom: 1rem; }

    input[type="file"] { color: rgba(255,255,255,0.7); }
    input[type="file"]::file-selector-button {
      background: var(--teal); color: #fff;
      border: none; padding: 0.5rem 1rem; border-radius: 6px;
      cursor: pointer; margin-right: 1rem; font-weight: 600;
    }
  </style>
</head>
<body>

<!-- NAV -->
<nav>
  <a href="dashboard.php" class="nav-logo">
    <div class="logo-box">SF</div>
    <span class="nav-brand">Sulut Fishery</span>
  </a>
  <div class="nav-right">
    <div class="nav-user">👋 <?= htmlspecialchars($user_name) ?></div>
    <a href="logout.php" class="nav-btn">Logout</a>
  </div>
</nav>

<div class="container">

  <!-- TABS -->
  <div class="tabs">
    <button type="button" class="tab-btn <?= $tab === 'dashboard' ? 'active' : '' ?>" onclick="switchTab('dashboard')">📊 Dashboard</button>
    <button type="button" class="tab-btn <?= $tab === 'my_sales' ? 'active' : '' ?>" onclick="switchTab('my_sales')">📤 My Sales</button>
    <button type="button" class="tab-btn <?= $tab === 'purchases' ? 'active' : '' ?>" onclick="switchTab('purchases')">📥 Purchases</button>
    <button type="button" class="tab-btn <?= $tab === 'add_listing' ? 'active' : '' ?>" onclick="switchTab('add_listing')">➕ Add Listing</button>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <!-- TAB: DASHBOARD ──────────────────────────────────────────────────────────── -->
  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <div id="tab-dashboard" class="tab-content <?= $tab === 'dashboard' ? 'active' : '' ?>">
    <h2 style="font-family: 'Playfair Display', serif; font-size: 2rem; margin-bottom: 2rem;">Available Fish Listings</h2>

    <?php if (empty($all_posts)): ?>
      <div class="empty-state">
        <div class="empty-state-icon">🐟</div>
        <p>No listings available yet. Check back soon!</p>
      </div>
    <?php else: ?>
      <div class="grid-posts">
        <?php foreach ($all_posts as $post): ?>
          <div class="card">
            <div class="card-img">
              <?php if ($post['photo'] && file_exists($post['photo'])): ?>
                <img src="<?= htmlspecialchars($post['photo']) ?>" alt="<?= htmlspecialchars($post['product_name']) ?>">
              <?php else: ?>
                <div style="width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; font-size: 3rem;">🐟</div>
              <?php endif; ?>
            </div>
            <div class="card-body">
              <?php if ($post['category']): ?>
                <div class="card-cat"><?= htmlspecialchars($post['category']) ?></div>
              <?php endif; ?>
              <h3 class="card-title"><?= htmlspecialchars($post['product_name']) ?></h3>
              <div class="card-meta">📍 <?= htmlspecialchars($post['location']) ?></div>
              <div class="card-price">Rp <?= number_format($post['price_per_unit'], 0, ',', '.') ?>/kg</div>
              <div class="card-qty">⚖️ Available: <?= number_format($post['quantity'], 2) ?> kg</div>
              <button class="btn btn-primary btn-sm" onclick="openBuyModal(<?= $post['id'] ?>, '<?= htmlspecialchars($post['product_name']) ?>', <?= $post['price_per_unit'] ?>, <?= $post['quantity'] ?>)">
                Buy Now
              </button>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <!-- TAB: MY SALES ────────────────────────────────────────────────────────────── -->
  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <div id="tab-my_sales" class="tab-content <?= $tab === 'my_sales' ? 'active' : '' ?>">
    <h2 style="font-family: 'Playfair Display', serif; font-size: 2rem; margin-bottom: 2rem;">My Sales Listings</h2>

    <?php if (empty($my_posts)): ?>
      <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <p>You haven't added any listings yet</p>
      </div>
    <?php else: ?>
      <div class="grid-posts">
        <?php foreach ($my_posts as $post): ?>
          <div class="card">
            <div class="card-img">
              <?php if ($post['photo'] && file_exists($post['photo'])): ?>
                <img src="<?= htmlspecialchars($post['photo']) ?>" alt="<?= htmlspecialchars($post['product_name']) ?>">
              <?php else: ?>
                <div style="width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; font-size: 3rem;">🐟</div>
              <?php endif; ?>
            </div>
            <div class="card-body">
              <?php if ($post['category']): ?>
                <div class="card-cat"><?= htmlspecialchars($post['category']) ?></div>
              <?php endif; ?>
              <h3 class="card-title"><?= htmlspecialchars($post['product_name']) ?></h3>
              <div class="card-meta">📍 <?= htmlspecialchars($post['location']) ?></div>
              <div class="card-price">Rp <?= number_format($post['price_per_unit'], 0, ',', '.') ?>/kg</div>
              <div class="card-qty">⚖️ Stock: <?= number_format($post['quantity'], 2) ?> kg</div>
              <div style="margin-bottom: 1rem;">
                <span class="status-badge status-<?= $post['status'] ?>"><?= ucfirst($post['status']) ?></span>
              </div>
              <div style="display: flex; gap: 0.5rem;">
                <button class="btn btn-primary btn-sm" onclick="updateStatus(<?= $post['id'] ?>, '<?= $post['status'] === 'active' ? 'sold' : 'active' ?>')">
                  <?= $post['status'] === 'active' ? 'Mark Sold' : 'Reactivate' ?>
                </button>
                <button class="btn btn-danger btn-sm" onclick="deletePost(<?= $post['id'] ?>)">Delete</button>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <!-- TAB: PURCHASES ───────────────────────────────────────────────────────────── -->
  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <div id="tab-purchases" class="tab-content <?= $tab === 'purchases' ? 'active' : '' ?>">
    <h2 style="font-family: 'Playfair Display', serif; font-size: 2rem; margin-bottom: 2rem;">My Purchases</h2>

    <?php if (empty($my_purchases)): ?>
      <div class="empty-state">
        <div class="empty-state-icon">🛒</div>
        <p>No purchases yet</p>
      </div>
    <?php else: ?>
      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1);">
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Product</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Seller</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Quantity</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Total Price</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Payment</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Delivery</th>
              <th style="text-align: left; padding: 1rem; color: rgba(255,255,255,0.7);">Date</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($my_purchases as $pur): ?>
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 1rem;"><?= htmlspecialchars($pur['product_name']) ?></td>
                <td style="padding: 1rem;"><?= htmlspecialchars($pur['seller_name']) ?></td>
                <td style="padding: 1rem;"><?= number_format($pur['quantity_bought'], 2) ?> kg</td>
                <td style="padding: 1rem; color: var(--gold); font-weight: 700;">Rp <?= number_format($pur['total_amount'], 0, ',', '.') ?></td>
                <td style="padding: 1rem;"><span class="status-badge status-<?= $pur['payment_status'] ?>"><?= ucfirst($pur['payment_status']) ?></span></td>
                <td style="padding: 1rem;"><span class="status-badge" style="background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.7);"><?= ucfirst($pur['delivery_status']) ?></span></td>
                <td style="padding: 1rem; color: rgba(255,255,255,0.5); font-size: 0.85rem;"><?= date('d M Y', strtotime($pur['created_at'])) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>

  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <!-- TAB: ADD LISTING ─────────────────────────────────────────────────────────── -->
  <!-- ══════════════════════════════════════════════════════════════════════════ -->
  <div id="tab-add_listing" class="tab-content <?= $tab === 'add_listing' ? 'active' : '' ?>">
    <div style="max-width: 600px;">
      <h2 style="font-family: 'Playfair Display', serif; font-size: 2rem; margin-bottom: 2rem;">Add New Listing</h2>

      <div id="add-msg" style="display: none; margin-bottom: 1.5rem;"></div>

      <form id="add-form">
        <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
        <div class="form-group">
          <label class="form-label">Product Name *</label>
          <input type="text" name="product_name" class="form-input" placeholder="e.g., Red Snapper" required>
        </div>

        <div class="form-group">
          <label class="form-label">Category</label>
          <select name="category" class="form-select">
            <option value="">Choose Category</option>
            <option value="Snapper">Snapper</option>
            <option value="Grouper">Grouper</option>
            <option value="Mackerel">Mackerel</option>
            <option value="Tuna">Tuna</option>
            <option value="Crab">Crab</option>
            <option value="Shrimp">Shrimp</option>
            <option value="Other">Other</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label">Description</label>
          <textarea name="description" class="form-textarea" placeholder="Describe your product..." rows="3"></textarea>
        </div>

        <div class="form-group">
          <label class="form-label">Location *</label>
          <input type="text" name="location" class="form-input" placeholder="e.g., Manado Port" required>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem;">
          <div class="form-group">
            <label class="form-label">Quantity (kg) *</label>
            <input type="number" name="quantity" class="form-input" placeholder="0" step="0.01" min="0" required>
          </div>

          <div class="form-group">
            <label class="form-label">Price per kg (Rp) *</label>
            <input type="number" name="price_per_unit" class="form-input" placeholder="0" step="0.01" min="0" required>
          </div>
        </div>

        <div class="form-group">
          <label class="form-label">Photo</label>
          <input type="file" name="photo" accept="image/jpeg,image/png,image/webp">
          <small style="color: rgba(255,255,255,0.4); display: block; margin-top: 0.5rem;">Max 5 MB (JPG, PNG, WebP)</small>
        </div>

        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 0.8rem;">Create Listing</button>
      </form>
    </div>
  </div>

</div>

<!-- ══════════════════════════════════════════════════════════════════════════ -->
<!-- MODAL: BUY PRODUCT ───────────────────────────────────────────────────────── -->
<!-- ══════════════════════════════════════════════════════════════════════════ -->
<div id="buy-modal" class="modal">
  <div class="modal-content">
    <button type="button" class="modal-close" onclick="closeBuyModal()">✕</button>
    <div class="modal-header">Buy Fish</div>

    <form id="buy-form">
      <input type="hidden" name="post_id" value="">
      <input type="hidden" name="csrf_token" id="buy-csrf-token" value="<?= $csrf_token ?>">

      <div class="form-group">
        <label class="form-label">Product</label>
        <input type="text" id="buy-product-name" readonly class="form-input" style="background: rgba(255,255,255,0.03);">
      </div>

      <div class="form-group">
        <label class="form-label">Price per kg: <span style="color: var(--gold);">Rp <span id="buy-price-display">0</span></span></label>
      </div>

      <div class="form-group">
        <label class="form-label">Available Quantity: <span id="buy-qty-available">0</span> kg</label>
        <label class="form-label">Quantity to Buy (kg) *</label>
        <input type="number" name="quantity" class="form-input" placeholder="0" step="0.01" min="0.01" id="buy-qty-input" required>
        <small id="qty-error" style="color: #fca5a5; display: none; margin-top: 0.5rem; display: block;"></small>
      </div>

      <div class="form-group">
        <label class="form-label">Total: <span id="buy-total-display" style="color: var(--gold); font-weight: 700;">Rp 0</span></label>
      </div>

      <div class="form-group">
        <label class="form-label">Notes (Optional)</label>
        <textarea name="notes" class="form-textarea" placeholder="Add any notes..." rows="2"></textarea>
      </div>

      <button type="submit" class="btn btn-primary" style="width: 100%; padding: 0.8rem;">Confirm Purchase</button>
    </form>
  </div>
</div>

<script>
  let buyData = {};
  let csrfToken = '<?= $csrf_token ?>';

  // ──── SWITCH TABS (SIMPLE & DIRECT) ────────────────────────────────────────
  function switchTab(tabName) {
    // Hide all tabs
    const allTabs = document.querySelectorAll('.tab-content');
    allTabs.forEach(tab => tab.classList.remove('active'));
    
    // Hide all tab buttons background
    const allButtons = document.querySelectorAll('.tab-btn');
    allButtons.forEach(btn => btn.classList.remove('active'));
    
    // Show selected tab
    const selectedTab = document.getElementById('tab-' + tabName);
    if (selectedTab) {
      selectedTab.classList.add('active');
    }
    
    // Highlight selected button
    event.target.classList.add('active');
    
    // Update URL
    window.history.replaceState(null, '', '?tab=' + tabName);
  }

  // ──── BUY MODAL ────────────────────────────────────────────────────────────
  function openBuyModal(postId, productName, price, maxQty) {
    buyData = { postId, productName, price, maxQty };
    document.getElementById('buy-product-name').value = productName;
    document.getElementById('buy-price-display').textContent = (price).toLocaleString('id-ID');
    document.getElementById('buy-qty-available').textContent = maxQty.toFixed(2);
    document.getElementById('buy-qty-input').max = maxQty;
    document.getElementById('buy-qty-input').value = '';
    document.querySelector('[name="post_id"]').value = postId;
    document.getElementById('buy-modal').classList.add('show');
  }

  function closeBuyModal() {
    document.getElementById('buy-modal').classList.remove('show');
    document.getElementById('buy-form').reset();
  }

  document.getElementById('buy-qty-input').addEventListener('input', function() {
    let qty = parseFloat(this.value) || 0;
    let max = parseFloat(this.max) || 0;
    let total = qty * buyData.price;
    let errorEl = document.getElementById('qty-error');

    if (qty > max) {
      errorEl.textContent = 'Quantity exceeds available stock';
      errorEl.style.display = 'block';
    } else {
      errorEl.style.display = 'none';
    }

    document.getElementById('buy-total-display').textContent = 'Rp ' + total.toLocaleString('id-ID', { maximumFractionDigits: 0 });
  });

  document.getElementById('buy-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    let qty = parseFloat(document.getElementById('buy-qty-input').value);
    if (qty <= 0 || qty > buyData.maxQty) {
      alert('Invalid quantity');
      return;
    }

    let formData = new FormData(this);
    formData.append('buy_product', '1');
    
    fetch('dashboard.php', { method: 'POST', body: formData })
      .then(r => r.text())
      .then(text => {
        try {
          let d = JSON.parse(text);
          if (d.success) {
            alert(d.message);
            closeBuyModal();
            location.reload();
          } else {
            alert('Error: ' + d.message);
          }
        } catch(e) {
          alert('Server error');
        }
      })
      .catch(err => alert('Error: ' + err.message));
  });

  document.getElementById('add-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    let formData = new FormData(this);
    fetch('process/add_listing.php', { method: 'POST', body: formData })
      .then(r => r.text())
      .then(text => {
        try {
          let d = JSON.parse(text);
          let msgEl = document.getElementById('add-msg');
          if (d.success) {
            msgEl.className = 'alert alert-success';
            msgEl.textContent = '✅ ' + d.message;
            msgEl.style.display = 'block';
            document.getElementById('add-form').reset();
            setTimeout(() => location.reload(), 1500);
          } else {
            msgEl.className = 'alert alert-error';
            msgEl.textContent = '⚠️ ' + d.message;
            msgEl.style.display = 'block';
          }
        } catch(e) {
          let msgEl = document.getElementById('add-msg');
          msgEl.className = 'alert alert-error';
          msgEl.textContent = '⚠️ Server error';
          msgEl.style.display = 'block';
        }
      })
      .catch(err => {
        let msgEl = document.getElementById('add-msg');
        msgEl.className = 'alert alert-error';
        msgEl.textContent = '⚠️ Error: ' + err.message;
        msgEl.style.display = 'block';
      });
  });

  function updateStatus(postId, newStatus) {
    if (!confirm('Update status to ' + newStatus + '?')) return;

    let formData = new FormData();
    formData.append('post_id', postId);
    formData.append('status', newStatus);
    formData.append('csrf_token', csrfToken);

    fetch('process/update_listing.php', { method: 'POST', body: formData })
      .then(r => r.text())
      .then(text => {
        try {
          let d = JSON.parse(text);
          alert(d.message);
          if (d.success) location.reload();
        } catch(e) {
          alert('Server error');
        }
      })
      .catch(err => alert('Error: ' + err.message));
  }

  function deletePost(postId) {
    if (!confirm('Delete this listing? This cannot be undone.')) return;

    let formData = new FormData();
    formData.append('post_id', postId);
    formData.append('csrf_token', csrfToken);

    fetch('process/delete_listing.php', { method: 'POST', body: formData })
      .then(r => r.text())
      .then(text => {
        try {
          let d = JSON.parse(text);
          alert(d.message);
          if (d.success) location.reload();
        } catch(e) {
          alert('Server error');
        }
      })
      .catch(err => alert('Error: ' + err.message));
  }

  // Close modal when clicking outside
  document.getElementById('buy-modal').addEventListener('click', function(e) {
    if (e.target === this) closeBuyModal();
  });
</script>

</body>
</html>
