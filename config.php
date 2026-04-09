<?php
/**
 * ═════════════════════════════════════════════════════════════════════════════
 * SULUT FISHERY - MAIN CONFIGURATION
 * OWASP Security Best Practices Implementation
 * ═════════════════════════════════════════════════════════════════════════════
 */

// ── ERROR HANDLING & LOGGING (H1-H2) ─────────────────────────────────────────
define('DEBUG_MODE', false);  // ⚠️ MUST BE FALSE IN PRODUCTION

if (!DEBUG_MODE) {
    // Production: Hide errors from users (H1)
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', __DIR__ . '/logs/php_errors.log');
    error_reporting(E_ALL);
} else {
    // Development: Show all errors
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
}

// ── APP ENVIRONMENT (H2) ─────────────────────────────────────────────────────
define('ENVIRONMENT', DEBUG_MODE ? 'DEVELOPMENT' : 'PRODUCTION');
define('SITE_URL', 'http://localhost/SulutFishery/');  // Update for HTTPS in production

// ── DIRECTORIES (H3, H4) ────────────────────────────────────────────────────
define('UPLOADS_DIR', __DIR__ . '/uploads/');
define('LOGS_DIR', __DIR__ . '/logs/');
define('CONFIG_DIR', __DIR__ . '/config/');

// Create directories with secure permissions (0755 = rwxr-xr-x)
$directories = [UPLOADS_DIR, LOGS_DIR];
foreach ($directories as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
        // Create .htaccess to prevent direct access (Apache 2.4 syntax)
        file_put_contents($dir . '.htaccess', "Require all denied\n");
    }
}

// ── SECURITY CONFIGURATION ──────────────────────────────────────────────────

// Session timeout: 30 minutes max (A7)
define('SESSION_TIMEOUT', 1800);
define('SESSION_IDLE_TIMEOUT', 1800);

// File upload
define('MAX_UPLOAD_SIZE', 5242880);  // 5 MB
define('ALLOWED_UPLOAD_TYPES', ['image/jpeg', 'image/png', 'image/gif']);

// Database
define('DB_HOST', 'localhost');
define('DB_USER', 'elana');
define('DB_PASS', 'Devops1813');
define('DB_NAME', 'sulutfishery');

// ── INCLUDE CONFIG MODULES ─────────────────────────────────────────────────
require_once CONFIG_DIR . 'koneksi.php';    // Database connection
require_once CONFIG_DIR . 'csrf.php';       // CSRF & XSS protection
require_once CONFIG_DIR . 'logger.php';     // Activity logging
require_once CONFIG_DIR . 'session.php';    // Session management

// ── SECURITY HEADERS (I7) ───────────────────────────────────────────────────
setSecurityHeaders();

// ── OWASP COMPLIANCE DOCUMENTATION ──────────────────────────────────────────
/**
 * OWASP A01 — BROKEN ACCESS CONTROL
 * 
 * B1: URL Routing
 * - Semua request ke dashboard.php, process files, config/ route via direktory structure
 * - Protected files di config/ & process/ via .htaccess (Require all denied)
 * 
 * B2: Access Modifier (Procedural Architecture)
 * - Sistem menggunakan PHP PROCEDURAL (bukan OOP)
 * - Access control via session validation (B5 — Server-side validation)
 * - requireLogin() di config/session.php enforce akses ke protected pages
 * 
 * B3: Endpoint Authorization Check
 * - dashboard.php: requireLogin() call
 * - process files: $_SESSION['user_id'] check
 * - Setiap aksi CRUD memvalidasi user ownership
 * 
 * B4: Sensitive URLs
 * - /config/ → Blocked via .htaccess (Require all denied)
 * - /logs/ → Blocked via .htaccess
 * - Process files → Only callable via POST dengan valid CSRF token
 * 
 * B6: Role Definition (PARTIAL)
 * - Role parameter di initializeSession(): 'user' (default)
 * - Saat ini hanya 1 role aktif (pembeli/penjual sama-sama 'user')
 * - Admin role belum diimplementasikan
 * - Dokumentasi lengkap: config/session.php
 * 
 * B7: User Cannot Access Other's Data
 * - Setiap query SQL filter by user_id
 * - Ex: "SELECT * FROM posts WHERE user_id = ?" ← User ID dari session
 * - Pembeli tidak bisa edit/delete listing milik penjual lain
 */

?>
