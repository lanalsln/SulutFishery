<?php
/**
 * ═════════════════════════════════════════════════════════════════════════════
 * SESSION MANAGEMENT & CONFIGURATION
 * OWASP A07: Identification and Authentication Failures
 * ═════════════════════════════════════════════════════════════════════════════
 */

// ── SESSION SECURITY SETTINGS (A1-A5) ────────────────────────────────────────

// A1: Do not use session ID in URL (use cookies only)
ini_set('session.use_trans_sid', 0);

// A2: Use only cookies for sessions (no URL-based sessions)
ini_set('session.use_only_cookies', 1);

// A3: HttpOnly flag - prevent JavaScript access to cookies
ini_set('session.cookie_httponly', 1);

// A4: Secure flag - only send cookie over HTTPS (conditional for local dev)
// Set to 1 in production when HTTPS is enabled
$secure = (strpos(SITE_URL, 'https://') === 0) ? 1 : 0;
ini_set('session.cookie_secure', $secure);

// A5: SameSite attribute - prevent CSRF attacks
ini_set('session.cookie_samesite', 'Lax');

// Additional session security
ini_set('session.cookie_lifetime', SESSION_TIMEOUT);  // A7: Timeout
ini_set('session.gc_maxlifetime', SESSION_TIMEOUT);   // A7: Garbage collection

// ── START SESSION (A2) ───────────────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ── SESSION TIMEOUT & IDLE LOGOUT (A7, A8) ──────────────────────────────────
function checkSessionTimeout() {
    $timeout = SESSION_IDLE_TIMEOUT;
    
    if (isset($_SESSION['user_id'])) {
        // Check if session exists
        if (!isset($_SESSION['session_start_time'])) {
            // Session created without proper initialization - destroy it
            destroySession();
            return false;
        }
        
        $current_time = time();
        $session_duration = $current_time - $_SESSION['session_start_time'];
        
        // A7: Session timeout (max 30 minutes)
        if ($session_duration > SESSION_TIMEOUT) {
            destroySession();
            redirect('login.php?expired=session_timeout');
            return false;
        }
        
        // A8: Idle timeout (no activity in 30 minutes)
        if (isset($_SESSION['last_activity'])) {
            $idle_time = $current_time - $_SESSION['last_activity'];
            
            if ($idle_time > $timeout) {
                destroySession();
                redirect('login.php?expired=idle_timeout');
                return false;
            }
        }
        
        // Update last activity time
        $_SESSION['last_activity'] = $current_time;
        return true;
    }
    
    return false;
}

// ── SESSION INITIALIZATION (A6) ──────────────────────────────────────────────
/**
 * B6: ROLE DEFINITION
 * Sistem mendefinisikan role pengguna di sini.
 * Saat ini hanya implementasi role 'user' (pembeli/penjual).
 * Role 'admin' belum diimplementasikan - semua pengguna memiliki hak akses yang sama.
 * 
 * OWASP Compliance: PARTIAL (Role 'user' terdefinisi, Admin role belum aktif)
 */
function initializeSession($user_id, $email, $name, $role = 'user') {
    // A6: Regenerate session ID after login (prevent session fixation)
    session_regenerate_id(true);
    
    // Set session variables
    $_SESSION['user_id'] = intval($user_id);
    $_SESSION['email'] = sanitizeInput($email);
    $_SESSION['name'] = sanitizeInput($name);
    $_SESSION['role'] = sanitizeInput($role);
    $_SESSION['session_start_time'] = time();  // A7: Session start time
    $_SESSION['last_activity'] = time();       // A8: Last activity tracking
    
    // Log session creation
    logSecurityEvent('SESSION_CREATED', [
        'user_id' => $user_id,
        'email' => $email,
        'session_id' => session_id()
    ]);
}

// ── SESSION DESTRUCTION (A9) ────────────────────────────────────────────────
function destroySession() {
    // Log session destruction
    if (isset($_SESSION['user_id'])) {
        logSecurityEvent('SESSION_DESTROYED', [
            'user_id' => $_SESSION['user_id'],
            'session_id' => session_id()
        ]);
    }
    
    // A9: Destroy all session data
    $_SESSION = [];
    
    // Delete session cookie
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }
    
    // Destroy session
    session_destroy();
}

// ── HELPER FUNCTIONS ────────────────────────────────────────────────────────
function redirect($url) {
    header('Location: ' . $url);
    exit;
}

/**
 * B2: ACCESS CONTROL MODIFIER & B3 & B5: ACCESS VALIDATION
 * 
 * Sistem menggunakan arsitektur PROCEDURAL (bukan OOP), sehingga tidak ada access modifier kelas.
 * Kontrol akses diterapkan melalui:
 * 
 * 1. Session Validation   : Cek $_SESSION['user_id'] di setiap endpoint (B5)
 * 2. requireLogin()       : Validasi user sudah login & session valid (B3)
 * 3. Session Timeout      : Otomatis logout setelah 30 menit idle (A8)
 * 4. Session Regeneration: ID di-regenerate setelah login (A6)
 * 
 * OWASP Compliance: PARTIAL
 * - Access control diterapkan via session check (tidak ada access modifier class)
 * - Setiap endpoint protected memangggil requireLogin()
 * - Data user tidak bisa diakses tanpa session valid
 */
function requireLogin() {
    if (!isset($_SESSION['user_id'])) {
        redirect('login.php?require_login=1');
    }
    if (!checkSessionTimeout()) {
        return false;
    }
    return true;
}

?>
