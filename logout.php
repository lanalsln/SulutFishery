<?php
require_once 'config.php';

// Log logout event
if (isset($_SESSION['user_id'])) {
    logSecurityEvent('LOGOUT', ['user_id' => $_SESSION['user_id']]);
    logActivity('LOGOUT', ['user_id' => $_SESSION['user_id']]);
}

// Clear all session variables
$_SESSION = [];

// Clear session cookies properly
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

// Destroy session
session_destroy();

// No-cache headers
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header('Location: login.php');
exit;