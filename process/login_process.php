<?php
/**
 * PROCESS LOGIN
 * Handle login form submission
 */

require_once __DIR__ . '/../config.php';

$response = ['success' => false, 'message' => '', 'redirect' => ''];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $response['message'] = 'Invalid request method';
    echo json_encode($response);
    exit;
}

// CSRF Token Verification
if (!isset($_POST['csrf_token']) || !verifyCSRFToken($_POST['csrf_token'])) {
    $response['message'] = 'Security token expired. Please try again.';
    echo json_encode($response);
    exit;
}

$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';

// Validation
if (!$email || !$password) {
    $response['message'] = 'Email and password are required.';
    echo json_encode($response);
    exit;
}

if (!validateEmail($email)) {
    $response['message'] = 'Please enter a valid email address.';
    echo json_encode($response);
    exit;
}

// Rate limiting check (5 attempts per 15 minutes)
$rateLimitKey = 'login_' . getClientIP();
if (!checkRateLimit($rateLimitKey, 5, 900)) {
    $response['message'] = 'Too many login attempts. Please try again in 15 minutes.';
    logSecurityEvent('LOGIN_RATE_LIMIT', ['email' => $email]);
    echo json_encode($response);
    exit;
}

// Check user credentials using prepared statement
$stmt = $conn->prepare("SELECT id, name, password FROM users WHERE email = ? LIMIT 1");
if (!$stmt) {
    $response['message'] = 'Database error. Please try again later.';
    logSecurityEvent('LOGIN_DB_ERROR', ['email' => $email, 'error' => $conn->error]);
    echo json_encode($response);
    exit;
}

$stmt->bind_param('s', $email);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();

if ($user && password_verify($password, $user['password'])) {
    // Successful login
    // Regenerate session ID to prevent session fixation attack
    session_regenerate_id(true);
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_name'] = $user['name'];
    $_SESSION['user_email'] = $email;
    $_SESSION['last_activity'] = time();
    $_SESSION['login_time'] = time();
    
    logSecurityEvent('LOGIN_SUCCESS', ['email' => $email, 'user_id' => $user['id']]);
    logActivity('LOGIN', ['email' => $email]);
    
    $response['success'] = true;
    $response['message'] = 'Login successful!';
    $response['redirect'] = '../dashboard.php';
} else {
    // Failed login
    logSecurityEvent('LOGIN_FAILED', ['email' => $email, 'reason' => 'Invalid credentials']);
    logActivity('LOGIN_FAILED', ['email' => $email]);
    
    $response['message'] = 'Email or password is incorrect.';
}

echo json_encode($response);
?>
