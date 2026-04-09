<?php
/**
 * PROCESS REGISTER
 * Handle register form submission
 */

require_once __DIR__ . '/../config.php';

$response = ['success' => false, 'message' => ''];

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

$name = sanitizeInput($_POST['name'] ?? '');
$email = sanitizeInput($_POST['email'] ?? '');
$phone = sanitizeInput($_POST['phone'] ?? '');
$password = $_POST['password'] ?? '';
$confirm = $_POST['confirm_password'] ?? '';

// Validation
if (!$name || strlen($name) < 3) {
    $response['message'] = 'Full name must be at least 3 characters.';
    echo json_encode($response);
    exit;
}

if (!validateEmail($email)) {
    $response['message'] = 'Please enter a valid email address.';
    echo json_encode($response);
    exit;
}

if (!preg_match('/^[0-9]{9,15}$/', str_replace(['-', ' ', '+'], '', $phone))) {
    $response['message'] = 'Phone number must be 9–15 digits.';
    echo json_encode($response);
    exit;
}

if (strlen($password) < 8) {
    $response['message'] = 'Password must be at least 8 characters.';
    echo json_encode($response);
    exit;
}

if ($password !== $confirm) {
    $response['message'] = 'Passwords do not match.';
    echo json_encode($response);
    exit;
}

// Check if email already exists
$stmt = $conn->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
if ($stmt) {
    $stmt->bind_param('s', $email);
    $stmt->execute();
    
    if ($stmt->get_result()->fetch_assoc()) {
        $response['message'] = 'Email already registered. Please use another email or login.';
        logSecurityEvent('REGISTER_DUPLICATE_EMAIL', ['email' => $email]);
        echo json_encode($response);
        $stmt->close();
        exit;
    }
    $stmt->close();
}

// Hash password with bcrypt
$hashed_password = password_hash($password, PASSWORD_BCRYPT);

// Insert new user
$stmt = $conn->prepare("INSERT INTO users (name, email, phone, password, created_at) VALUES (?, ?, ?, ?, NOW())");
if (!$stmt) {
    $response['message'] = 'Database error. Please try again later.';
    logSecurityEvent('REGISTER_DB_ERROR', ['email' => $email, 'error' => $conn->error]);
    echo json_encode($response);
    exit;
}

$stmt->bind_param('ssss', $name, $email, $phone, $hashed_password);

if ($stmt->execute()) {
    $response['success'] = true;
    $response['message'] = 'Account created successfully! You can now log in.';
    logSecurityEvent('REGISTER_SUCCESS', ['email' => $email, 'name' => $name]);
    logActivity('REGISTER', ['email' => $email, 'name' => $name]);
} else {
    $response['message'] = 'Failed to create account. Please try again.';
    logSecurityEvent('REGISTER_FAILED', ['email' => $email, 'error' => $stmt->error]);
}

$stmt->close();
echo json_encode($response);
?>
