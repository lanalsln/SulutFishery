<?php
/**
 * PROCESS UPDATE LISTING
 * Handle update fish listing status/info
 */

require_once __DIR__ . '/../config.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Unauthorized']);
    exit;
}

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

$user_id = $_SESSION['user_id'];
$post_id = (int)($_POST['post_id'] ?? 0);
$status = sanitizeInput($_POST['status'] ?? '');

// Validation
if (!$post_id) {
    $response['message'] = 'Invalid listing ID.';
    echo json_encode($response);
    exit;
}

if (!in_array($status, ['active', 'sold', 'cancelled'])) {
    $response['message'] = 'Invalid status.';
    echo json_encode($response);
    exit;
}

// Check if listing belongs to current user
$stmt = $conn->prepare("SELECT id, photo FROM posts WHERE id = ? AND user_id = ? LIMIT 1");
if (!$stmt) {
    $response['message'] = 'Database error.';
    echo json_encode($response);
    exit;
}

$stmt->bind_param('ii', $post_id, $user_id);
$stmt->execute();
$listing = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$listing) {
    $response['message'] = 'Listing not found or you do not have permission to update it.';
    logSecurityEvent('UPDATE_LISTING_UNAUTHORIZED', ['user_id' => $user_id, 'post_id' => $post_id]);
    echo json_encode($response);
    exit;
}

// Update listing status
$stmt = $conn->prepare("UPDATE posts SET status = ?, updated_at = NOW() WHERE id = ? AND user_id = ?");
if (!$stmt) {
    $response['message'] = 'Database error. Please try again later.';
    echo json_encode($response);
    exit;
}

$stmt->bind_param('sii', $status, $post_id, $user_id);

if ($stmt->execute()) {
    $response['success'] = true;
    $response['message'] = 'Listing updated successfully!';
    logActivity('LISTING_UPDATED', ['listing_id' => $post_id, 'new_status' => $status]);
} else {
    $response['message'] = 'Failed to update listing. Please try again.';
    logSecurityEvent('UPDATE_LISTING_FAILED', ['user_id' => $user_id, 'post_id' => $post_id, 'error' => $stmt->error]);
}

$stmt->close();
echo json_encode($response);
?>
