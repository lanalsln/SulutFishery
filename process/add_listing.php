<?php
/**
 * PROCESS ADD LISTING
 * Handle add new fish listing (for sale)
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
$product_name = sanitizeInput($_POST['product_name'] ?? '');
$category = sanitizeInput($_POST['category'] ?? '');
$location = sanitizeInput($_POST['location'] ?? '');
$quantity = (int)($_POST['quantity'] ?? 0);
$price = (float)($_POST['price'] ?? 0);
$description = sanitizeInput($_POST['description'] ?? '');

// Validation
if (!$product_name || strlen($product_name) < 3) {
    $response['message'] = 'Product name must be at least 3 characters.';
    echo json_encode($response);
    exit;
}

if (!$category) {
    $response['message'] = 'Please select a category.';
    echo json_encode($response);
    exit;
}

if (!$location) {
    $response['message'] = 'Location is required.';
    echo json_encode($response);
    exit;
}

if ($quantity <= 0) {
    $response['message'] = 'Quantity must be greater than 0.';
    echo json_encode($response);
    exit;
}

if ($price <= 0) {
    $response['message'] = 'Price must be greater than 0.';
    echo json_encode($response);
    exit;
}

// Handle file upload
$photo = null;
if (isset($_FILES['photo']) && $_FILES['photo']['error'] === UPLOAD_ERR_OK) {
    $upload_dir = __DIR__ . '/../uploads/';
    
    // Validate file
    $validate = validateFileUpload($_FILES['photo']);
    if (!$validate['valid']) {
        $response['message'] = $validate['error'];
        echo json_encode($response);
        exit;
    }
    
    // Ensure upload directory exists
    if (!is_dir($upload_dir)) {
        @mkdir($upload_dir, 0755, true);
    }
    
    // Generate unique filename
    $extension = pathinfo($_FILES['photo']['name'], PATHINFO_EXTENSION);
    $filename = 'product_' . uniqid() . '_' . time() . '.' . strtolower($extension);
    $filepath = $upload_dir . $filename;
    
    if (move_uploaded_file($_FILES['photo']['tmp_name'], $filepath)) {
        $photo = 'uploads/' . $filename;
    } else {
        $response['message'] = 'Failed to upload photo.';
        echo json_encode($response);
        exit;
    }
}

// Insert into database
$stmt = $conn->prepare("
    INSERT INTO posts (user_id, product_name, category, location, quantity_kg, price_per_kg, description, photo, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW(), NOW())
");

if (!$stmt) {
    $response['message'] = 'Database error. Please try again later.';
    echo json_encode($response);
    exit;
}

$status = 'active';
$stmt->bind_param('issidiss', $user_id, $product_name, $category, $location, $quantity, $price, $description, $photo);

if ($stmt->execute()) {
    $listing_id = $stmt->insert_id;
    $response['success'] = true;
    $response['message'] = 'Fish listing created successfully!';
    logActivity('LISTING_CREATED', ['listing_id' => $listing_id, 'product' => $product_name]);
} else {
    $response['message'] = 'Failed to create listing. Please try again.';
    logSecurityEvent('ADD_LISTING_FAILED', ['user_id' => $user_id, 'error' => $stmt->error]);
}

$stmt->close();
echo json_encode($response);
?>
