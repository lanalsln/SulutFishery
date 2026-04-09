<?php
/**
 * ═════════════════════════════════════════════════════════════════════════════
 * CSRF & SECURITY FUNCTIONS
 * OWASP Security Best Practices: A03 (Injection), D (XSS), E (CSRF)
 * OWASP B: Authorization & Access Control
 * ═════════════════════════════════════════════════════════════════════════════
 */

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1: SECURITY HEADERS (I7 - Complete Security Headers)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * D4: CONTENT SECURITY POLICY (OWASP A03 — Injection/XSS Protection)
 * 
 * ⚠️ CURRENT IMPLEMENTATION: PERMISSIVE (for development)
 * 
 * Policy Breakdown:
 *   default-src 'self' https:
 *     → Only allow resources from same origin & HTTPS
 * 
 *   script-src 'self' 'unsafe-inline' 'unsafe-hashes' https://cdn.tailwindcss.com https://fonts.googleapis.com
 *     → Allow local scripts + inline scripts + inline event handlers (onclick="...")
 *     → Allow Tailwind CSS CDN + Google Fonts API
 * 
 *   style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com
 *     → Allow local styles + inline styles + Google Fonts + Tailwind
 * 
 *   img-src 'self' data: https:
 *     → Local images + data URIs (base64) + HTTPS external
 * 
 *   font-src 'self' https://fonts.gstatic.com
 *     → Local fonts + Google Fonts API
 * 
 * Why 'unsafe-inline'?
 * ────────────────────
 *   ✓ Tailwind CSS CDN compile at runtime → requires inline styles
 *   ✓ Inline event handlers (onclick="switchTab()") → requires 'unsafe-inline'
 *   ✓ This is a trade-off for development convenience vs strict XSS protection
 * 
 * ⚠️ SECURITY TRADE-OFF:
 *   - 'unsafe-inline' weakens XSS protection
 *   - BUT: input sanitization + escapeHTML() still protect against stored XSS
 *   - inline scripts only come from trusted sources (our code, not user input)
 * 
 * PRODUCTION RECOMMENDATIONS:
 * ──────────────────────────
 *   1. Build Tailwind with PostCSS (no inline styles needed)
 *      $ npm run build  (generates optimized .css)
 * 
 *   2. Move onclick handlers to external JS with nonce-based CSP
 *      Instead of: <button onclick="switchTab('dashboard')">
 *      Use: <button data-action="dashboard"> (then event listener in JS)
 * 
 *   3. Update CSP to stricter version:
 *      script-src 'self' 'nonce-RANDOM' https://cdn.tailwindcss.com
 *      style-src 'self' https://fonts.googleapis.com https://cdn.tailwindcss.com
 * 
 *   4. Verify at: https://securityheaders.com (target: A+ grade)
 * 
 * COMPLIANCE STATUS:
 * ──────────────────
 *   ✅ CSP header implemented
 *   ✅ XSS prevention via escapeHTML() + input sanitization
 *   ✅ Input validation (C1) active on all forms
 *   ⚠️  'unsafe-inline' weakens CSP strictness
 *       → Acceptable for development
 *       → Must improve for production
 */
function setSecurityHeaders() {
    // X-Content-Type-Options: Prevent MIME type sniffing
    header('X-Content-Type-Options: nosniff');
    
    // X-Frame-Options: Prevent clickjacking
    header('X-Frame-Options: SAMEORIGIN');
    
    // X-XSS-Protection: Legacy XSS protection (deprecated but still useful)
    header('X-XSS-Protection: 1; mode=block');
    
    // D4: Content Security Policy (PERMISSIVE for development, see doc above)
    header("Content-Security-Policy: default-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-hashes' https://cdn.tailwindcss.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' https: http:; media-src 'self' https:; frame-src 'self';");
    
    // Referrer Policy: Control referrer information
    header('Referrer-Policy: no-referrer-when-downgrade');
    
    // Permissions Policy: Disable dangerous APIs
    header("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()");
    
    // Prevent caching for sensitive pages
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2: CSRF PROTECTION (E1-E4)
// ═════════════════════════════════════════════════════════════════════════════

// E3: Generate unique CSRF token per session
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// E2: Verify CSRF token on server-side
function verifyCSRFToken($token) {
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    // Use hash_equals to prevent timing attacks
    return hash_equals($_SESSION['csrf_token'], $token);
}

// E1: Output CSRF token input for forms
function getCSRFTokenInput() {
    $token = generateCSRFToken();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3: INPUT VALIDATION & SANITIZATION (C1, D1)
// ═════════════════════════════════════════════════════════════════════════════

// C1: Sanitize input - remove dangerous characters
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    
    // D1: Escape HTML entities to prevent XSS
    $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    return trim($input);
}

// D1: Escape HTML for safe output (alias for htmlspecialchars)
function escapeHTML($input) {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

// C1: Validate email format
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// C1: Validate password strength
function validatePassword($password) {
    // Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special char
    return preg_match('/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/', $password);
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4: FILE UPLOAD VALIDATION (C4, C5)
// ═════════════════════════════════════════════════════════════════════════════

function validateFileUpload($file) {
    // C4: Validate file size
    if ($file['size'] > MAX_UPLOAD_SIZE) {
        return ['valid' => false, 'error' => 'File terlalu besar (max 5MB)'];
    }
    
    // C4: Validate MIME type
    if (!in_array($file['type'], ALLOWED_UPLOAD_TYPES)) {
        return ['valid' => false, 'error' => 'Tipe file tidak didukung'];
    }
    
    // C4: Check magic bytes (file signature) to verify file type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $real_mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($real_mime, ALLOWED_UPLOAD_TYPES)) {
        return ['valid' => false, 'error' => 'File tidak valid atau corrupted'];
    }
    
    return ['valid' => true];
}

// C5: Sanitize filename (remove dangerous characters)
function sanitizeFilename($filename) {
    // Remove path components
    $filename = basename($filename);
    
    // Remove special characters, keep only alphanumeric, dots, hyphens, underscores
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    
    // Prevent null bytes and directory traversal
    $filename = str_replace(['..', '/', '\\', "\0"], '', $filename);
    
    return $filename;
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 5: RATE LIMITING (Anti-Brute Force)
// ═════════════════════════════════════════════════════════════════════════════

function checkRateLimit($key, $max_attempts = 5, $time_window = 900) {
    if (!isset($_SESSION['rate_limit'])) {
        $_SESSION['rate_limit'] = [];
    }
    
    $now = time();
    
    if (!isset($_SESSION['rate_limit'][$key])) {
        $_SESSION['rate_limit'][$key] = ['count' => 1, 'first_attempt' => $now];
        return true;
    }
    
    $age = $now - $_SESSION['rate_limit'][$key]['first_attempt'];
    
    // Reset if time window has passed
    if ($age > $time_window) {
        $_SESSION['rate_limit'][$key] = ['count' => 1, 'first_attempt' => $now];
        return true;
    }
    
    // Check if max attempts exceeded
    if ($_SESSION['rate_limit'][$key]['count'] >= $max_attempts) {
        return false;
    }
    
    $_SESSION['rate_limit'][$key]['count']++;
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 6: UTILITY FUNCTIONS
// ═════════════════════════════════════════════════════════════════════════════

// Get client IP address
function getClientIP() {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];  // Cloudflare
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];  // Proxy
    } else {
        return $_SERVER['REMOTE_ADDR'];
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 7: AUTHORIZATION & ACCESS CONTROL (B1-B7)
// ═════════════════════════════════════════════════════════════════════════════

// B3: Check user permissions for resources
function canAccessResource($user_id, $resource_id, $resource_type = 'listing') {
    global $conn;
    
    // B5: Validate access on server-side
    switch ($resource_type) {
        case 'listing':
            // User can only access their own listings
            $stmt = $conn->prepare("SELECT user_id FROM posts WHERE id = ?");
            $stmt->bind_param("i", $resource_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                return false;
            }
            
            $row = $result->fetch_assoc();
            return intval($row['user_id']) === intval($user_id);
            
        case 'purchase':
            // User can only access their own purchases
            $stmt = $conn->prepare("SELECT user_id FROM purchases WHERE id = ?");
            $stmt->bind_param("i", $resource_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                return false;
            }
            
            $row = $result->fetch_assoc();
            return intval($row['user_id']) === intval($user_id);
            
        default:
            return false;
    }
}

// B6: Check user role
function hasRole($required_role) {
    if (!isset($_SESSION['role'])) {
        return false;
    }
    
    return $_SESSION['role'] === $required_role;
}

// B7: Prevent accessing other user's data
function preventCrossUserAccess($request_user_id, $current_user_id) {
    if (intval($request_user_id) !== intval($current_user_id)) {
        logSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', [
            'requested_user' => $request_user_id,
            'current_user' => $current_user_id,
            'ip_address' => getClientIP()
        ]);
        return false;
    }
    return true;
}

?>
