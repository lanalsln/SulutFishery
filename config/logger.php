<?php
/**
 * ═════════════════════════════════════════════════════════════════════════════
 * LOGGING & MONITORING SYSTEM
 * OWASP G: Logging and Monitoring, G1-G4: Security Event Logging
 * ═════════════════════════════════════════════════════════════════════════════
 */

// ═════════════════════════════════════════════════════════════════════════════
// SECURITY EVENTS LOGGING (G1, G2, G3)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Log security events (login, logout, failed attempts, unauthorized access)
 * G1: Login dan logout dicatat
 * G2: Percobaan login gagal dicatat
 * G3: Aktivitas admin dicatat
 * G4: Log disimpan aman dan tidak public
 */
function logSecurityEvent($event_type, $data = []) {
    $log_dir = __DIR__ . '/../logs/';
    
    // Ensure logs directory exists
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0755, true);
    }
    
    // G4: Store logs with timestamp per date
    $log_file = $log_dir . 'security_' . date('Y-m-d') . '.log';
    
    // Build log entry with full context
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'user_id' => isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : 'UNKNOWN',
        'ip_address' => getClientIP(),
        'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255),
        'data' => $data
    ];
    
    // G4: Write log in JSON format (easy to parse)
    $log_line = json_encode($log_entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
    
    // Write to file with file locking
    @file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
}

// ═════════════════════════════════════════════════════════════════════════════
// ACTIVITY LOGGING (G3 - Admin & User Activity)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Log user activities (CRUD operations)
 * G3: Aktivitas admin dicatat
 * G4: Log disimpan aman
 */
function logActivity($activity, $details = []) {
    $log_dir = __DIR__ . '/../logs/';
    
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0755, true);
    }
    
    // Activity logs by year-month
    $log_file = $log_dir . 'activity_' . date('Y-m') . '.log';
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'user_id' => isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null,
        'activity' => $activity,
        'ip_address' => getClientIP(),
        'details' => $details
    ];
    
    $log_line = json_encode($log_entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
    
    @file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
}

// ═════════════════════════════════════════════════════════════════════════════
// ERROR LOGGING (H1 - Hide errors from users, log for monitoring)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Log application errors
 * H1: Hide error details dari end-users tapi log untuk monitoring
 */
function logError($message, $context = []) {
    $log_dir = __DIR__ . '/../logs/';
    
    if (!is_dir($log_dir)) {
        @mkdir($log_dir, 0755, true);
    }
    
    $log_file = $log_dir . 'errors_' . date('Y-m-d') . '.log';
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'message' => $message,
        'file' => isset($context['file']) ? basename($context['file']) : 'UNKNOWN',
        'line' => $context['line'] ?? 'UNKNOWN',
        'ip_address' => getClientIP(),
        'user_id' => isset($_SESSION['user_id']) ? intval($_SESSION['user_id']) : null
    ];
    
    $log_line = json_encode($log_entry, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL;
    
    @file_put_contents($log_file, $log_line, FILE_APPEND | LOCK_EX);
}

// ═════════════════════════════════════════════════════════════════════════════
// LOG READING & ANALYSIS (G5 - Monitoring Scripts)
// ═════════════════════════════════════════════════════════════════════════════

/**
 * Get security events from log
 * G5: Monitoring log secara otomatis menggunakan Script
 */
function getSecurityLogs($date = null, $event_type = null) {
    $log_dir = __DIR__ . '/../logs/';
    
    if ($date === null) {
        $date = date('Y-m-d');
    }
    
    $log_file = $log_dir . 'security_' . $date . '.log';
    
    if (!file_exists($log_file)) {
        return [];
    }
    
    $logs = [];
    $lines = file($log_file, FILE_IGNORE_NEW_LINES);
    
    foreach ($lines as $line) {
        if (empty($line)) continue;
        
        $entry = json_decode($line, true);
        
        // Filter by event type if specified
        if ($event_type !== null && $entry['event_type'] !== $event_type) {
            continue;
        }
        
        $logs[] = $entry;
    }
    
    return $logs;
}

/**
 * Detect suspicious activity
 * G5: Automated monitoring - deteksi suspicious behavior
 */
function detectSuspiciousActivity($max_failed_logins = 5, $time_window_minutes = 15) {
    $suspicious_ips = [];
    
    // Get failed login attempts from today
    $logs = getSecurityLogs(date('Y-m-d'), 'LOGIN_FAILED');
    
    $now = time();
    $time_window = $time_window_minutes * 60;
    
    $ip_attempts = [];
    
    foreach ($logs as $log) {
        $log_time = strtotime($log['timestamp']);
        
        if ($now - $log_time > $time_window) {
            continue;  // Skip old attempts
        }
        
        $ip = $log['ip_address'];
        if (!isset($ip_attempts[$ip])) {
            $ip_attempts[$ip] = 0;
        }
        $ip_attempts[$ip]++;
    }
    
    // Mark IPs with too many failed attempts
    foreach ($ip_attempts as $ip => $count) {
        if ($count >= $max_failed_logins) {
            $suspicious_ips[] = [
                'ip_address' => $ip,
                'failed_attempts' => $count,
                'alert_level' => 'HIGH'
            ];
        }
    }
    
    return $suspicious_ips;
}

?>

