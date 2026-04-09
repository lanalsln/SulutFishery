<?php
/**
 * ═════════════════════════════════════════════════════════════════════════════
 * DATABASE CONNECTION & CONFIGURATION
 * OWASP C: Input Validation & Injection Protection
 * ═════════════════════════════════════════════════════════════════════════════
 */

// ── CREATE DATABASE CONNECTION ───────────────────────────────────────────────
// C2: Using mysqli with prepared statements (parameterized queries)
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// ── CHECK CONNECTION (H1) ────────────────────────────────────────────────────
if ($conn->connect_error) {
    // H1: Hide technical details from end-users in production
    if (DEBUG_MODE) {
        // Development: Show error details for debugging
        die("Database Connection Error: " . htmlspecialchars($conn->connect_error));
    } else {
        // Production: Show generic message
        die("Service temporarily unavailable. Please try again later.");
    }
}

// ── CHARACTER SET CONFIGURATION ──────────────────────────────────────────────
// Ensure UTF-8 encoding to prevent encoding attacks
$conn->set_charset("utf8mb4");

// ── PREPARE DATABASE FOR QUERIES ────────────────────────────────────────────
// Enable prepared statements (C2 - Protect against SQL Injection)
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

?>

