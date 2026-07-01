<?php
// Database connection
date_default_timezone_set('Asia/Ho_Chi_Minh');

$host = getenv('DB_HOST') ?: 'db';
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASS') ?: 'root';
$name = getenv('DB_NAME') ?: 'connecthub';

$conn = new mysqli($host, $user, $pass, $name);
if ($conn->connect_error) {
    // VULN: exposes DB error details
    die("Connection failed: " . $conn->connect_error);
}
$conn->set_charset("utf8mb4");
$conn->query("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
$conn->query("SET time_zone = '+07:00'");

// VULN: Weak session config — no httponly, no secure, long lifetime
session_name('CONNECTHUB_SESSION');
$weak_session_fixed = false;
$session_rule = $conn->query("
    SELECT id
    FROM ai_fix_rules
    WHERE is_active=1 AND event_type='weak_session' AND route='/includes/db.php'
    LIMIT 1
");
if ($session_rule && $session_rule->num_rows > 0) {
    $weak_session_fixed = true;
}

if ($weak_session_fixed) {
    $is_https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', $is_https ? 1 : 0);
    ini_set('session.gc_maxlifetime', 1800);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $is_https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
} else {
    ini_set('session.cookie_httponly', 0);
    ini_set('session.cookie_secure', 0);
    ini_set('session.gc_maxlifetime', 99999);
}
session_start();

define('BASE_URL', 'http://localhost');
define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('UPLOAD_URL', BASE_URL . '/uploads/');

require_once __DIR__ . '/security.php';
ensure_admin_schema($conn);
enforce_ip_blocking($conn);
inspect_request_for_intrusion($conn);
enforce_ai_fix_rules($conn);
enforce_not_banned($conn);
enforce_single_session($conn);
?>
