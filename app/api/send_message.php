<?php
require_once '../includes/db.php';
header('Content-Type: application/json; charset=utf-8');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['error' => 'unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'method_not_allowed']);
    exit;
}

$me      = (int)$_SESSION['user_id'];
$idor_ai_fixed = ai_fix_rule_active($conn, 'idor_messages', '/api/send_message.php');
$to      = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : 0;
// VULN: content not sanitized = Stored XSS via messenger popup (real-time XSS demo)
$content = isset($_POST['content']) ? trim($_POST['content']) : '';

if (!$to || $content === '') {
    echo json_encode(['error' => 'missing_params']);
    exit;
}

if (!ai_message_access_allowed($conn, $me, $to)) {
    log_security_event($conn, 'idor_messages', 'high', 'API message send without an accepted friendship', 'to=' . $to);
}

if ($idor_ai_fixed && !ai_message_access_allowed($conn, $me, $to)) {
    http_response_code(403);
    echo json_encode(['error' => 'forbidden_conversation']);
    exit;
}

$check_me = $conn->query("SELECT is_admin FROM users WHERE id=$me")->fetch_assoc();
$is_me_admin = !empty($check_me['is_admin']);

if (!$is_me_admin) {
    $other_is_admin = $conn->query("SELECT is_admin FROM users WHERE id=$to")->fetch_assoc();
    if ($other_is_admin && !empty($other_is_admin['is_admin'])) {
        echo json_encode(['error' => 'forbidden_admin_chat']);
        exit;
    }
}

// VULN: no CSRF token
log_if_suspicious_payload($conn, $content, 'Messenger popup content', 'receiver_id=' . $to);
$content = $conn->real_escape_string($content);
$conn->query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($me, $to, '$content')");
$new_id = $conn->insert_id;

echo json_encode(['status' => 'ok', 'message_id' => $new_id]);
