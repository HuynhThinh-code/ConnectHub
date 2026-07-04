<?php
require_once '../includes/db.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit;
}

$me  = (int)$_SESSION['user_id'];
$idor_ai_fixed = ai_fix_rule_active($conn, 'idor_messages', '/api/get_messages.php');
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/api/get_messages.php');
// ===== VULN: IDOR — anyone can read any conversation by passing ?to=<victim_id> =====
$to      = isset($_GET['to'])      ? (int)$_GET['to']      : 0;
$last_id = isset($_GET['last_id']) ? (int)$_GET['last_id'] : 0;

if (!$to) {
    echo json_encode([]);
    exit;
}

if (!ai_message_access_allowed($conn, $me, $to)) {
    log_security_event($conn, 'idor_messages', 'high', 'API message read without an accepted friendship', 'to=' . $to);
}

if ($idor_ai_fixed && !ai_message_access_allowed($conn, $me, $to)) {
    http_response_code(403);
    echo json_encode([]);
    exit;
}

$check_me = $conn->query("SELECT is_admin FROM users WHERE id=$me")->fetch_assoc();
$is_me_admin = !empty($check_me['is_admin']);

if (!$is_me_admin) {
    $other_is_admin = $conn->query("SELECT is_admin FROM users WHERE id=$to")->fetch_assoc();
    if ($other_is_admin && !empty($other_is_admin['is_admin'])) {
        echo json_encode([]);
        exit;
    }
}

$messages = [];

if ($last_id === 0) {
    // Initial load: return the last 40 messages for this conversation
    $result = $conn->query("
        SELECT id, sender_id, content, created_at
        FROM messages
        WHERE (sender_id = $me AND receiver_id = $to)
           OR (sender_id = $to AND receiver_id = $me)
        ORDER BY id DESC
        LIMIT 40
    ");
    while ($row = $result->fetch_assoc()) {
        $messages[] = $row;
    }
    $messages = array_reverse($messages); // oldest first
} else {
    // Polling: only return messages newer than last_id
    $result = $conn->query("
        SELECT id, sender_id, content, created_at
        FROM messages
        WHERE ((sender_id = $me AND receiver_id = $to)
            OR (sender_id = $to AND receiver_id = $me))
          AND id > $last_id
        ORDER BY id ASC
    ");
    while ($row = $result->fetch_assoc()) {
        $messages[] = $row;
    }
}

if ($xss_ai_fixed) {
    $messages = ai_json_escape_messages($messages);
}

echo json_encode($messages, JSON_UNESCAPED_UNICODE);
