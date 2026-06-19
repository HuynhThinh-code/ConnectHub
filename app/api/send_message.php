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
$to      = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : 0;
// VULN: content not sanitized = Stored XSS via messenger popup (real-time XSS demo)
$content = isset($_POST['content']) ? trim($_POST['content']) : '';

if (!$to || $content === '') {
    echo json_encode(['error' => 'missing_params']);
    exit;
}

// VULN: no CSRF token
log_if_suspicious_payload($conn, $content, 'Messenger popup content', 'receiver_id=' . $to);
$content = $conn->real_escape_string($content);
$conn->query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($me, $to, '$content')");
$new_id = $conn->insert_id;

echo json_encode(['status' => 'ok', 'message_id' => $new_id]);
