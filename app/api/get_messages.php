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
// ===== VULN: IDOR — anyone can read any conversation by passing ?to=<victim_id> =====
$to      = isset($_GET['to'])      ? (int)$_GET['to']      : 0;
$last_id = isset($_GET['last_id']) ? (int)$_GET['last_id'] : 0;

if (!$to) {
    echo json_encode([]);
    exit;
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

echo json_encode($messages, JSON_UNESCAPED_UNICODE);
