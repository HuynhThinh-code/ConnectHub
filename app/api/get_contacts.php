<?php
require_once '../includes/db.php';
header('Content-Type: application/json');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');

if (!isset($_SESSION['user_id'])) {
    echo json_encode([]);
    exit;
}

$me = (int)$_SESSION['user_id'];

$check_me = $conn->query("SELECT is_admin FROM users WHERE id=$me")->fetch_assoc();
$is_me_admin = !empty($check_me['is_admin']);

$admin_filter = "";
if (!$is_me_admin) {
    $admin_filter = "AND u.is_admin = 0";
}

// ===== VULN: IDOR — no strict ownership check on conversations =====
$result = $conn->query("
    SELECT
        u.id AS other_id,
        u.username,
        u.full_name,
        u.avatar,
        MAX(m.created_at) AS last_msg
    FROM messages m
    JOIN users u ON (
        (m.sender_id = $me AND u.id = m.receiver_id) OR
        (m.receiver_id = $me AND u.id = m.sender_id)
    )
    WHERE (m.sender_id = $me OR m.receiver_id = $me) $admin_filter
    GROUP BY u.id, u.username, u.full_name, u.avatar
    ORDER BY last_msg DESC
    LIMIT 10
");

$contacts = [];
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $contacts[] = $row;
    }
}

echo json_encode($contacts);
