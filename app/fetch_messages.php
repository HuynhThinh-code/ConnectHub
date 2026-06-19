<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { exit; }
$me = $_SESSION['user_id'];
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/fetch_messages.php');

$to = isset($_GET['to']) ? (int)$_GET['to'] : 0;
if (!$to) exit;

// Mark as read
$conn->query("UPDATE messages SET is_read=1 WHERE receiver_id=$to AND sender_id=$me");

$msgs = $conn->query("
    SELECT m.*, 
           u1.username as sender_name, u1.avatar as sender_avatar,
           u2.username as recv_name
    FROM messages m
    JOIN users u1 ON m.sender_id = u1.id
    JOIN users u2 ON m.receiver_id = u2.id
    WHERE (m.sender_id=$me AND m.receiver_id=$to)
       OR (m.sender_id=$to AND m.receiver_id=$me)
    ORDER BY m.created_at ASC
");

if ($msgs->num_rows === 0) {
    echo '<p class="text-muted" style="text-align: center; margin: 20px 0;">No messages in this chat. Start the conversation!</p>';
} else {
    while ($msg = $msgs->fetch_assoc()) {
        $class = ($msg['sender_id'] == $me) ? 'msg-sent' : 'msg-recv';
        // VULN: Stored XSS — raw output
        echo '<div class="message ' . $class . '">';
        echo '<div class="msg-bubble">' . ($xss_ai_fixed ? ai_safe_html($msg['content']) : $msg['content']) . '</div>';
        echo '<small class="msg-time"><i class="far fa-clock"></i> ' . $msg['created_at'] . '</small>';
        echo '</div>';
    }
}
?>
