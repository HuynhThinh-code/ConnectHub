<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$me = $_SESSION['user_id'];
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/messages.php');

// Send message
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['send']) || isset($_POST['content']))) {
    $to      = (int)$_POST['receiver_id'];
    // VULN: content not sanitized = Stored XSS in messages
    $raw_content = $_POST['content'];
    log_if_suspicious_payload($conn, $raw_content, 'Chat message content', 'receiver_id=' . $to);
    $content = $conn->real_escape_string($raw_content);
    $conn->query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($me, $to, '$content')");
    if (isset($_POST['ajax'])) exit;
    header("Location: messages.php?to=$to"); exit;
}

// ===== VULN: IDOR — read any conversation by changing ?to= parameter =====
// http://localhost/messages.php?to=1  → reads admin's messages
// No check: are you part of this conversation?
$to = isset($_GET['to']) ? (int)$_GET['to'] : 0;

if ($to) {
    // Mark as read — VULN: marks messages of any user read
    $conn->query("UPDATE messages SET is_read=1 WHERE receiver_id=$to AND sender_id=$me");

    // ===== VULN: IDOR — fetches messages between $me and $to but no ownership check =====
    // Attacker can read messages between user 2 and user 3 by setting to=2 while logged as user 4
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

    $other_user = $conn->query("SELECT * FROM users WHERE id=$to")->fetch_assoc();
}

// Get inbox conversations
$inbox = $conn->query("
    SELECT DISTINCT
        CASE WHEN sender_id=$me THEN receiver_id ELSE sender_id END as other_id,
        u.username, u.avatar, u.full_name,
        MAX(m.created_at) as last_msg
    FROM messages m
    JOIN users u ON u.id = CASE WHEN m.sender_id=$me THEN m.receiver_id ELSE m.sender_id END
    WHERE m.sender_id=$me OR m.receiver_id=$me
    GROUP BY other_id, u.username, u.avatar, u.full_name
    ORDER BY last_msg DESC
");
?>
<?php require_once 'includes/header.php'; ?>
<div class="messages-layout animate-fade-in">
    <!-- Inbox sidebar -->
    <div class="inbox-list card">
        <h3><i class="fas fa-inbox" style="color: var(--primary); margin-right: 6px;"></i> Inbox</h3>
        <?php if ($inbox->num_rows === 0): ?>
            <p class="text-muted" style="padding: 12px; text-align: center;">No messages yet.</p>
        <?php endif; ?>
        <?php while ($conv = $inbox->fetch_assoc()): ?>
        <a href="messages.php?to=<?= $conv['other_id'] ?>" class="inbox-item <?= ($to == $conv['other_id']) ? 'active' : '' ?>">
            <img src="/uploads/<?= htmlspecialchars($conv['avatar']) ?>" class="avatar-sm">
            <div>
                <strong><?= htmlspecialchars($conv['full_name']) ?></strong>
                <small class="text-muted">@<?= htmlspecialchars($conv['username']) ?></small>
            </div>
        </a>
        <?php endwhile; ?>
    </div>

    <!-- Chat window -->
    <div class="chat-window card">
        <?php if ($to && $other_user): ?>
            <div class="chat-header">
                <img src="/uploads/<?= htmlspecialchars($other_user['avatar']) ?>" class="avatar-sm">
                <div>
                    <strong><?= htmlspecialchars($other_user['full_name']) ?></strong>
                    <a href="profile.php?id=<?= $to ?>" class="text-muted">@<?= htmlspecialchars($other_user['username']) ?></a>
                </div>
            </div>
            <div class="chat-messages" id="chatBox">
                <?php if ($msgs->num_rows === 0): ?>
                    <p class="text-muted" style="text-align: center; margin: 20px 0;">No messages in this chat. Start the conversation!</p>
                <?php endif; ?>
                <?php while ($msg = $msgs->fetch_assoc()): ?>
                <div class="message <?= ($msg['sender_id'] == $me) ? 'msg-sent' : 'msg-recv' ?>">
                    <!-- ===== VULN: Stored XSS — raw output ===== -->
                    <div class="msg-bubble"><?= $xss_ai_fixed ? ai_safe_html($msg['content']) : $msg['content'] ?></div>
                    <small class="msg-time"><i class="far fa-clock"></i> <?= $msg['created_at'] ?></small>
                </div>
                <?php endwhile; ?>
            </div>
            <form method="POST" class="chat-input" id="chatForm">
                <!-- VULN: no CSRF token -->
                <input type="hidden" name="receiver_id" value="<?= $to ?>">
                <input type="hidden" name="ajax" value="1">
                <input type="text" name="content" id="chatInput" class="form-control" placeholder="Type a message..." required autocomplete="off">
                <button type="submit" name="send" class="btn btn-primary" aria-label="Send Message"><i class="fas fa-paper-plane"></i></button>
            </form>
        <?php else: ?>
            <div class="no-chat">
                <i class="fas fa-comments fa-3x"></i>
                <p>Select a conversation from the sidebar or <a href="friends.php" style="font-weight: 600;">find friends</a> to chat.</p>
            </div>
        <?php endif; ?>
    </div>
</div>
<script>
// Auto scroll to bottom of chat
var chatBox = document.getElementById('chatBox');
if (chatBox) chatBox.scrollTop = chatBox.scrollHeight;

<?php if (isset($to) && $to): ?>
// Real-time messages polling
setInterval(function() {
    fetch('fetch_messages.php?to=<?= $to ?>')
        .then(res => res.text())
        .then(html => {
            var isAtBottom = chatBox.scrollHeight - chatBox.scrollTop <= chatBox.clientHeight + 50;
            chatBox.innerHTML = html;
            if (isAtBottom) chatBox.scrollTop = chatBox.scrollHeight;
        });
}, 2000);

// AJAX form submission
var chatForm = document.getElementById('chatForm');
if (chatForm) {
    chatForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var formData = new FormData(chatForm);
        formData.append('send', '1');
        
        fetch('messages.php?to=<?= $to ?>', {
            method: 'POST',
            body: formData
        }).then(() => {
            document.getElementById('chatInput').value = '';
            // Immediately fetch messages after send
            fetch('fetch_messages.php?to=<?= $to ?>')
                .then(res => res.text())
                .then(html => {
                    chatBox.innerHTML = html;
                    chatBox.scrollTop = chatBox.scrollHeight;
                });
        });
    });
}
<?php endif; ?>
</script>
<?php require_once 'includes/footer.php'; ?>
