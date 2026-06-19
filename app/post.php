<?php
require_once 'includes/db.php';
require_login();
$me = $_SESSION['user_id'];
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/post.php');

$post_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

// Add comment
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['comment'])) {
    $content = $_POST['comment'];
    $allowed = $conn->query("SELECT user_id, is_private, status FROM posts WHERE id=$post_id")->fetch_assoc();
    if (!$allowed) {
        die("Post not found");
    }
    log_if_suspicious_payload($conn, $content, 'Post comment content', 'post_id=' . $post_id);
    // VULN: Stored XSS — no sanitization
    if ($xss_ai_fixed) {
        $stmt = $conn->prepare("INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)");
        $stmt->bind_param("iis", $post_id, $me, $content);
        $stmt->execute();
    } else {
        $conn->query("INSERT INTO comments (post_id, user_id, content) VALUES ($post_id, $me, '$content')");
    }
    header("Location: post.php?id=$post_id"); exit;
}

// VULN: private post accessible without ownership check
$post = $conn->query("
    SELECT p.*, u.username, u.full_name, u.avatar
    FROM posts p JOIN users u ON p.user_id=u.id
    WHERE p.id=$post_id
")->fetch_assoc();

if (!$post) die("Post not found");
$comments = $conn->query("
    SELECT c.*, u.username, u.full_name, u.avatar
    FROM comments c JOIN users u ON c.user_id=u.id
    WHERE c.post_id=$post_id
    ORDER BY c.created_at ASC
");
?>
<?php require_once 'includes/header.php'; ?>
<div class="post-detail animate-fade-in">
    <div class="post card <?= $post['is_private'] ? 'private-post' : '' ?>">
        <div class="post-header">
            <img src="/uploads/<?= htmlspecialchars($post['avatar']) ?>" class="avatar-sm">
            <div>
                <a href="profile.php?id=<?= $post['user_id'] ?>"><strong><?= htmlspecialchars($post['full_name']) ?></strong></a>
                <span class="text-muted">@<?= htmlspecialchars($post['username']) ?></span>
                <?php if ($post['is_private']): ?>
                    <span class="badge-private"><i class="fas fa-lock"></i> Private</span>
                <?php endif; ?>
            </div>
            <small class="post-time"><i class="far fa-clock"></i> <?= $post['created_at'] ?></small>
        </div>
        <!-- VULN: Stored XSS -->
        <div class="post-content"><?= $xss_ai_fixed ? ai_safe_html($post['content']) : $post['content'] ?></div>
        <?php if ($post['image']): ?>
            <img src="/uploads/<?= htmlspecialchars($post['image']) ?>" class="post-image">
        <?php endif; ?>
    </div>

    <div class="comments-section card">
        <h3><i class="fas fa-comments" style="color: var(--primary); margin-right: 6px;"></i> Comments (<?= $comments->num_rows ?>)</h3>
        
        <?php if ($comments->num_rows === 0): ?>
            <p class="text-muted" style="text-align: center; margin: 20px 0;">No comments yet. Be the first to comment!</p>
        <?php endif; ?>

        <?php while ($c = $comments->fetch_assoc()): ?>
        <div class="comment">
            <img src="/uploads/<?= htmlspecialchars($c['avatar']) ?>" class="avatar-xs">
            <div class="comment-body">
                <strong><?= htmlspecialchars($c['full_name']) ?></strong>
                <span class="text-muted">@<?= htmlspecialchars($c['username']) ?></span>
                <!-- VULN: Stored XSS in comments -->
                <p><?= $xss_ai_fixed ? ai_safe_html($c['content']) : $c['content'] ?></p>
                <small class="text-muted"><i class="far fa-clock"></i> <?= $c['created_at'] ?></small>
            </div>
        </div>
        <?php endwhile; ?>

        <form method="POST" class="comment-form">
            <!-- VULN: no CSRF token -->
            <textarea name="comment" class="form-control" rows="2" placeholder="Write a comment..." required></textarea>
            <button type="submit" class="btn btn-primary btn-sm" style="height: fit-content; padding: 10px 18px;"><i class="fas fa-paper-plane"></i> Comment</button>
        </form>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
