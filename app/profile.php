<?php
require_once 'includes/db.php';
require_login();
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/profile.php');

// ===== VULN: IDOR — no authorization check, anyone can view any profile =====
// http://localhost/profile.php?id=1  → views admin profile
// http://localhost/profile.php?id=2  → views alice profile
$id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];

// VULN: no prepared statement
$result = $conn->query("SELECT * FROM users WHERE id = $id");
if (!$result || $result->num_rows === 0) {
    die("User not found");
}
$user = $result->fetch_assoc();

// ===== VULN: Private posts also visible on other users' profiles =====
$posts = $conn->query("SELECT * FROM posts WHERE user_id = $id ORDER BY created_at DESC");

// Friend status
$is_friend = false;
$pending   = false;
$me        = $_SESSION['user_id'];
$fr = $conn->query("SELECT * FROM friend_requests WHERE ((sender_id=$me AND receiver_id=$id) OR (sender_id=$id AND receiver_id=$me))");
if ($fr && $fr->num_rows > 0) {
    $f = $fr->fetch_assoc();
    if ($f['status'] === 'accepted') $is_friend = true;
    if ($f['status'] === 'pending')  $pending   = true;
}

// Handle friend request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['send_friend_request'])) {
    $conn->query("INSERT INTO friend_requests (sender_id, receiver_id) VALUES ($me, $id)");
    header("Location: profile.php?id=$id"); exit;
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="profile-layout">
    <div class="profile-header card">
        <div class="profile-cover"></div>
        <div class="profile-header-content">
            <img src="/uploads/<?= $user['avatar'] ?>" class="avatar-lg" style="margin-top: -60px; border: 4px solid #fff; box-shadow: var(--shadow-lg);">
            <div class="profile-info">
                <h2><?= htmlspecialchars($user['full_name']) ?> <?php if($user['is_admin']): ?><span class="badge-admin">Admin</span><?php endif; ?></h2>
                <p class="text-muted">@<?= htmlspecialchars($user['username']) ?></p>
                
                <!-- VULN: bio not escaped = Stored XSS vector -->
                <p class="profile-bio"><?= $xss_ai_fixed ? ai_safe_html($user['bio']) : $user['bio'] ?></p>
                
                <!-- VULN: email/sensitive fields exposed via IDOR -->
                <?php if ($id == $_SESSION['user_id'] || $_SESSION['is_admin']): ?>
                    <div class="profile-meta">
                        <span><i class="fas fa-envelope"></i> <?= htmlspecialchars($user['email']) ?></span>
                        <span><i class="fas fa-venus-mars"></i> <?= ($user['gender'] ?? 'male') === 'female' ? 'Female' : 'Male' ?></span>
                        <span><i class="fas fa-key"></i> OAuth Scope: <code><?= htmlspecialchars($user['oauth_scope']) ?></code></span>
                    </div>
                <?php endif; ?>
            </div>
            <div class="profile-actions">
                <?php if ($id != $_SESSION['user_id']): ?>
                    <?php if (!$user['is_admin'] || !empty($_SESSION['is_admin'])): ?>
                        <a href="messages.php?to=<?= $id ?>" class="btn btn-primary"><i class="fas fa-comment"></i> Message</a>
                    <?php endif; ?>
                    <?php if (!$is_friend && !$pending): ?>
                        <form method="POST" style="display:inline">
                            <button name="send_friend_request" class="btn btn-success"><i class="fas fa-user-plus"></i> Add Friend</button>
                        </form>
                    <?php elseif ($pending): ?>
                        <span class="btn btn-secondary">Request Pending</span>
                    <?php else: ?>
                        <span class="btn btn-success"><i class="fas fa-check"></i> Friends</span>
                    <?php endif; ?>
                <?php else: ?>
                    <a href="settings.php" class="btn btn-secondary"><i class="fas fa-user-gear"></i> Edit Profile</a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <div class="profile-posts">
        <h3>Posts (<?= $posts->num_rows ?>)</h3>
        <?php while ($post = $posts->fetch_assoc()): ?>
        <div class="post card <?= $post['is_private'] ? 'private-post' : '' ?>">
            <div class="post-header" style="margin-bottom: 8px;">
                <?php if ($post['is_private']): ?>
                    <span class="badge-private"><i class="fas fa-lock"></i> Private</span>
                <?php endif; ?>
                <span class="status-badge status-<?= htmlspecialchars($post['status']) ?>"><?= htmlspecialchars(ucfirst($post['status'])) ?></span>
                <small class="post-time"><i class="far fa-clock"></i> <?= $post['created_at'] ?></small>
            </div>
            <!-- VULN: Stored XSS — no output encoding -->
            <div class="post-content"><?= $xss_ai_fixed ? ai_safe_html($post['content']) : $post['content'] ?></div>
            <?php if ($post['image']): ?>
                <img src="/uploads/<?= htmlspecialchars($post['image']) ?>" class="post-image">
            <?php endif; ?>
        </div>
        <?php endwhile; ?>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
