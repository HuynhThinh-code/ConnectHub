<?php
require_once 'includes/db.php';
require_regular_user();

$uid = (int)$_SESSION['user_id'];
$user = $conn->query("SELECT * FROM users WHERE id=$uid")->fetch_assoc();
$stats = [
    'posts' => 0,
    'pending' => 0,
    'approved' => 0,
    'friends' => 0,
];

$res = $conn->query("SELECT COUNT(*) AS total, SUM(status='pending') AS pending, SUM(status='approved') AS approved FROM posts WHERE user_id=$uid");
if ($res) {
    $row = $res->fetch_assoc();
    $stats['posts'] = (int)$row['total'];
    $stats['pending'] = (int)$row['pending'];
    $stats['approved'] = (int)$row['approved'];
}

$res = $conn->query("SELECT COUNT(*) AS total FROM friend_requests WHERE status='accepted' AND (sender_id=$uid OR receiver_id=$uid)");
if ($res) {
    $stats['friends'] = (int)$res->fetch_assoc()['total'];
}

$my_posts = $conn->query("SELECT * FROM posts WHERE user_id=$uid ORDER BY created_at DESC LIMIT 6");
?>
<?php require_once 'includes/header.php'; ?>
<div class="user-dashboard">
    <section class="dashboard-hero card">
        <div>
            <span class="eyebrow">User Space</span>
            <h1>Welcome back, <?= htmlspecialchars($user['full_name'] ?: $user['username']) ?></h1>
            <p class="text-muted">Your personal ConnectHub area keeps your profile, posts, messages, and moderation status in one place.</p>
        </div>
        <div class="dashboard-actions">
            <a href="index.php" class="btn btn-primary"><i class="fas fa-house"></i> Open Feed</a>
            <a href="profile.php?id=<?= $uid ?>" class="btn btn-secondary"><i class="fas fa-user"></i> My Profile</a>
        </div>
    </section>

    <div class="stat-grid">
        <div class="stat-card">
            <i class="fas fa-newspaper"></i>
            <strong><?= $stats['posts'] ?></strong>
            <span>Total Posts</span>
        </div>
        <div class="stat-card">
            <i class="fas fa-clock"></i>
            <strong><?= $stats['pending'] ?></strong>
            <span>Waiting Review</span>
        </div>
        <div class="stat-card">
            <i class="fas fa-circle-check"></i>
            <strong><?= $stats['approved'] ?></strong>
            <span>Approved</span>
        </div>
        <div class="stat-card">
            <i class="fas fa-user-group"></i>
            <strong><?= $stats['friends'] ?></strong>
            <span>Friends</span>
        </div>
    </div>

    <div class="dashboard-grid">
        <section class="card">
            <h3><i class="fas fa-route"></i> Quick Access</h3>
            <div class="quick-links">
                <a href="messages.php"><i class="fas fa-paper-plane"></i> Messages</a>
                <a href="friends.php"><i class="fas fa-user-group"></i> Friends</a>
                <a href="search.php"><i class="fas fa-magnifying-glass"></i> Search People</a>
                <a href="settings.php"><i class="fas fa-sliders"></i> Settings</a>
            </div>
        </section>

        <section class="card">
            <h3><i class="fas fa-list-check"></i> My Recent Posts</h3>
            <?php if ($my_posts && $my_posts->num_rows > 0): ?>
                <div class="compact-list">
                    <?php while ($post = $my_posts->fetch_assoc()): ?>
                    <div class="compact-row">
                        <div>
                            <strong><?= htmlspecialchars(substr(strip_tags($post['content']), 0, 80)) ?><?= strlen(strip_tags($post['content'])) > 80 ? '...' : '' ?></strong>
                            <span><?= htmlspecialchars($post['created_at']) ?></span>
                        </div>
                        <span class="status-badge status-<?= htmlspecialchars($post['status']) ?>"><?= htmlspecialchars(ucfirst($post['status'])) ?></span>
                    </div>
                    <?php endwhile; ?>
                </div>
            <?php else: ?>
                <p class="text-muted">You have not shared any posts yet.</p>
            <?php endif; ?>
        </section>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
