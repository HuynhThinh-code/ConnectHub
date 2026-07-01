<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$me = $_SESSION['user_id'];

// Accept/reject friend request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $req_id = (int)$_POST['req_id'];
    $action = $_POST['action'];
    // VULN: no check if this request belongs to $me
    if ($action === 'accept') {
        $conn->query("UPDATE friend_requests SET status='accepted' WHERE id=$req_id");
    } elseif ($action === 'reject') {
        $conn->query("UPDATE friend_requests SET status='rejected' WHERE id=$req_id");
    }
    header('Location: friends.php'); exit;
}

// Incoming requests
$requests = $conn->query("
    SELECT fr.id, fr.sender_id, u.username, u.full_name, u.avatar
    FROM friend_requests fr
    JOIN users u ON fr.sender_id = u.id
    WHERE fr.receiver_id=$me AND fr.status='pending'
");

// My friends
$friends = $conn->query("
    SELECT u.id, u.username, u.full_name, u.avatar
    FROM friend_requests fr
    JOIN users u ON u.id = CASE WHEN fr.sender_id=$me THEN fr.receiver_id ELSE fr.sender_id END
    WHERE (fr.sender_id=$me OR fr.receiver_id=$me) AND fr.status='accepted'
");

// Suggested users (not friends yet, exclude admin for regular users)
$admin_cond = "";
$check_me = $conn->query("SELECT is_admin FROM users WHERE id=$me")->fetch_assoc();
$is_me_admin = !empty($check_me['is_admin']);
if (!$is_me_admin) {
    $admin_cond = "AND u.is_admin = 0";
}

$suggested = $conn->query("
    SELECT u.id, u.username, u.full_name, u.avatar
    FROM users u
    WHERE u.id != $me $admin_cond
    AND u.id NOT IN (
        SELECT CASE WHEN sender_id=$me THEN receiver_id ELSE sender_id END
        FROM friend_requests
        WHERE sender_id=$me OR receiver_id=$me
    )
    LIMIT 6
");
?>
<?php require_once 'includes/header.php'; ?>
<div class="friends-page animate-fade-in">

    <?php if ($requests && $requests->num_rows > 0): ?>
    <div class="card">
        <h3><i class="fas fa-user-clock" style="color: var(--warning);"></i> Friend Requests (<?= $requests->num_rows ?>)</h3>
        <?php while ($req = $requests->fetch_assoc()): ?>
        <div class="friend-request-item">
            <img src="/uploads/<?= htmlspecialchars($req['avatar']) ?>" class="avatar-sm">
            <div>
                <strong><?= htmlspecialchars($req['full_name']) ?></strong>
                <span class="text-muted">@<?= htmlspecialchars($req['username']) ?></span>
            </div>
            <form method="POST" style="display:flex;gap:8px">
                <!-- VULN: no CSRF token -->
                <input type="hidden" name="req_id" value="<?= $req['id'] ?>">
                <button name="action" value="accept" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Accept</button>
                <button name="action" value="reject" class="btn btn-danger btn-sm"><i class="fas fa-xmark"></i> Reject</button>
            </form>
        </div>
        <?php endwhile; ?>
    </div>
    <?php endif; ?>

    <div class="card">
        <h3><i class="fas fa-user-group" style="color: var(--primary);"></i> My Friends</h3>
        <div class="friends-grid">
            <?php if ($friends->num_rows === 0): ?>
                <p class="text-muted" style="grid-column: 1 / -1; text-align: center; padding: 20px 0;">No friends yet. Find friends below!</p>
            <?php endif; ?>
            <?php while ($f = $friends->fetch_assoc()): ?>
            <div class="friend-card">
                <img src="/uploads/<?= htmlspecialchars($f['avatar']) ?>" class="avatar-md">
                <strong><?= htmlspecialchars($f['full_name']) ?></strong>
                <span class="text-muted">@<?= htmlspecialchars($f['username']) ?></span>
                <div class="friend-actions">
                    <a href="profile.php?id=<?= $f['id'] ?>" class="btn btn-sm btn-primary">Profile</a>
                    <a href="messages.php?to=<?= $f['id'] ?>" class="btn btn-sm btn-secondary">Chat</a>
                </div>
            </div>
            <?php endwhile; ?>
        </div>
    </div>

    <div class="card">
        <h3><i class="fas fa-compass" style="color: var(--accent);"></i> People You May Know</h3>
        <div class="friends-grid">
            <?php if ($suggested->num_rows === 0): ?>
                <p class="text-muted" style="grid-column: 1 / -1; text-align: center; padding: 20px 0;">No new suggestions available.</p>
            <?php endif; ?>
            <?php while ($s = $suggested->fetch_assoc()): ?>
            <div class="friend-card">
                <img src="/uploads/<?= htmlspecialchars($s['avatar']) ?>" class="avatar-md">
                <strong><?= htmlspecialchars($s['full_name']) ?></strong>
                <span class="text-muted">@<?= htmlspecialchars($s['username']) ?></span>
                <a href="profile.php?id=<?= $s['id'] ?>" class="btn btn-sm btn-success" style="width: 100%;"><i class="fas fa-user-plus"></i> Add Friend</a>
            </div>
            <?php endwhile; ?>
        </div>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
