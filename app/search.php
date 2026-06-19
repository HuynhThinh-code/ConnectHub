<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }

$results = [];
$query_str = '';
$sql_ai_fixed = ai_fix_rule_active($conn, 'sql_injection', '/search.php');
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/search.php');

if (isset($_GET['q']) && $_GET['q'] !== '') {
    $query_str = $_GET['q'];

    if ($sql_ai_fixed) {
        $like = '%' . $query_str . '%';
        $stmt = $conn->prepare("SELECT id, username, full_name, bio, avatar FROM users WHERE username LIKE ? OR full_name LIKE ?");
        $stmt->bind_param("ss", $like, $like);
        $stmt->execute();
        $res = $stmt->get_result();
    } else {
        // VULN LAB: SQL Injection in user search when AI Fix is not trained for this route.
        $sql = "SELECT id, username, full_name, bio, avatar FROM users WHERE username LIKE '%$query_str%' OR full_name LIKE '%$query_str%'";
        $res = $conn->query($sql);
    }

    if ($res) {
        while ($row = $res->fetch_assoc()) $results[] = $row;
    }
}

$display_query = $xss_ai_fixed ? htmlspecialchars($query_str) : $query_str;
?>
<?php require_once 'includes/header.php'; ?>
<div class="search-page animate-fade-in">
    <div class="card">
        <h2><i class="fas fa-magnifying-glass" style="color: var(--primary); margin-right: 6px;"></i> Search Users</h2>
        <form method="GET" class="search-form">
            <input type="text" name="q" class="form-control"
                   placeholder="Search by username or name..."
                   value="<?= $display_query ?>">
            <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Search</button>
        </form>

        <?php if ($query_str): ?>
        <p style="margin-bottom: 16px; font-size: 0.95rem;">Results for: <strong style="color: var(--primary);"><?= $display_query ?></strong></p>
        <?php endif; ?>

        <?php if (!empty($results)): ?>
        <div class="user-list">
            <?php foreach ($results as $u): ?>
            <div class="user-card">
                <img src="/uploads/<?= htmlspecialchars($u['avatar']) ?>" class="avatar-sm">
                <div>
                    <strong><?= htmlspecialchars($u['full_name']) ?></strong>
                    <span class="text-muted">@<?= htmlspecialchars($u['username']) ?></span>
                    <p class="text-muted" style="margin-top: 4px;"><?= $xss_ai_fixed ? htmlspecialchars($u['bio']) : $u['bio'] ?></p>
                </div>
                <a href="profile.php?id=<?= (int)$u['id'] ?>" class="btn btn-sm btn-primary">View Profile</a>
            </div>
            <?php endforeach; ?>
        </div>
        <?php elseif ($query_str): ?>
        <p class="text-muted" style="text-align: center; margin: 20px 0;"><i class="fas fa-face-frown fa-2x" style="display: block; margin-bottom: 8px; color: var(--muted);"></i> No users found matching your search.</p>
        <?php endif; ?>
    </div>
</div>
<?php require_once 'includes/footer.php'; ?>
