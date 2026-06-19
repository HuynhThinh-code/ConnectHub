<?php
$current_page = basename($_SERVER['SCRIPT_NAME']);
function is_active($page, $current_page) {
    return $current_page === $page ? 'active' : '';
}
$is_admin_session = !empty($_SESSION['is_admin']);
$home_url = isset($_SESSION['user_id']) ? ($is_admin_session ? '/admin.php' : '/user.php') : '/index.php';

$header_user = null;
if (isset($_SESSION['user_id'])) {
    $header_uid = (int)$_SESSION['user_id'];
    $header_res = $conn->query("SELECT avatar, full_name, username FROM users WHERE id = $header_uid");
    if ($header_res && $header_res->num_rows > 0) {
        $header_user = $header_res->fetch_assoc();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ConnectHub — Modern Social Platform</title>
    <meta name="description" content="ConnectHub is a modern social media platform for connecting with friends, sharing thoughts, and messaging.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/css/style.css?v=1.1">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
<nav class="navbar">
    <div class="nav-brand">
        <a href="<?= $home_url ?>"><i class="fas fa-share-nodes"></i> ConnectHub</a>
    </div>
    
    <?php if (isset($_SESSION['user_id'])): ?>
        <button class="mobile-menu-btn" id="mobileMenuBtn" aria-label="Toggle Navigation">
            <i class="fas fa-bars"></i>
        </button>
    <?php endif; ?>

    <div class="nav-links" id="navLinks">
        <?php if (isset($_SESSION['user_id'])): ?>
            <?php if ($is_admin_session): ?>
                <a href="/admin.php" class="<?= is_active('admin.php', $current_page) ?>"><i class="fas fa-gauge-high"></i> Admin</a>
                <a href="/admin.php#posts"><i class="fas fa-list-check"></i> Posts</a>
                <a href="/admin.php#users"><i class="fas fa-users-gear"></i> Users</a>
                <a href="/admin.php#security"><i class="fas fa-shield-halved"></i> Security</a>
            <?php else: ?>
                <a href="/user.php" class="<?= is_active('user.php', $current_page) ?>"><i class="fas fa-user"></i> My Space</a>
                <a href="/index.php" class="<?= is_active('index.php', $current_page) ?>"><i class="fas fa-house"></i> Feed</a>
                <a href="/search.php" class="<?= is_active('search.php', $current_page) ?>"><i class="fas fa-magnifying-glass"></i> Search</a>
                <a href="/messages.php" class="<?= is_active('messages.php', $current_page) ?>"><i class="fas fa-paper-plane"></i> Messages</a>
                <a href="/friends.php" class="<?= is_active('friends.php', $current_page) ?>"><i class="fas fa-user-group"></i> Friends</a>
                <a href="/profile.php?id=<?= (int)$_SESSION['user_id'] ?>" class="<?= is_active('profile.php', $current_page) ?>">
                    <?php if ($header_user && $header_user['avatar']): ?>
                        <img src="/uploads/<?= htmlspecialchars($header_user['avatar']) ?>" class="avatar-xs" style="margin: -5px 0; border-color: rgba(255,255,255,0.8);">
                    <?php else: ?>
                        <i class="fas fa-user"></i>
                    <?php endif; ?>
                    Profile
                </a>
                <a href="/settings.php" class="<?= is_active('settings.php', $current_page) ?>"><i class="fas fa-sliders"></i> Settings</a>
            <?php endif; ?>
            <a href="/logout.php"><i class="fas fa-right-from-bracket"></i> Logout</a>
        <?php else: ?>
            <a href="/login.php" class="<?= is_active('login.php', $current_page) ?>"><i class="fas fa-right-to-bracket"></i> Login</a>
            <a href="/register.php" class="<?= is_active('register.php', $current_page) ?>"><i class="fas fa-user-plus"></i> Register</a>
        <?php endif; ?>
    </div>
</nav>
<div class="container">
