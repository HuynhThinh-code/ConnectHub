<?php
require_once 'includes/db.php';
$error = '';

if (isset($_GET['banned'])) {
    $error = 'Your account has been banned. Please contact an administrator.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $weak_session_fixed = ai_fix_rule_active($conn, 'weak_session', '/includes/db.php');

    // ===== VULN: SQL Injection — no sanitization, no prepared statement =====
    log_if_suspicious_payload($conn, $username . "\n" . $password, 'Login form input', 'post_username=' . $username);
    if (ai_fix_rule_active($conn, 'sql_injection', '/login.php')) {
        $password_hash = md5($password);
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
        $stmt->bind_param("ss", $username, $password_hash);
        $stmt->execute();
        $result = $stmt->get_result();
    } else {
        $query = "SELECT * FROM users WHERE username = '$username' AND password = MD5('$password')";
        // Payload: username = admin' AND 1=1 #   password = anything
        $result = $conn->query($query);
    }

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (!empty($user['is_banned'])) {
            log_security_event($conn, 'banned_user_login', 'medium', 'Banned user attempted to log in', 'username=' . $username, $username);
            $error = 'Your account has been banned. Please contact an administrator.';
        } else {
        if ($weak_session_fixed) {
            session_regenerate_id(true);
        }
        $_SESSION['user_id']  = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['is_admin'] = $user['is_admin'];

        // ===== VULN: Weak session — token = MD5(username+time), stored in DB =====
        $token = $weak_session_fixed ? bin2hex(random_bytes(32)) : md5($user['username'] . time());
        $conn->query("UPDATE users SET session_token='$token' WHERE id={$user['id']}");
        if ($weak_session_fixed) {
            setcookie('remember_token', $token, [
                'expires' => time()+86400,
                'path' => '/',
                'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
                'httponly' => true,
                'samesite' => 'Lax',
            ]);
        } else {
            setcookie('remember_token', $token, time()+86400, '/', '', false, false);
        }

        log_security_event($conn, !empty($user['is_admin']) ? 'admin_login' : 'user_login', 'low', 'Successful login', 'username=' . $username, $username);
        header('Location: ' . (!empty($user['is_admin']) ? 'admin.php' : 'user.php'));
        exit;
        }
    } else {
        log_security_event($conn, 'failed_login', 'medium', 'Failed login attempt', 'username=' . $username, $username);
        // VULN: reveals whether username exists
        if (ai_fix_rule_active($conn, 'sql_injection', '/login.php')) {
            $check_stmt = $conn->prepare("SELECT id FROM users WHERE username=?");
            $check_stmt->bind_param("s", $username);
            $check_stmt->execute();
            $check = $check_stmt->get_result();
        } else {
            $check = $conn->query("SELECT id FROM users WHERE username='$username'");
        }
        $error = ($check && $check->num_rows > 0) ? 'Wrong password.' : 'User not found.';
    }
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="auth-box animate-fade-in">
    <h2><i class="fas fa-right-to-bracket"></i> Login</h2>
    <?php if ($error): ?>
        <div class="alert alert-danger">
            <i class="fas fa-triangle-exclamation"></i> <?= $error ?>
        </div>
    <?php endif; ?>
    <form method="POST">
        <div class="form-group">
            <label><i class="fas fa-user"></i> Username</label>
            <input type="text" name="username" class="form-control" required placeholder="Enter username">
        </div>
        <div class="form-group">
            <label><i class="fas fa-key"></i> Password</label>
            <div class="password-field">
                <input type="password" name="password" class="form-control" required placeholder="Enter password">
                <button type="button" class="password-toggle" aria-label="Show password" title="Show password"><i class="fas fa-eye"></i></button>
            </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 8px;"><i class="fas fa-right-to-bracket"></i> Login</button>
    </form>
    <p>Don't have an account? <a href="register.php">Register now</a></p>
    
    <div style="display: flex; align-items: center; margin: 24px 0 16px;">
        <hr style="flex: 1; border-top: 1px solid var(--border);">
        <span style="padding: 0 10px; font-size: 0.8rem; color: var(--muted); text-transform: uppercase; font-weight: 600;">Or login with</span>
        <hr style="flex: 1; border-top: 1px solid var(--border);">
    </div>
    
    <div style="display: flex; gap: 12px;">
        <a href="oauth.php?provider=github" class="btn btn-dark" style="flex: 1;"><i class="fab fa-github"></i> GitHub</a>
        <a href="oauth.php?provider=google" class="btn btn-danger" style="flex: 1;"><i class="fab fa-google"></i> Google</a>
    </div>
    
</div>
<?php require_once 'includes/footer.php'; ?>
