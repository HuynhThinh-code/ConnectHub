<?php
require_once 'includes/db.php';

// ===== VULN: OAuth Scope Escalation =====
// This simulates OAuth flow with intentional flaws:
// 1. Scope parameter from user request is trusted without validation
// 2. No state parameter = CSRF on OAuth flow
// 3. Token stored insecurely, scope not enforced server-side

$provider = $_GET['provider'] ?? 'github';
$code     = $_GET['code']     ?? null;
$scope    = $_GET['scope']    ?? 'read';  // VULN: user-supplied scope
$error    = '';
$oauth_ai_fixed = ai_fix_rule_active($conn, 'oauth_scope_escalation', '/oauth.php');

// Simulate OAuth callback (in real lab, configure real OAuth app)
// For demo: auto-login as a test OAuth user
if ($code || isset($_GET['simulate'])) {

    // ===== VULN: Scope escalation =====
    // Normal: scope=read (read-only access)
    // Attacker: scope=admin or scope=read,write,admin
    // Server accepts whatever scope client requests
    $allowed_scopes = $oauth_ai_fixed ? ['read', 'user:email'] : ['read', 'write', 'admin', 'delete', 'user:email', 'repo'];
    $requested_scopes = array_filter(array_map('trim', explode(',', $scope)));
    $granted = array_values(array_intersect($requested_scopes ?: ['read'], $allowed_scopes));
    $granted_scope = implode(',', $granted ?: ['read']);

    // Simulate getting user info from OAuth provider
    $oauth_id   = 'oauth_' . $provider . '_12345';
    $oauth_user = [
        'username'  => 'oauth_' . $provider . '_user',
        'email'     => 'oauth@' . $provider . '.example.com',
        'full_name' => 'OAuth User (' . $provider . ')',
    ];

    // Check if OAuth user exists
    $existing = $conn->query("SELECT * FROM users WHERE oauth_id='$oauth_id' AND oauth_provider='$provider'");

    if ($existing && $existing->num_rows > 0) {
        $user = $existing->fetch_assoc();
        // VULN: update scope to whatever was requested
        $conn->query("UPDATE users SET oauth_scope='$granted_scope' WHERE id={$user['id']}");
    } else {
        // Register new OAuth user
        $conn->query("INSERT INTO users (username, email, full_name, password, oauth_provider, oauth_id, oauth_scope)
                      VALUES ('{$oauth_user['username']}', '{$oauth_user['email']}', '{$oauth_user['full_name']}',
                              MD5(RAND()), '$provider', '$oauth_id', '$granted_scope')");
        $user = $conn->query("SELECT * FROM users WHERE oauth_id='$oauth_id'")->fetch_assoc();
    }

    if (!empty($user['is_banned'])) {
        log_security_event($conn, 'banned_oauth_login', 'medium', 'Banned user attempted OAuth login', 'provider=' . $provider);
        header('Location: login.php?banned=1');
        exit;
    }
    if (strpos($scope, 'admin') !== false || strpos($scope, 'delete') !== false) {
        log_security_event($conn, 'oauth_scope_escalation', 'high', 'OAuth login requested elevated scope', 'provider=' . $provider . '&scope=' . $granted_scope);
    }

    $_SESSION['user_id']  = $user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['is_admin'] = $user['is_admin'];
    $_SESSION['oauth_scope'] = $granted_scope;

    $weak_session_fixed = ai_fix_rule_active($conn, 'weak_session', '/includes/db.php');
    $token = $weak_session_fixed ? bin2hex(random_bytes(32)) : md5($user['username'] . time());
    $_SESSION['session_token'] = $token;
    $conn->query("UPDATE users SET session_token='$token' WHERE id={$user['id']}");

    header('Location: ' . (!empty($user['is_admin']) ? 'admin.php' : 'user.php')); exit;
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="auth-box animate-fade-in" style="max-width: 480px;">
    <h2 style="color: <?= $provider === 'github' ? '#2D3436' : '#D63031' ?>;">
        <i class="fab fa-<?= htmlspecialchars($provider) ?>"></i> OAuth Login — <?= ucfirst(htmlspecialchars($provider)) ?>
    </h2>
    <p class="text-muted" style="margin-bottom: 20px;">Simulating connection to <strong><?= ucfirst(htmlspecialchars($provider)) ?></strong> secure authorization server...</p>

    <!-- ===== VULN: Scope parameter exposed and user-controllable ===== -->
    <!-- Normal flow: oauth.php?provider=github&scope=read -->
    <!-- Attack:      oauth.php?provider=github&scope=admin -->
    <form method="GET" style="margin-bottom: 20px;">
        <input type="hidden" name="provider" value="<?= htmlspecialchars($provider) ?>">
        <input type="hidden" name="simulate" value="1">
        <div class="form-group">
            <label style="font-weight: 600;"><i class="fas fa-eye"></i> Requested Scope <span style="color: var(--primary); font-size: 0.75rem;">(VULN: User Controlled)</span></label>
            <select name="scope" class="form-control" style="font-weight: 500;">
                <option value="read">read (normal access)</option>
                <option value="read,write">read,write (elevated access)</option>
                <option value="admin">admin (escalated privilege!)</option>
                <option value="read,write,admin,delete">Full access (maximum escalation)</option>
            </select>
        </div>
        <!-- VULN: no state parameter = CSRF vulnerable -->
        <button type="submit" class="btn btn-primary" style="width: 100%;"><i class="fas fa-shield-halved"></i> Authorize & Login</button>
    </form>

    <details class="vuln-hint">
        <summary><i class="fas fa-lightbulb"></i> Lab Hint — OAuth Scope Escalation</summary>
        <div style="margin-top: 10px;">
            <ul>
                <li>Intercept OAuth request in Burp Suite</li>
                <li>Change <code>scope=read</code> to <code>scope=admin</code></li>
                <li>Server grants admin scope without validation</li>
                <li>Also: no <code>state</code> parameter = CSRF attack possible</li>
            </ul>
        </div>
    </details>
</div>
<?php require_once 'includes/footer.php'; ?>
