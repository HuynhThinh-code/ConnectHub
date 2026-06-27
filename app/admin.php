<?php
require_once 'includes/db.php';
require_admin();

$admin_id = (int)$_SESSION['user_id'];
$message = $error = '';

function admin_event_time($value) {
    if (!$value) return '';
    return date('d/m/Y H:i:s', strtotime($value));
}

function admin_event_actor($event) {
    if (!empty($event['actor_name'])) return $event['actor_name'];
    if (!empty($event['actor_username'])) return $event['actor_username'];
    if (!empty($event['username'])) return $event['username'];
    if (!empty($event['payload']) && preg_match('/(?:username|post_username)=([^\r\n&]+)/i', $event['payload'], $m)) {
        return trim($m[1]);
    }
    return 'Guest';
}

function admin_event_label($type) {
    $labels = [
        'admin_login' => 'Admin login',
        'user_login' => 'User login',
        'failed_login' => 'Failed login',
        'banned_user_login' => 'Banned login blocked',
        'banned_oauth_login' => 'Banned OAuth blocked',
        'oauth_scope_escalation' => 'OAuth scope escalation',
        'private_disclosure' => 'Private disclosure',
        'idor_messages' => 'Message IDOR',
        'weak_session' => 'Weak session',
        'avatar_upload_bypass' => 'Avatar upload bypass',
        'sql_injection' => 'SQL Injection',
        'xss_probe' => 'XSS / Stored Script',
        'path_traversal' => 'Path Traversal',
        'command_injection' => 'Command Injection',
        'ssrf_probe' => 'SSRF / Internal Access',
    ];
    return $labels[$type] ?? ucwords(str_replace('_', ' ', $type));
}

function admin_event_payload($payload) {
    $payload = trim((string)$payload);
    return $payload === '' ? 'No payload captured' : substr($payload, 0, 420);
}

function admin_ai_fix_summary($type) {
    $fixes = [
        'sql_injection' => 'AI Fix: kich hoat rule chan SQLi tren route nay, dong thoi de xuat chuyen cau lenh SQL sang prepared statements va rang buoc kieu du lieu dau vao.',
        'xss_probe' => 'AI Fix: kich hoat rule chan XSS tren route nay, dong thoi de xuat escape output bang htmlspecialchars, lam sach HTML nguoi dung nhap va them CSP.',
        'path_traversal' => 'AI Fix: kich hoat rule chan path traversal tren route nay, dong thoi de xuat chuan hoa duong dan va chi cho phep file trong allowlist.',
        'command_injection' => 'AI Fix: kich hoat rule chan command injection tren route nay, dong thoi de xuat khong ghep input vao shell command va dung escapeshellarg khi bat buoc.',
        'ssrf_probe' => 'AI Fix: kich hoat rule chan SSRF tren route nay, dong thoi de xuat chi cho phep URL http/https tu domain hop le va chan IP noi bo.',
        'oauth_scope_escalation' => 'AI Fix: kich hoat rule chan scope escalation tren route nay, dong thoi de xuat xac thuc scope o server va rang buoc state/redirect_uri.',
        'private_disclosure' => 'AI Fix: loc private posts theo quyen xem, chi chu bai viet hoac admin moi thay noi dung rieng tu.',
        'idor_messages' => 'AI Fix: kiem tra quyen truy cap conversation, chi ban be/nguoi lien quan moi doc va gui tin nhan.',
        'weak_session' => 'AI Fix: bat HttpOnly/SameSite cho session cookie, regenerate session sau login va tao remember token bang random_bytes.',
        'avatar_upload_bypass' => 'AI Fix: validate MIME/extension avatar, doi ten file random va tu choi file khong phai anh.',
    ];
    return $fixes[$type] ?? 'AI Fix: kich hoat rule bao ve route nay, xac minh nguon su kien, validate input va them test hoi quy cho luong bi anh huong.';
}

function admin_event_route($uri) {
    return normalize_security_route($uri);
}

function admin_event_group_where($conn, $event) {
    $type = $conn->real_escape_string((string)$event['event_type']);
    $route = $conn->real_escape_string(admin_event_route($event['request_uri'] ?? ''));
    return "deleted_at IS NULL AND event_type='$type' AND REPLACE(REPLACE(SUBSTRING_INDEX(COALESCE(request_uri, ''), '?', 1), '///', '/'), '//', '/')='$route'";
}

function admin_upsert_ai_fix_rule($conn, $event_type, $route, $summary, $admin_id) {
    $event_type = $conn->real_escape_string($event_type);
    $route = $conn->real_escape_string($route);
    $summary = $conn->real_escape_string($summary);
    $source_name = $conn->real_escape_string(ai_security_source_name());
    $source_url = $conn->real_escape_string(ai_security_source_url());

    return $conn->query("
        INSERT INTO ai_fix_rules (event_type, route, source_name, source_url, fix_summary, is_active, created_by, created_at, updated_at)
        VALUES ('$event_type', '$route', '$source_name', '$source_url', '$summary', 1, $admin_id, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            source_name=VALUES(source_name),
            source_url=VALUES(source_url),
            fix_summary=VALUES(fix_summary),
            is_active=1,
            created_by=VALUES(created_by),
            updated_at=NOW()
    ");
}

function admin_train_ai_fix_from_events($conn, $admin_id) {
    $attack_types = "'sql_injection','xss_probe','path_traversal','command_injection','ssrf_probe','oauth_scope_escalation'";
    $events = $conn->query("
        SELECT event_type, request_uri
        FROM security_events
        WHERE deleted_at IS NULL
          AND event_type IN ($attack_types)
        ORDER BY occurred_at DESC, id DESC
    ");
    if (!$events) return 0;

    $trained = [];
    while ($event = $events->fetch_assoc()) {
        $route = admin_event_route($event['request_uri'] ?? '');
        $key = $event['event_type'] . '|' . $route;
        if (isset($trained[$key])) continue;
        $trained[$key] = true;

        $summary = admin_ai_fix_summary($event['event_type']);
        admin_upsert_ai_fix_rule($conn, $event['event_type'], $route, $summary, $admin_id);
        if ($event['event_type'] === 'xss_probe' && $route === '/index.php') {
            admin_upsert_ai_fix_rule($conn, 'xss_probe', '/post.php', $summary, $admin_id);
            admin_upsert_ai_fix_rule($conn, 'xss_probe', '/profile.php', $summary, $admin_id);
        }
        if ($event['event_type'] === 'xss_probe' && $route === '/messages.php') {
            admin_upsert_ai_fix_rule($conn, 'xss_probe', '/fetch_messages.php', $summary, $admin_id);
        }

        $where = admin_event_group_where($conn, [
            'event_type' => $event['event_type'],
            'request_uri' => $route,
        ]);
        $safe_summary = $conn->real_escape_string($summary);
        $conn->query("
            UPDATE security_events
            SET ai_fixed_at=COALESCE(ai_fixed_at, NOW()),
                ai_fix_summary='$safe_summary',
                resolved_at=COALESCE(resolved_at, NOW()),
                resolved_by=$admin_id
            WHERE $where
        ");
    }

    $readme_rules = [
        ['sql_injection', '/login.php'],
        ['sql_injection', '/search.php'],
        ['xss_probe', '/search.php'],
        ['xss_probe', '/index.php'],
        ['xss_probe', '/post.php'],
        ['xss_probe', '/profile.php'],
        ['xss_probe', '/messages.php'],
        ['xss_probe', '/fetch_messages.php'],
        ['private_disclosure', '/index.php'],
        ['private_disclosure', '/profile.php'],
        ['idor_messages', '/messages.php'],
        ['idor_messages', '/fetch_messages.php'],
        ['idor_messages', '/api/get_messages.php'],
        ['idor_messages', '/api/send_message.php'],
        ['weak_session', '/includes/db.php'],
        ['command_injection', '/settings.php'],
        ['avatar_upload_bypass', '/settings.php'],
        ['ssrf_probe', '/preview.php'],
        ['oauth_scope_escalation', '/oauth.php'],
    ];
    foreach ($readme_rules as $rule) {
        [$event_type, $route] = $rule;
        $key = $event_type . '|' . $route;
        if (isset($trained[$key])) continue;
        $trained[$key] = true;
        admin_upsert_ai_fix_rule($conn, $event_type, $route, admin_ai_fix_summary($event_type), $admin_id);
    }

    return count($trained);
}

function admin_group_attack_events($result) {
    $groups = [];
    if (!$result) return $groups;

    while ($event = $result->fetch_assoc()) {
        $key = md5($event['event_type'] . "\n" . admin_event_route($event['request_uri'] ?? ''));
        if (!isset($groups[$key])) {
            $event['duplicate_count'] = 1;
            $groups[$key] = $event;
            continue;
        }

        $groups[$key]['duplicate_count']++;
        if (!empty($event['ai_fixed_at'])) {
            $groups[$key]['ai_fixed_at'] = $event['ai_fixed_at'];
            $groups[$key]['ai_fix_summary'] = $event['ai_fix_summary'];
            $groups[$key]['resolved_at'] = $event['resolved_at'];
        }
    }

    return array_values($groups);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
    $note = isset($_POST['note']) ? $conn->real_escape_string(trim($_POST['note'])) : '';

    if ($action === 'approve_post' && $id > 0) {
        $conn->query("UPDATE posts SET status='approved', moderation_note='$note', moderated_by=$admin_id, moderated_at=NOW() WHERE id=$id");
        log_security_event($conn, 'admin_approved_post', 'low', 'Admin approved a post', 'post_id=' . $id);
        $message = 'Post approved.';
    } elseif ($action === 'reject_post' && $id > 0) {
        $conn->query("UPDATE posts SET status='rejected', moderation_note='$note', moderated_by=$admin_id, moderated_at=NOW() WHERE id=$id");
        log_security_event($conn, 'admin_rejected_post', 'low', 'Admin rejected a post', 'post_id=' . $id);
        $message = 'Post rejected.';
    } elseif ($action === 'delete_post' && $id > 0) {
        $conn->query("DELETE FROM comments WHERE post_id=$id");
        $conn->query("DELETE FROM posts WHERE id=$id");
        log_security_event($conn, 'admin_deleted_post', 'medium', 'Admin deleted a post', 'post_id=' . $id);
        $message = 'Post deleted.';
    } elseif ($action === 'ban_user' && $id > 0) {
        if ($id === $admin_id) {
            $error = 'You cannot ban your own admin account.';
        } else {
            $reason = $note ?: 'Violation of community standards';
            $conn->query("UPDATE users SET is_banned=1, ban_reason='$reason', banned_at=NOW() WHERE id=$id AND is_admin=0");
            log_security_event($conn, 'admin_banned_user', 'high', 'Admin banned a user', 'user_id=' . $id);
            $message = 'User banned.';
        }
    } elseif ($action === 'unban_user' && $id > 0) {
        $conn->query("UPDATE users SET is_banned=0, ban_reason=NULL, banned_at=NULL WHERE id=$id");
        log_security_event($conn, 'admin_unbanned_user', 'medium', 'Admin unbanned a user', 'user_id=' . $id);
        $message = 'User restored.';
    } elseif ($action === 'resolve_event' && $id > 0) {
        $event_res = $conn->query("SELECT event_type, request_uri, payload FROM security_events WHERE id=$id AND deleted_at IS NULL LIMIT 1");
        if ($event_res && $event_res->num_rows > 0) {
            $where = admin_event_group_where($conn, $event_res->fetch_assoc());
            $conn->query("UPDATE security_events SET resolved_at=NOW(), resolved_by=$admin_id WHERE $where");
            $message = 'Security event group marked as reviewed.';
        }
    } elseif ($action === 'ai_fix_event' && $id > 0) {
        $event_res = $conn->query("SELECT event_type, request_uri, payload FROM security_events WHERE id=$id AND deleted_at IS NULL LIMIT 1");
        if ($event_res && $event_res->num_rows > 0) {
            $event = $event_res->fetch_assoc();
            $where = admin_event_group_where($conn, $event);
            $route = $conn->real_escape_string(admin_event_route($event['request_uri'] ?? ''));
            $summary = $conn->real_escape_string(admin_ai_fix_summary($event['event_type']));
            $conn->query("
                UPDATE security_events
                SET ai_fixed_at=NOW(),
                    ai_fix_summary='$summary',
                    resolved_at=COALESCE(resolved_at, NOW()),
                    resolved_by=$admin_id
                WHERE $where
            ");
            admin_upsert_ai_fix_rule($conn, $event['event_type'], $route, admin_ai_fix_summary($event['event_type']), $admin_id);
            $message = 'AI Fix applied. Duplicate events changed to fixed.';
        }
    } elseif ($action === 'train_ai_fix_all') {
        $trained_count = admin_train_ai_fix_from_events($conn, $admin_id);
        $message = "AI Fix trained $trained_count route rule(s). All trained exploit groups are now protected.";
    } elseif ($action === 'delete_event' && $id > 0) {
        $event_res = $conn->query("SELECT event_type, request_uri, payload FROM security_events WHERE id=$id AND deleted_at IS NULL LIMIT 1");
        if ($event_res && $event_res->num_rows > 0) {
            $where = admin_event_group_where($conn, $event_res->fetch_assoc());
            $conn->query("UPDATE security_events SET deleted_at=NOW() WHERE $where");
            $message = 'Old duplicate security events deleted.';
        }
    }
}

$stats = [
    'pending_posts' => 0,
    'approved_posts' => 0,
    'users' => 0,
    'banned_users' => 0,
    'open_events' => 0,
];

$queries = [
    'pending_posts' => "SELECT COUNT(*) AS total FROM posts WHERE status='pending'",
    'approved_posts' => "SELECT COUNT(*) AS total FROM posts WHERE status='approved'",
    'users' => "SELECT COUNT(*) AS total FROM users WHERE is_admin=0",
    'banned_users' => "SELECT COUNT(*) AS total FROM users WHERE is_banned=1",
    'open_events' => "SELECT COUNT(*) AS total FROM security_events WHERE deleted_at IS NULL AND ai_fixed_at IS NULL AND resolved_at IS NULL AND severity IN ('high','critical')",
];
foreach ($queries as $key => $sql) {
    $res = $conn->query($sql);
    if ($res) $stats[$key] = (int)$res->fetch_assoc()['total'];
}

$pending_posts = $conn->query("
    SELECT p.*, u.username, u.full_name, u.avatar
    FROM posts p
    JOIN users u ON p.user_id = u.id
    WHERE p.status='pending'
    ORDER BY p.created_at ASC
");

$recent_posts = $conn->query("
    SELECT p.*, u.username, u.full_name
    FROM posts p
    JOIN users u ON p.user_id = u.id
    ORDER BY p.created_at DESC
    LIMIT 12
");

$users = $conn->query("
    SELECT id, username, email, full_name, avatar, is_admin, is_banned, ban_reason, created_at
    FROM users
    ORDER BY is_admin DESC, is_banned DESC, created_at DESC
");

$events = $conn->query("
    SELECT se.*, COALESCE(se.actor_username, u.username) AS actor_name, u.username
    FROM security_events se
    LEFT JOIN users u ON se.user_id = u.id
    WHERE se.deleted_at IS NULL
    ORDER BY se.occurred_at DESC, se.id DESC
    LIMIT 40
");

$login_events = $conn->query("
    SELECT se.*, COALESCE(se.actor_username, u.username) AS actor_name, u.username
    FROM security_events se
    LEFT JOIN users u ON se.user_id = u.id
    WHERE se.deleted_at IS NULL
      AND se.event_type IN ('admin_login','user_login','failed_login','banned_user_login','banned_oauth_login')
    ORDER BY se.occurred_at DESC, se.id DESC
    LIMIT 20
");

$attack_events = $conn->query("
    SELECT se.*, COALESCE(se.actor_username, u.username) AS actor_name, u.username
    FROM security_events se
    LEFT JOIN users u ON se.user_id = u.id
    WHERE se.deleted_at IS NULL
      AND se.event_type IN ('sql_injection','xss_probe','path_traversal','command_injection','ssrf_probe','oauth_scope_escalation')
    ORDER BY se.occurred_at DESC, se.id DESC
    LIMIT 120
");
$attack_event_groups = array_slice(admin_group_attack_events($attack_events), 0, 30);
$stats['open_events'] = 0;
foreach ($attack_event_groups as $event) {
    if (in_array($event['severity'], ['high', 'critical'], true) && empty($event['ai_fixed_at']) && empty($event['resolved_at'])) {
        $stats['open_events']++;
    }
}

$ai_fix_rules = $conn->query("
    SELECT *
    FROM ai_fix_rules
    WHERE is_active=1
    ORDER BY updated_at DESC
    LIMIT 12
");
?>
<?php require_once 'includes/header.php'; ?>
<div class="admin-page">
    <section class="admin-hero card">
        <div>
            <span class="eyebrow">Admin Console</span>
            <h1>Moderation and Security Center</h1>
            <p class="text-muted">Review posts, remove violating content, ban users, and monitor suspicious access attempts.</p>
        </div>
        <div class="admin-tabs">
            <a href="#posts"><i class="fas fa-list-check"></i> Posts</a>
            <a href="#users"><i class="fas fa-users-gear"></i> Users</a>
            <a href="#security"><i class="fas fa-shield-halved"></i> Security</a>
        </div>
    </section>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-danger"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <div class="stat-grid">
        <div class="stat-card"><i class="fas fa-clock"></i><strong><?= $stats['pending_posts'] ?></strong><span>Pending Posts</span></div>
        <div class="stat-card"><i class="fas fa-circle-check"></i><strong><?= $stats['approved_posts'] ?></strong><span>Approved Posts</span></div>
        <div class="stat-card"><i class="fas fa-user"></i><strong><?= $stats['users'] ?></strong><span>Regular Users</span></div>
        <div class="stat-card danger"><i class="fas fa-ban"></i><strong><?= $stats['banned_users'] ?></strong><span>Banned Users</span></div>
        <div class="stat-card warning"><i class="fas fa-triangle-exclamation"></i><strong><?= $stats['open_events'] ?></strong><span>Open Alerts</span></div>
    </div>

    <section class="card admin-section" id="posts">
        <div class="section-heading">
            <h2><i class="fas fa-list-check"></i> Posts Waiting For Review</h2>
            <span><?= $pending_posts ? $pending_posts->num_rows : 0 ?> pending</span>
        </div>
        <?php if ($pending_posts && $pending_posts->num_rows > 0): ?>
            <div class="moderation-list">
                <?php while ($post = $pending_posts->fetch_assoc()): ?>
                <article class="moderation-item">
                    <img src="/uploads/<?= htmlspecialchars($post['avatar']) ?>" class="avatar-sm">
                    <div class="moderation-body">
                        <div class="moderation-meta">
                            <strong><?= htmlspecialchars($post['full_name']) ?></strong>
                            <span>@<?= htmlspecialchars($post['username']) ?> &middot; <?= htmlspecialchars($post['created_at']) ?></span>
                        </div>
                        <p><?= nl2br(htmlspecialchars($post['content'])) ?></p>
                        <?php if ($post['image']): ?>
                            <a href="/uploads/<?= htmlspecialchars($post['image']) ?>" target="_blank" class="attachment-link"><i class="fas fa-image"></i> View image</a>
                        <?php endif; ?>
                    </div>
                    <form method="POST" class="moderation-actions">
                        <input type="hidden" name="id" value="<?= (int)$post['id'] ?>">
                        <input type="text" name="note" class="form-control" placeholder="Moderation note">
                        <button name="action" value="approve_post" class="btn btn-success btn-sm"><i class="fas fa-check"></i> Approve</button>
                        <button name="action" value="reject_post" class="btn btn-warning btn-sm"><i class="fas fa-xmark"></i> Reject</button>
                        <button name="action" value="delete_post" class="btn btn-danger btn-sm" onclick="return confirm('Delete this post permanently?')"><i class="fas fa-trash"></i> Delete</button>
                    </form>
                </article>
                <?php endwhile; ?>
            </div>
        <?php else: ?>
            <p class="text-muted">No posts are waiting for review.</p>
        <?php endif; ?>
    </section>

    <section class="card admin-section">
        <div class="section-heading">
            <h2><i class="fas fa-newspaper"></i> Recent Posts</h2>
        </div>
        <div class="admin-table-wrap">
            <table class="admin-table">
                <thead><tr><th>Author</th><th>Content</th><th>Status</th><th>Created</th><th>Action</th></tr></thead>
                <tbody>
                <?php while ($post = $recent_posts->fetch_assoc()): ?>
                    <tr>
                        <td><?= htmlspecialchars($post['full_name']) ?><br><span>@<?= htmlspecialchars($post['username']) ?></span></td>
                        <td><?= htmlspecialchars(substr(strip_tags($post['content']), 0, 100)) ?><?= strlen(strip_tags($post['content'])) > 100 ? '...' : '' ?></td>
                        <td><span class="status-badge status-<?= htmlspecialchars($post['status']) ?>"><?= htmlspecialchars(ucfirst($post['status'])) ?></span></td>
                        <td><?= htmlspecialchars($post['created_at']) ?></td>
                        <td>
                            <form method="POST" style="display:inline">
                                <input type="hidden" name="id" value="<?= (int)$post['id'] ?>">
                                <button name="action" value="delete_post" class="btn btn-danger btn-sm" onclick="return confirm('Delete this post permanently?')"><i class="fas fa-trash"></i></button>
                            </form>
                        </td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </section>

    <section class="card admin-section" id="users">
        <div class="section-heading">
            <h2><i class="fas fa-users-gear"></i> User Management</h2>
        </div>
        <div class="admin-table-wrap">
            <table class="admin-table">
                <thead><tr><th>User</th><th>Email</th><th>Role</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>
                <?php while ($u = $users->fetch_assoc()): ?>
                    <tr>
                        <td>
                            <div class="table-user">
                                <img src="/uploads/<?= htmlspecialchars($u['avatar']) ?>" class="avatar-xs">
                                <div><strong><?= htmlspecialchars($u['full_name']) ?></strong><span>@<?= htmlspecialchars($u['username']) ?></span></div>
                            </div>
                        </td>
                        <td><?= htmlspecialchars($u['email']) ?></td>
                        <td><?= $u['is_admin'] ? '<span class="badge-admin">Admin</span>' : 'User' ?></td>
                        <td>
                            <?php if ($u['is_banned']): ?>
                                <span class="status-badge status-rejected">Banned</span>
                                <small><?= htmlspecialchars($u['ban_reason'] ?: '') ?></small>
                            <?php else: ?>
                                <span class="status-badge status-approved">Active</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!$u['is_admin']): ?>
                                <form method="POST" class="inline-admin-form">
                                    <input type="hidden" name="id" value="<?= (int)$u['id'] ?>">
                                    <?php if ($u['is_banned']): ?>
                                        <button name="action" value="unban_user" class="btn btn-success btn-sm"><i class="fas fa-unlock"></i> Unban</button>
                                    <?php else: ?>
                                        <input type="text" name="note" class="form-control" placeholder="Ban reason">
                                        <button name="action" value="ban_user" class="btn btn-danger btn-sm" onclick="return confirm('Ban this user?')"><i class="fas fa-ban"></i> Ban</button>
                                    <?php endif; ?>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </section>

    <section class="card admin-section" id="security">
        <div class="section-heading">
            <h2><i class="fas fa-shield-halved"></i> Intrusion Detection</h2>
            <span>Server timezone: Asia/Ho_Chi_Minh (UTC+7)</span>
        </div>
        <div class="security-dashboard-grid">
            <section class="security-panel security-panel-wide" style="display: none;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h3 style="margin: 0;"><i class="fas fa-robot"></i> AI Fix Assistant</h3>
                    <form method="POST" style="margin: 0;">
                        <button name="action" value="train_ai_fix_all" class="btn btn-success btn-sm"><i class="fas fa-brain"></i> Train AI Fix All</button>
                    </form>
                </div>
            </section>

            <!-- Floating Chat Widget Styles -->
            <style>
                .floating-ai-toggle {
                    position: fixed;
                    bottom: 24px;
                    right: 24px;
                    width: 60px;
                    height: 60px;
                    background: linear-gradient(135deg, #6366f1, #4f46e5);
                    border-radius: 50%;
                    box-shadow: 0 8px 30px rgba(79, 70, 229, 0.4);
                    color: #fff;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    font-size: 24px;
                    cursor: pointer;
                    z-index: 9999;
                    transition: box-shadow 0.3s ease;
                }
                .floating-ai-toggle:hover {
                    box-shadow: 0 12px 35px rgba(79, 70, 229, 0.6);
                }
                .floating-ai-toggle .pulse {
                    position: absolute;
                    width: 100%;
                    height: 100%;
                    background: rgba(79, 70, 229, 0.4);
                    border-radius: 50%;
                    animation: pulse-ring 2s infinite;
                    z-index: -1;
                }
                @keyframes pulse-ring {
                    0% { transform: scale(0.95); opacity: 0.8; }
                    50% { transform: scale(1.3); opacity: 0; }
                    100% { transform: scale(0.95); opacity: 0; }
                }

                /* Floating Chatbox Container */
                .ai-chat-widget {
                    position: fixed;
                    bottom: 96px;
                    right: 24px;
                    width: 420px;
                    height: 600px;
                    background: rgba(255, 255, 255, 0.85);
                    backdrop-filter: blur(20px) saturate(180%);
                    -webkit-backdrop-filter: blur(20px) saturate(180%);
                    border: 1px solid rgba(209, 213, 219, 0.3);
                    border-radius: 20px;
                    box-shadow: 0 20px 50px rgba(0, 0, 0, 0.15);
                    display: flex;
                    flex-direction: column;
                    z-index: 9998;
                    overflow: hidden;
                    opacity: 0;
                    transform: translateY(30px) scale(0.95);
                    pointer-events: none;
                    transition: all 0.4s cubic-bezier(0.165, 0.84, 0.44, 1);
                }
                .ai-chat-widget.active {
                    opacity: 1;
                    transform: translateY(0) scale(1);
                    pointer-events: auto;
                }

                /* Header */
                .ai-chat-header {
                    background: linear-gradient(135deg, #1e1b4b, #312e81);
                    color: #fff;
                    padding: 16px 20px;
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                }
                .ai-chat-header-title {
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    font-weight: 600;
                    font-size: 1.05rem;
                }
                .ai-chat-header-actions {
                    display: flex;
                    align-items: center;
                    gap: 12px;
                }
                .ai-chat-header-btn {
                    background: transparent;
                    border: none;
                    color: rgba(255, 255, 255, 0.8);
                    cursor: pointer;
                    font-size: 1.1rem;
                    transition: color 0.2s;
                }
                .ai-chat-header-btn:hover {
                    color: #fff;
                }

                /* Message Area */
                .ai-chat-messages-area {
                    flex: 1;
                    padding: 20px;
                    overflow-y: auto;
                    display: flex;
                    flex-direction: column;
                    gap: 16px;
                }
                .ai-bubble {
                    max-width: 85%;
                    padding: 12px 16px;
                    border-radius: 16px;
                    font-size: 0.95rem;
                    line-height: 1.5;
                    word-wrap: break-word;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.03);
                }
                .ai-bubble.bot {
                    align-self: flex-start;
                    background: #f3f4f6;
                    color: #1f2937;
                    border-top-left-radius: 4px;
                }
                .ai-bubble.user {
                    align-self: flex-end;
                    background: #4f46e5;
                    color: #fff;
                    border-top-right-radius: 4px;
                }
                .ai-bubble code {
                    background: rgba(0,0,0,0.06);
                    padding: 2px 5px;
                    border-radius: 4px;
                    font-family: Consolas, monospace;
                    font-size: 0.85rem;
                }
                .ai-bubble.user code {
                    background: rgba(255,255,255,0.2);
                }
                .ai-bubble pre {
                    background: #1e293b;
                    color: #f8fafc;
                    padding: 12px;
                    border-radius: 8px;
                    overflow-x: auto;
                    margin: 8px 0;
                }
                .ai-bubble pre code {
                    background: transparent;
                    color: inherit;
                    padding: 0;
                }

                /* Typing Indicator */
                .typing-indicator {
                    display: flex;
                    align-items: center;
                    gap: 4px;
                }
                .typing-indicator span {
                    width: 6px;
                    height: 6px;
                    background: #9ca3af;
                    border-radius: 50%;
                    display: inline-block;
                    animation: bounce 1.4s infinite ease-in-out both;
                }
                .typing-indicator span:nth-child(1) { animation-delay: -0.32s; }
                .typing-indicator span:nth-child(2) { animation-delay: -0.16s; }
                @keyframes bounce {
                    0%, 80%, 100% { transform: scale(0); }
                    40% { transform: scale(1); }
                }

                /* Settings Overlay Panel */
                .ai-settings-panel {
                    position: absolute;
                    top: 60px;
                    left: 0;
                    right: 0;
                    background: #fff;
                    border-bottom: 1px solid #e5e7eb;
                    padding: 20px;
                    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05);
                    transform: translateY(-100%);
                    opacity: 0;
                    pointer-events: none;
                    transition: all 0.3s ease;
                    z-index: 10;
                }
                .ai-settings-panel.active {
                    transform: translateY(0);
                    opacity: 1;
                    pointer-events: auto;
                }

                /* Input Bar */
                .ai-chat-input-bar {
                    border-top: 1px solid rgba(229, 231, 235, 0.6);
                    padding: 16px;
                    display: flex;
                    gap: 10px;
                    background: rgba(249, 250, 251, 0.8);
                }
                .ai-chat-input-bar input {
                    flex: 1;
                    border: 1px solid #d1d5db;
                    border-radius: 24px;
                    padding: 10px 18px;
                    outline: none;
                    font-size: 0.95rem;
                    background: #fff;
                    transition: border-color 0.2s;
                }
                .ai-chat-input-bar input:focus {
                    border-color: #6366f1;
                }
                .ai-chat-input-bar button {
                    background: #4f46e5;
                    color: #fff;
                    border: none;
                    border-radius: 50%;
                    width: 42px;
                    height: 42px;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    cursor: pointer;
                    transition: background 0.2s;
                }
                .ai-chat-input-bar button:hover {
                    background: #4338ca;
                }

                /* Interactive Patch Card */
                .patch-card {
                    background: #fff;
                    border: 1px solid #e5e7eb;
                    border-radius: 12px;
                    margin-top: 12px;
                    box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);
                    overflow: hidden;
                }
                .patch-card-header {
                    background: #f9fafb;
                    padding: 10px 14px;
                    border-bottom: 1px solid #e5e7eb;
                    font-weight: 600;
                    font-size: 0.85rem;
                    color: #374151;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                .patch-card-body {
                    padding: 12px;
                    max-height: 150px;
                    overflow-y: auto;
                }
                .patch-card-btn {
                    width: 100%;
                    border: none;
                    background: #10b981;
                    color: #fff;
                    font-weight: 600;
                    font-size: 0.9rem;
                    padding: 10px;
                    cursor: pointer;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    gap: 8px;
                    transition: background 0.2s;
                }
                .patch-card-btn:hover {
                    background: #059669;
                }
            </style>
            <!-- Chat widget elements moved outside grid container to prevent overflow clipping -->


            <!-- Client Script Controller -->
            <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const toggle = document.getElementById('floatingAiToggle');
                    const widget = document.getElementById('aiChatWidget');
                    const collapse = document.getElementById('aiChatCollapse');
                    const settingsToggle = document.getElementById('aiSettingsToggle');
                    const settingsPanel = document.getElementById('aiSettingsPanel');
                    const saveKeyBtn = document.getElementById('saveApiKeyBtn');
                    const apiKeyInput = document.getElementById('geminiApiKeyInput');
                    const keyStatus = document.getElementById('apiKeyStatus');
                    const chatMessages = document.getElementById('aiChatMessages');
                    const chatInput = document.getElementById('aiChatInput');
                    const sendBtn = document.getElementById('aiChatSend');

                    let activePatch = null;

                    // Toggle chat window open/close
                    toggle.addEventListener('click', () => {
                        widget.classList.toggle('active');
                    });
                    collapse.addEventListener('click', () => {
                        widget.classList.remove('active');
                    });

                    // Toggle settings overlay
                    settingsToggle.addEventListener('click', () => {
                        settingsPanel.classList.toggle('active');
                    });

                    // Load API Key configuration status
                    function loadApiKeyStatus() {
                        fetch('api/ai_agent.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'get_key_status' })
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.configured) {
                                keyStatus.innerHTML = '<span style="color:#10b981;"><i class="fas fa-check-circle"></i> Key Active: ' + data.masked_key + '</span>';
                            } else {
                                keyStatus.innerHTML = '<span style="color:#ef4444;"><i class="fas fa-exclamation-circle"></i> API Key Not Configured</span>';
                            }
                        });
                    }
                    loadApiKeyStatus();

                    // Save new API Key
                    saveKeyBtn.addEventListener('click', () => {
                        const key = apiKeyInput.value.trim();
                        if (!key) return;
                        saveKeyBtn.disabled = true;
                        fetch('api/ai_agent.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'save_key', key: key })
                        })
                        .then(res => res.json())
                        .then(data => {
                            saveKeyBtn.disabled = false;
                            if (data.success) {
                                apiKeyInput.value = '';
                                settingsPanel.classList.remove('active');
                                loadApiKeyStatus();
                                appendMessage('bot', '✔️ Đã lưu API Key thành công! Tôi đã sẵn sàng hoạt động.');
                            } else {
                                alert(data.error || 'Failed to save key.');
                            }
                        })
                        .catch(() => {
                            saveKeyBtn.disabled = false;
                        });
                    });

                    // Append chat bubbles
                    function appendMessage(sender, text) {
                        const bubble = document.createElement('div');
                        bubble.className = 'ai-bubble ' + sender;
                        
                        if (sender === 'bot') {
                            // Simple Markdown rendering helper (supports code blocks and paragraph breaks)
                            let parsed = text;
                            
                            // Detect patch blocks
                            const patchRegex = /```patch\s*([\s\S]*?)```/g;
                            let patchMatch;
                            let patchCardHtml = '';
                            
                            if (patchMatch = patchRegex.exec(text)) {
                                const patchBlock = patchMatch[1];
                                const lines = patchBlock.split('\n');
                                let filePath = '';
                                let searchCode = [];
                                let replaceCode = [];
                                let mode = ''; // 'search' or 'replace'

                                lines.forEach(line => {
                                    if (line.startsWith('[PATCH]')) {
                                        filePath = line.replace('[PATCH] file_path:', '').trim();
                                    } else if (line.startsWith('[SEARCH]')) {
                                        mode = 'search';
                                    } else if (line.startsWith('[REPLACE]')) {
                                        mode = 'replace';
                                    } else {
                                        if (mode === 'search') searchCode.push(line);
                                        if (mode === 'replace') replaceCode.push(line);
                                    }
                                });

                                activePatch = {
                                    file_path: filePath,
                                    search_code: searchCode.join('\n'),
                                    replace_code: replaceCode.join('\n')
                                };

                                patchCardHtml = `
                                    <div class="patch-card">
                                        <div class="patch-card-header">
                                            <span><i class="fas fa-file-code"></i> ${escapeHtml(filePath)}</span>
                                            <span style="color:#ef4444; font-size:0.75rem;">Source Hotpatch</span>
                                        </div>
                                        <div class="patch-card-body">
                                            <pre style="margin:0; font-size:0.8rem;"><code>${escapeHtml(activePatch.replace_code.substring(0, 100))}${activePatch.replace_code.length > 100 ? '...' : ''}</code></pre>
                                        </div>
                                        <button class="patch-card-btn" id="applyPatchBtn">
                                            <i class="fas fa-wand-magic-sparkles"></i> Apply Source Patch
                                        </button>
                                    </div>
                                `;
                            }

                            // Render basic pre blocks
                            parsed = parsed.replace(/```(\w+)?([\s\S]*?)```/g, '<pre><code>$2</code></pre>');
                            parsed = parsed.replace(/`([^`]+)`/g, '<code>$1</code>');
                            parsed = parsed.replace(/\n/g, '<br>');
                            
                            bubble.innerHTML = '<strong>Gemini Agent:</strong><br>' + parsed + patchCardHtml;
                        } else {
                            bubble.innerHTML = '<strong>Bạn:</strong><br>' + escapeHtml(text).replace(/\n/g, '<br>');
                        }
                        
                        chatMessages.appendChild(bubble);
                        chatMessages.scrollTop = chatMessages.scrollHeight;

                        // Attach trigger for Applying Patch button
                        const applyBtn = document.getElementById('applyPatchBtn');
                        if (applyBtn && activePatch) {
                            applyBtn.addEventListener('click', function() {
                                applyBtn.disabled = true;
                                applyBtn.innerHTML = '<i class="fas fa-circle-notch fa-spin"></i> Patching file...';
                                applyPatchDirect(applyBtn);
                            });
                        }
                    }

                    function escapeHtml(str) {
                        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                    }

                    // Apply source patch helper
                    function applyPatchDirect(btn) {
                        if (!activePatch) return;
                        fetch('api/ai_agent.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                action: 'apply_patch',
                                file_path: activePatch.file_path,
                                search_code: activePatch.search_code,
                                replace_code: activePatch.replace_code
                            })
                        })
                        .then(res => res.json())
                        .then(data => {
                            if (data.success) {
                                btn.style.background = '#10b981';
                                btn.innerHTML = '<i class="fas fa-check-double"></i> Patched Successfully!';
                                appendMessage('bot', '✔️ ' + data.message);
                                activePatch = null;
                            } else {
                                btn.style.background = '#ef4444';
                                btn.innerHTML = '<i class="fas fa-triangle-exclamation"></i> Patch Failed';
                                appendMessage('bot', '❌ Thất bại: ' + data.error);
                            }
                        })
                        .catch(err => {
                            btn.style.background = '#ef4444';
                            btn.innerHTML = '<i class="fas fa-triangle-exclamation"></i> Connection Error';
                            appendMessage('bot', '❌ Lỗi kết nối khi vá: ' + err.message);
                        });
                    }

                    // Send normal chat message
                    function handleChatSend(overrideMessage = null) {
                        const message = overrideMessage || chatInput.value.trim();
                        if (!message) return;
                        
                        if (!overrideMessage) {
                            appendMessage('user', message);
                            chatInput.value = '';
                        }

                        // Add typing bubble
                        const typing = document.createElement('div');
                        typing.className = 'ai-bubble bot';
                        typing.innerHTML = `
                            <strong>Gemini Agent:</strong><br>
                            <div class="typing-indicator">
                                <span></span><span></span><span></span>
                            </div>
                        `;
                        chatMessages.appendChild(typing);
                        chatMessages.scrollTop = chatMessages.scrollHeight;

                        fetch('api/ai_agent.php', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ action: 'chat', message: message })
                        })
                        .then(res => res.json())
                        .then(data => {
                            chatMessages.removeChild(typing);
                            if (data.reply) {
                                appendMessage('bot', data.reply);
                            } else {
                                appendMessage('bot', '⚠️ Lỗi: ' + (data.error || 'Unknown response.'));
                            }
                        })
                        .catch(err => {
                            chatMessages.removeChild(typing);
                            appendMessage('bot', '❌ Lỗi kết nối API: ' + err.message);
                        });
                    }

                    sendBtn.addEventListener('click', () => handleChatSend());
                    chatInput.addEventListener('keypress', (e) => {
                        if (e.key === 'Enter') handleChatSend();
                    });

                    // Modify the default "AI Fix" click buttons on the events panel
                    window.triggerAiFixForEvent = function(eventType, route, details, payload) {
                        widget.classList.add('active');
                        appendMessage('user', `Hỏi cách vá lỗ hổng loại "${eventType}" tại route "${route}"`);
                        
                        const queryMessage = `Vui lòng phân tích sự cố bảo mật này và đề xuất một bản vá hotpatch bằng cách sử dụng cấu trúc [PATCH]:
Loại sự kiện: ${eventType}
Route: ${route}
Chi tiết: ${details}
Payload ghi nhận: ${payload}
Vui lòng giải thích ngắn gọn lý do vì sao bị lỗi và cung cấp cấu trúc code [PATCH] chuẩn xác để tôi bấm nút vá lỗi trực tiếp.`;
                        
                        handleChatSend(queryMessage);
                    };
                });
            </script>

            <section class="security-panel">
                <h3><i class="fas fa-right-to-bracket"></i> Login Activity</h3>
                <?php if ($login_events && $login_events->num_rows > 0): ?>
                    <div class="admin-table-wrap">
                        <table class="admin-table security-table">
                            <thead><tr><th>Time</th><th>User</th><th>Result</th><th>IP</th><th>Payload</th></tr></thead>
                            <tbody>
                            <?php while ($event = $login_events->fetch_assoc()): ?>
                                <tr>
                                    <td><?= htmlspecialchars(admin_event_time($event['occurred_at'] ?: $event['created_at'])) ?></td>
                                    <td><strong><?= htmlspecialchars(admin_event_actor($event)) ?></strong></td>
                                    <td><span class="severity-badge severity-<?= htmlspecialchars($event['severity']) ?>"><?= htmlspecialchars(admin_event_label($event['event_type'])) ?></span></td>
                                    <td><?= htmlspecialchars($event['ip_address']) ?></td>
                                    <td><code><?= htmlspecialchars(admin_event_payload($event['payload'])) ?></code></td>
                                </tr>
                            <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <p class="text-muted">No login events yet.</p>
                <?php endif; ?>
            </section>

            <section class="security-panel">
                <h3><i class="fas fa-bug"></i> Detected Vulnerability Attempts</h3>
                <?php if (!empty($attack_event_groups)): ?>
                    <div class="security-events">
                        <?php foreach ($attack_event_groups as $event): ?>
                        <article class="security-event severity-<?= htmlspecialchars($event['severity']) ?> <?= $event['resolved_at'] ? 'resolved' : '' ?> <?= $event['ai_fixed_at'] ? 'fixed' : '' ?>">
                            <form method="POST" class="event-delete-form">
                                <input type="hidden" name="id" value="<?= (int)$event['id'] ?>">
                                <button name="action" value="delete_event" class="event-delete-btn" title="Delete old event" onclick="return confirm('Delete this old security event?')"><i class="fas fa-xmark"></i></button>
                            </form>
                            <div class="event-main">
                                <div>
                                    <strong><?= htmlspecialchars(admin_event_label($event['event_type'])) ?></strong>
                                    <span>
                                        <?= htmlspecialchars(admin_event_time($event['occurred_at'] ?: $event['created_at'])) ?> &middot;
                                        <?= htmlspecialchars(admin_event_actor($event)) ?> &middot;
                                        <?= htmlspecialchars($event['ip_address']) ?>
                                        <?php if (!empty($event['duplicate_count']) && $event['duplicate_count'] > 1): ?>
                                            &middot; <?= (int)$event['duplicate_count'] ?> duplicate attempts
                                        <?php endif; ?>
                                    </span>
                                </div>
                                <?php if ($event['ai_fixed_at']): ?>
                                    <span class="severity-badge severity-fixed">FIXED</span>
                                <?php else: ?>
                                    <span class="severity-badge severity-<?= htmlspecialchars($event['severity']) ?>"><?= htmlspecialchars(strtoupper($event['severity'])) ?></span>
                                <?php endif; ?>
                            </div>
                            <p><?= htmlspecialchars($event['details']) ?></p>
                            <?php if ($event['request_uri']): ?><code>URL: <?= htmlspecialchars(substr($event['request_uri'], 0, 220)) ?></code><?php endif; ?>
                            <code>Payload: <?= htmlspecialchars(admin_event_payload($event['payload'])) ?></code>
                             <?php if ($event['ai_fixed_at']): ?>
                                 <div class="ai-fix-summary">
                                     <strong><i class="fas fa-wand-magic-sparkles"></i> AI Fix applied at <?= htmlspecialchars(admin_event_time($event['ai_fixed_at'])) ?></strong>
                                     <p><?= htmlspecialchars($event['ai_fix_summary']) ?></p>
                                     <small>Protection source: <a href="<?= htmlspecialchars(ai_security_source_url()) ?>" target="_blank" rel="noopener"><?= htmlspecialchars(ai_security_source_name()) ?></a></small>
                                 </div>
                             <?php elseif (!$event['resolved_at']): ?>
                                 <div class="security-event-actions">
                                     <button type="button" class="btn btn-success btn-sm" onclick="triggerAiFixForEvent('<?= htmlspecialchars($event['event_type']) ?>', '<?= htmlspecialchars(admin_event_route($event['request_uri'] ?? '')) ?>', '<?= htmlspecialchars(addslashes($event['details'])) ?>', '<?= htmlspecialchars(addslashes(admin_event_payload($event['payload']))) ?>')">
                                         <i class="fas fa-wand-magic-sparkles"></i> AI Fix
                                     </button>
                                     <form method="POST" style="display:inline;">
                                         <input type="hidden" name="id" value="<?= (int)$event['id'] ?>">
                                         <button name="action" value="resolve_event" class="btn btn-secondary btn-sm"><i class="fas fa-check-double"></i> Mark reviewed</button>
                                     </form>
                                 </div>
                             <?php else: ?>
                                 <div class="security-event-actions">
                                     <button type="button" class="btn btn-success btn-sm" onclick="triggerAiFixForEvent('<?= htmlspecialchars($event['event_type']) ?>', '<?= htmlspecialchars(admin_event_route($event['request_uri'] ?? '')) ?>', '<?= htmlspecialchars(addslashes($event['details'])) ?>', '<?= htmlspecialchars(addslashes(admin_event_payload($event['payload']))) ?>')">
                                         <i class="fas fa-wand-magic-sparkles"></i> AI Fix
                                     </button>
                                     <small class="text-muted">Reviewed at <?= htmlspecialchars(admin_event_time($event['resolved_at'])) ?></small>
                                 </div>
                             <?php endif; ?>
                        </article>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <p class="text-muted">No vulnerability attempts have been detected yet.</p>
                <?php endif; ?>
            </section>

            <section class="security-panel security-panel-wide">
                <h3><i class="fas fa-clock-rotate-left"></i> Full Recent Event Log</h3>
                <?php if ($events && $events->num_rows > 0): ?>
                    <div class="admin-table-wrap">
                        <table class="admin-table security-table">
                            <thead><tr><th>Time</th><th>User</th><th>Event</th><th>Severity</th><th>IP</th><th>Details</th></tr></thead>
                            <tbody>
                            <?php while ($event = $events->fetch_assoc()): ?>
                                <tr>
                                    <td><?= htmlspecialchars(admin_event_time($event['occurred_at'] ?: $event['created_at'])) ?></td>
                                    <td><?= htmlspecialchars(admin_event_actor($event)) ?></td>
                                    <td><?= htmlspecialchars(admin_event_label($event['event_type'])) ?></td>
                                    <td>
                                        <?php if ($event['ai_fixed_at']): ?>
                                            <span class="severity-badge severity-fixed">FIXED</span>
                                        <?php else: ?>
                                            <span class="severity-badge severity-<?= htmlspecialchars($event['severity']) ?>"><?= htmlspecialchars(strtoupper($event['severity'])) ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td><?= htmlspecialchars($event['ip_address']) ?></td>
                                    <td>
                                        <?= htmlspecialchars($event['details']) ?>
                                        <?php if ($event['request_uri']): ?><code><?= htmlspecialchars(substr($event['request_uri'], 0, 180)) ?></code><?php endif; ?>
                                    </td>
                                </tr>
                            <?php endwhile; ?>
                            </tbody>
                        </table>
                    </div>
                <?php else: ?>
                    <p class="text-muted">No events have been recorded yet.</p>
                <?php endif; ?>
            </section>
        </div>
    </section>
</div>

<!-- Floating Toggle Trigger Button -->
<div class="floating-ai-toggle" id="floatingAiToggle">
    <span class="pulse"></span>
    <i class="fas fa-robot"></i>
</div>

<!-- Floating AI Chat Widget -->
<div class="ai-chat-widget" id="aiChatWidget">
    <div class="ai-chat-header">
        <div class="ai-chat-header-title">
            <i class="fas fa-shield-halved text-primary-light"></i>
            <span>Gemini Security Agent</span>
        </div>
        <div class="ai-chat-header-actions">
            <button class="ai-chat-header-btn" id="aiSettingsToggle" title="Settings">
                <i class="fas fa-cog"></i>
            </button>
            <button class="ai-chat-header-btn" id="aiChatCollapse" title="Minimize">
                <i class="fas fa-minus"></i>
            </button>
        </div>
    </div>

    <!-- API Key Configuration Settings Panel -->
    <div class="ai-settings-panel" id="aiSettingsPanel">
        <h4 style="margin: 0 0 10px 0;"><i class="fas fa-key"></i> Gemini API Key</h4>
        <p class="text-muted" style="font-size: 0.8rem; margin-bottom: 12px;">Get a Gemini API Key from Google AI Studio and save it here.</p>
        <div style="display: flex; gap: 8px;">
            <input type="password" id="geminiApiKeyInput" class="form-control" placeholder="AIzaSy..." style="flex:1;">
            <button id="saveApiKeyBtn" class="btn btn-primary btn-sm">Save</button>
        </div>
        <div id="apiKeyStatus" style="font-size: 0.8rem; margin-top: 8px; font-weight: 500;">Checking Key status...</div>
    </div>

    <!-- Chats History -->
    <div class="ai-chat-messages-area" id="aiChatMessages">
        <div class="ai-bubble bot">
            <strong>Gemini Agent:</strong> Xin chào! Tôi là AI Agent bảo mật. Tôi có thể giúp bạn vá các lỗ hổng (SQLi, XSS, SSRF, Command Injection...) trực tiếp trên Lab này. Hãy hỏi tôi hoặc bấm nút <strong>AI Fix</strong> ở các sự kiện tấn công phát hiện được.
        </div>
    </div>

    <!-- Input area -->
    <div class="ai-chat-input-bar">
        <input type="text" id="aiChatInput" placeholder="Hỏi cách fix lỗi hoặc nhập câu hỏi...">
        <button id="aiChatSend"><i class="fas fa-paper-plane"></i></button>
    </div>
</div>

<?php require_once 'includes/footer.php'; ?>
