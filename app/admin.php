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
            <section class="security-panel security-panel-wide">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                    <h3 style="margin: 0;"><i class="fas fa-robot"></i> AI Fix Assistant</h3>
                    <form method="POST" style="margin: 0;">
                        <button name="action" value="train_ai_fix_all" class="btn btn-success btn-sm"><i class="fas fa-brain"></i> Train AI Fix All</button>
                    </form>
                </div>
                <p class="text-muted">Trò chuyện với AI để tìm hiểu cách vá các lỗ hổng bảo mật được liệt kê trong README.</p>

                <!-- Chat UI -->
                <div class="ai-chat-container" style="border: 1px solid var(--border); border-radius: 8px; display: flex; flex-direction: column; height: 400px; background: var(--bg-color); margin-top: 16px;">
                    <div id="chat-messages" style="flex: 1; padding: 16px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px;">
                        <div class="chat-message bot" style="align-self: flex-start; background: var(--primary-light); color: var(--text-dark); padding: 10px 14px; border-radius: 12px; max-width: 80%;">
                            <strong><i class="fas fa-robot"></i> AI:</strong> Xin chào! Tôi là AI Fix Assistant. Bạn có thể hỏi tôi về cách vá các lỗ hổng bảo mật trong bài Lab này (ví dụ: SQL Injection, XSS, SSRF, Command Injection, IDOR...). Tôi có thể giúp gì cho bạn?
                        </div>
                    </div>
                    <div class="chat-input-area" style="display: flex; border-top: 1px solid var(--border); padding: 12px; background: var(--bg-light); border-bottom-left-radius: 8px; border-bottom-right-radius: 8px;">
                        <input type="text" id="chat-input" class="form-control" placeholder="Hỏi cách fix lỗi (VD: làm sao để fix XSS?)..." style="flex: 1; border-radius: 20px; padding: 8px 16px; border: 1px solid var(--border);">
                        <button id="chat-send" class="btn btn-primary" style="border-radius: 20px; margin-left: 8px; padding: 8px 16px;"><i class="fas fa-paper-plane"></i></button>
                    </div>
                </div>

                <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const input = document.getElementById('chat-input');
                    const sendBtn = document.getElementById('chat-send');
                    const messages = document.getElementById('chat-messages');

                    const fixKnowledge = {
                        'sql': 'Để fix **SQL Injection**: Bạn nên sử dụng Prepared Statements (ví dụ: `$stmt = $conn->prepare()`) thay vì nối chuỗi trực tiếp vào câu lệnh SQL. Đồng thời, hãy ép kiểu (type casting) các biến đầu vào cho đúng đắn.',
                        'xss': 'Để fix **XSS**: Bạn cần gọi hàm `htmlspecialchars($input, ENT_QUOTES, \'UTF-8\')` khi in bất kỳ dữ liệu nào do người dùng nhập ra màn hình HTML. Đối với dữ liệu cần giữ lại HTML (Rich Text), hãy dùng thư viện như HTMLPurifier.',
                        'command': 'Để fix **Command Injection**: Không bao giờ ghép chuỗi đầu vào thẳng vào các hàm như `shell_exec()`. Nếu thực sự cần, hãy dùng `escapeshellarg()` hoặc cấu hình whitelist cho các tham số hợp lệ.',
                        'ssrf': 'Để fix **SSRF**: Bạn cần kiểm tra URL mục tiêu trước khi fetch: chỉ cho phép `http/https`, kiểm tra domain có nằm trong whitelist không, và đảm bảo IP giải mã ra không thuộc dải mạng nội bộ (127.0.0.1, 10.x.x.x).',
                        'idor': 'Để fix **IDOR / Private Disclosure**: Trong các câu truy vấn cơ sở dữ liệu, hãy luôn thêm điều kiện kiểm tra chủ sở hữu: `WHERE user_id = $_SESSION["user_id"]`. Không bao giờ tin tưởng tham số ID truyền từ URL mà không có bước Authorization.',
                        'session': 'Để fix **Weak Session / Hijacking**: Hãy set cờ `HttpOnly` và `Secure` cho session cookie trong PHP. Khi thiết kế chức năng "Remember me", hãy sinh token ngẫu nhiên bằng `random_bytes()` thay vì hash đơn giản.',
                        'avatar': 'Để fix **Avatar Upload Bypass**: Hãy dùng hàm `finfo_file()` để kiểm tra MIME type thực sự của file (không tin tưởng đuôi file gửi từ client). Từ chối mọi file không phải là ảnh và nhớ đổi tên file thành chuỗi ngẫu nhiên khi lưu.',
                        'oauth': 'Để fix **OAuth Scope Escalation**: Hãy lưu danh sách scope được phép ở phía Backend. Đừng lấy tham số `scope` từ Client gửi lên form. Bổ sung thêm tham số `state` để chống CSRF.'
                    };

                    function appendMessage(text, isUser) {
                        const msg = document.createElement('div');
                        msg.style.alignSelf = isUser ? 'flex-end' : 'flex-start';
                        msg.style.background = isUser ? 'var(--primary)' : 'var(--primary-light)';
                        msg.style.color = isUser ? '#fff' : 'var(--text-dark)';
                        msg.style.padding = '10px 14px';
                        msg.style.borderRadius = '12px';
                        msg.style.maxWidth = '80%';
                        msg.style.lineHeight = '1.5';
                        msg.innerHTML = (isUser ? '<strong>Bạn:</strong> ' : '<strong><i class="fas fa-robot"></i> AI:</strong> ') + text.replace(/\n/g, '<br>');
                        messages.appendChild(msg);
                        messages.scrollTop = messages.scrollHeight;
                    }

                    function handleSend() {
                        const text = input.value.trim();
                        if (!text) return;
                        appendMessage(text, true);
                        input.value = '';

                        const typing = document.createElement('div');
                        typing.style.alignSelf = 'flex-start';
                        typing.style.color = 'var(--muted)';
                        typing.style.fontSize = '0.9rem';
                        typing.innerHTML = '<em>AI đang gõ...</em>';
                        messages.appendChild(typing);
                        messages.scrollTop = messages.scrollHeight;

                        setTimeout(() => {
                            messages.removeChild(typing);
                            const lowerText = text.toLowerCase();
                            let response = "Xin lỗi, tôi chỉ tập trung hỗ trợ hướng dẫn vá các lỗ hổng có trong README của Lab này. Bạn có thể hỏi tôi chi tiết về: SQL, XSS, SSRF, Command Injection, IDOR, Session, Avatar Bypass, hoặc OAuth.";

                            for (const [key, fix] of Object.entries(fixKnowledge)) {
                                if (lowerText.includes(key)) {
                                    response = fix;
                                    break;
                                }
                            }
                            appendMessage(response, false);
                        }, 600);
                    }

                    sendBtn.addEventListener('click', handleSend);
                    input.addEventListener('keypress', (e) => { if (e.key === 'Enter') handleSend(); });
                });
                </script>
            </section>

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
                                <form method="POST" class="security-event-actions">
                                    <input type="hidden" name="id" value="<?= (int)$event['id'] ?>">
                                    <button name="action" value="ai_fix_event" class="btn btn-success btn-sm"><i class="fas fa-wand-magic-sparkles"></i> AI Fix</button>
                                    <button name="action" value="resolve_event" class="btn btn-secondary btn-sm"><i class="fas fa-check-double"></i> Mark reviewed</button>
                                </form>
                            <?php else: ?>
                                <form method="POST" class="security-event-actions">
                                    <input type="hidden" name="id" value="<?= (int)$event['id'] ?>">
                                    <button name="action" value="ai_fix_event" class="btn btn-success btn-sm"><i class="fas fa-wand-magic-sparkles"></i> AI Fix</button>
                                    <small class="text-muted">Reviewed at <?= htmlspecialchars(admin_event_time($event['resolved_at'])) ?></small>
                                </form>
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
<?php require_once 'includes/footer.php'; ?>
