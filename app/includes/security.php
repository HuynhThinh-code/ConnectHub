<?php
function get_client_ip() {
    $ip = '127.0.0.1';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = trim($_SERVER['HTTP_X_REAL_IP']);
    } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
        $ip = trim($_SERVER['REMOTE_ADDR']);
    }
    
    // Normalize localhost IPv6 to IPv4 loopback
    if ($ip === '::1') {
        return '127.0.0.1';
    }
    
    // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if (strpos($ip, '::ffff:') === 0) {
        return substr($ip, 7);
    }
    
    return $ip;
}

function ensure_admin_schema($conn) {
    static $done = false;
    if ($done) return;
    $done = true;

    $columns = [];
    $res = $conn->query("SHOW COLUMNS FROM users");
    if ($res) {
        while ($row = $res->fetch_assoc()) $columns[$row['Field']] = true;
    }
    if (!isset($columns['is_banned'])) {
        $conn->query("ALTER TABLE users ADD COLUMN is_banned TINYINT(1) DEFAULT 0 AFTER is_admin");
    }
    if (!isset($columns['ban_reason'])) {
        $conn->query("ALTER TABLE users ADD COLUMN ban_reason VARCHAR(255) NULL AFTER is_banned");
    }
    if (!isset($columns['banned_at'])) {
        $conn->query("ALTER TABLE users ADD COLUMN banned_at TIMESTAMP NULL AFTER ban_reason");
    }
    if (!isset($columns['gender'])) {
        $conn->query("ALTER TABLE users ADD COLUMN gender ENUM('male','female') DEFAULT 'male' AFTER full_name");
    }
    $conn->query("UPDATE users SET avatar='default-male.svg' WHERE (avatar IS NULL OR avatar='' OR avatar='default.png') AND (gender='male' OR gender IS NULL)");
    $conn->query("UPDATE users SET avatar='default-female.svg' WHERE (avatar IS NULL OR avatar='' OR avatar='default.png') AND gender='female'");

    $post_columns = [];
    $res = $conn->query("SHOW COLUMNS FROM posts");
    if ($res) {
        while ($row = $res->fetch_assoc()) $post_columns[$row['Field']] = true;
    }
    if (!isset($post_columns['status'])) {
        $conn->query("ALTER TABLE posts ADD COLUMN status ENUM('pending','approved','rejected') DEFAULT 'approved' AFTER is_private");
    }
    if (!isset($post_columns['moderation_note'])) {
        $conn->query("ALTER TABLE posts ADD COLUMN moderation_note TEXT NULL AFTER status");
    }
    if (!isset($post_columns['moderated_by'])) {
        $conn->query("ALTER TABLE posts ADD COLUMN moderated_by INT NULL AFTER moderation_note");
    }
    if (!isset($post_columns['moderated_at'])) {
        $conn->query("ALTER TABLE posts ADD COLUMN moderated_at TIMESTAMP NULL AFTER moderated_by");
    }

    $conn->query("
        CREATE TABLE IF NOT EXISTS security_events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            actor_username VARCHAR(80),
            ip_address VARCHAR(64),
            user_agent VARCHAR(255),
            event_type VARCHAR(80) NOT NULL,
            severity ENUM('low','medium','high','critical') DEFAULT 'medium',
            request_uri TEXT,
            payload TEXT,
            details TEXT,
            resolved_at TIMESTAMP NULL,
            resolved_by INT NULL,
            ai_fixed_at DATETIME NULL,
            ai_fix_summary TEXT NULL,
            deleted_at DATETIME NULL,
            occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $conn->query("
        CREATE TABLE IF NOT EXISTS ai_fix_rules (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(80) NOT NULL,
            route VARCHAR(255) NOT NULL,
            source_name VARCHAR(120) DEFAULT 'GitHub Security Lab SecLab Taskflow Agent',
            source_url VARCHAR(255) DEFAULT 'https://github.com/GitHubSecurityLab/seclab-taskflow-agent',
            fix_summary TEXT,
            is_active TINYINT(1) DEFAULT 1,
            created_by INT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_event_route (event_type, route)
        )
    ");

    $conn->query("
        CREATE TABLE IF NOT EXISTS ai_agent_memory (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_type VARCHAR(80) NOT NULL,
            route VARCHAR(255) NOT NULL,
            fix_summary TEXT,
            source_name VARCHAR(120) DEFAULT 'ConnectHub AI Agent',
            source_url VARCHAR(255) DEFAULT 'https://ai.google.dev',
            learned_by INT NULL,
            learned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_memory_event_route (event_type, route)
        )
    ");

    $conn->query("
        CREATE TABLE IF NOT EXISTS ai_agent_config (
            config_key VARCHAR(80) PRIMARY KEY,
            config_value TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    ");

    $conn->query("
        CREATE TABLE IF NOT EXISTS ai_attack_memory (
            id INT AUTO_INCREMENT PRIMARY KEY,
            fingerprint VARCHAR(64) NOT NULL,
            route VARCHAR(255) NOT NULL,
            event_type VARCHAR(80) NOT NULL DEFAULT 'learned_attack',
            attack_name VARCHAR(120) NOT NULL,
            signature_hint VARCHAR(255) NULL,
            reference_url VARCHAR(255) NULL,
            code_location VARCHAR(255) NULL,
            fix_guidance TEXT NULL,
            seen_count INT DEFAULT 1,
            learned_by INT NULL,
            learned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_attack_fingerprint_route (fingerprint, route)
        )
    ");

    $conn->query("
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(64) UNIQUE NOT NULL,
            blocked_reason VARCHAR(255) NULL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ");

    $event_columns = [];
    $res = $conn->query("SHOW COLUMNS FROM security_events");
    if ($res) {
        while ($row = $res->fetch_assoc()) $event_columns[$row['Field']] = true;
    }
    if (!isset($event_columns['actor_username'])) {
        $conn->query("ALTER TABLE security_events ADD COLUMN actor_username VARCHAR(80) NULL AFTER user_id");
    }
    if (!isset($event_columns['occurred_at'])) {
        $conn->query("ALTER TABLE security_events ADD COLUMN occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER resolved_by");
        $conn->query("UPDATE security_events SET occurred_at=created_at WHERE occurred_at IS NULL");
    }
    if (!isset($event_columns['ai_fixed_at'])) {
        $conn->query("ALTER TABLE security_events ADD COLUMN ai_fixed_at DATETIME NULL AFTER resolved_by");
    }
    if (!isset($event_columns['ai_fix_summary'])) {
        $conn->query("ALTER TABLE security_events ADD COLUMN ai_fix_summary TEXT NULL AFTER ai_fixed_at");
    }
    if (!isset($event_columns['deleted_at'])) {
        $conn->query("ALTER TABLE security_events ADD COLUMN deleted_at DATETIME NULL AFTER ai_fix_summary");
    }

    $fixed_events = $conn->query("
        SELECT event_type, request_uri, ai_fix_summary, resolved_by, ai_fixed_at
        FROM security_events
        WHERE ai_fixed_at IS NOT NULL
          AND deleted_at IS NULL
          AND event_type IN ('sql_injection','xss_probe','path_traversal','command_injection','ssrf_probe','oauth_scope_escalation')
        ORDER BY ai_fixed_at DESC
    ");
    if ($fixed_events) {
        while ($event = $fixed_events->fetch_assoc()) {
            $type = $conn->real_escape_string($event['event_type']);
            $route = $conn->real_escape_string(normalize_security_route($event['request_uri']));
            $summary = $conn->real_escape_string($event['ai_fix_summary'] ?: 'AI Fix rule restored from a fixed security event.');
            $source_name = $conn->real_escape_string(ai_security_source_name());
            $source_url = $conn->real_escape_string(ai_security_source_url());
            $created_by = $event['resolved_by'] ? (int)$event['resolved_by'] : 'NULL';
            $conn->query("
                INSERT INTO ai_fix_rules (event_type, route, source_name, source_url, fix_summary, is_active, created_by, created_at, updated_at)
                VALUES ('$type', '$route', '$source_name', '$source_url', '$summary', 1, $created_by, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    fix_summary=VALUES(fix_summary),
                    is_active=1,
                    updated_at=NOW()
            ");
        }
    }

    $conn->query("
        CREATE TABLE IF NOT EXISTS app_meta (
            meta_key VARCHAR(80) PRIMARY KEY,
            meta_value VARCHAR(255),
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    ");

    $charset_done = false;
    $meta = $conn->query("SELECT meta_value FROM app_meta WHERE meta_key='utf8mb4_migrated'");
    if ($meta && $meta->num_rows > 0) {
        $charset_done = $meta->fetch_assoc()['meta_value'] === '1';
    }
    if (!$charset_done) {
        $conn->query("ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        foreach (['users', 'posts', 'comments', 'messages', 'friend_requests', 'url_previews', 'security_events', 'ai_fix_rules'] as $table) {
            $conn->query("ALTER TABLE $table CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        }
        $conn->query("REPLACE INTO app_meta (meta_key, meta_value) VALUES ('utf8mb4_migrated', '1')");
    }
}

function ai_security_source_name() {
    return 'GitHub Security Lab SecLab Taskflow Agent';
}

function ai_security_source_url() {
    return 'https://github.com/GitHubSecurityLab/seclab-taskflow-agent';
}

function remember_ai_agent_fix($conn, $event_type, $route, $summary, $admin_id = null, $source_name = null, $source_url = null) {
    $event_type = $conn->real_escape_string($event_type);
    $route = $conn->real_escape_string($route);
    $summary = $conn->real_escape_string($summary);
    $source_name = $conn->real_escape_string($source_name ?: ai_security_source_name());
    $source_url = $conn->real_escape_string($source_url ?: ai_security_source_url());
    $learned_by = $admin_id ? (int)$admin_id : 'NULL';

    return $conn->query("
        INSERT INTO ai_agent_memory (event_type, route, fix_summary, source_name, source_url, learned_by, learned_at, updated_at)
        VALUES ('$event_type', '$route', '$summary', '$source_name', '$source_url', $learned_by, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            fix_summary=VALUES(fix_summary),
            source_name=VALUES(source_name),
            source_url=VALUES(source_url),
            learned_by=VALUES(learned_by),
            updated_at=NOW()
    ");
}

function ai_payload_fingerprint($payload) {
    $decoded = urldecode(strtolower((string)$payload));
    $decoded = preg_replace('/[a-z0-9_]{12,}/i', '{token}', $decoded);
    $decoded = preg_replace('/\d+/', '{n}', $decoded);
    $decoded = preg_replace('/\s+/', ' ', $decoded);
    return hash('sha256', trim($decoded));
}

function ai_payload_looks_unknown_suspicious($payload) {
    $payload = strtolower((string)$payload);
    $signals = [
        '/%[0-9a-f]{2}/i',
        '/\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b/i',
        '/<[^>]+>/',
        '/\bbase64\b|\beval\b|\bexec\b|\bsystem\b|\bpassthru\b/i',
        '/\.\.|\bcmd\b|\bpowershell\b|\bphp:\/\/|\bdata:|\bexpect:|\bzip:|\bphar:/i',
        '/\{\{|\$\{|\bconstructor\b|\bprototype\b/i',
    ];
    foreach ($signals as $pattern) {
        if (preg_match($pattern, $payload)) return true;
    }
    return false;
}

function ai_known_attack_from_memory($conn, $route, $payload) {
    $fingerprint = $conn->real_escape_string(ai_payload_fingerprint($payload));
    $safe_route = $conn->real_escape_string(normalize_security_route($route));
    $res = $conn->query("
        SELECT *
        FROM ai_attack_memory
        WHERE fingerprint='$fingerprint' AND route='$safe_route'
        LIMIT 1
    ");
    if ($res && $res->num_rows > 0) {
        $memory = $res->fetch_assoc();
        $id = (int)$memory['id'];
        $conn->query("UPDATE ai_attack_memory SET seen_count=seen_count+1, updated_at=NOW() WHERE id=$id");
        return $memory;
    }
    return null;
}

function remember_ai_attack_signature($conn, $route, $payload, $attack_name, $signature_hint, $reference_url, $code_location, $fix_guidance, $admin_id = null) {
    $fingerprint = $conn->real_escape_string(ai_payload_fingerprint($payload));
    $route = $conn->real_escape_string(normalize_security_route($route));
    $attack_name = $conn->real_escape_string(substr($attack_name, 0, 120));
    $signature_hint = $conn->real_escape_string(substr($signature_hint, 0, 255));
    $reference_url = $conn->real_escape_string(substr($reference_url, 0, 255));
    $code_location = $conn->real_escape_string(substr($code_location, 0, 255));
    $fix_guidance = $conn->real_escape_string($fix_guidance);
    $learned_by = $admin_id ? (int)$admin_id : 'NULL';

    return $conn->query("
        INSERT INTO ai_attack_memory (fingerprint, route, event_type, attack_name, signature_hint, reference_url, code_location, fix_guidance, seen_count, learned_by, learned_at, updated_at)
        VALUES ('$fingerprint', '$route', 'learned_attack', '$attack_name', '$signature_hint', '$reference_url', '$code_location', '$fix_guidance', 1, $learned_by, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            attack_name=VALUES(attack_name),
            signature_hint=VALUES(signature_hint),
            reference_url=VALUES(reference_url),
            code_location=VALUES(code_location),
            fix_guidance=VALUES(fix_guidance),
            learned_by=VALUES(learned_by),
            updated_at=NOW()
    ");
}

function normalize_security_route($uri = null) {
    if ($uri === null || $uri === '') {
        $uri = $_SERVER['SCRIPT_NAME'] ?? ($_SERVER['REQUEST_URI'] ?? '');
    }
    $route = explode('?', (string)$uri, 2)[0];
    $route = preg_replace('#/+#', '/', $route);
    $route = '/' . ltrim($route, '/');
    return $route === '/' ? '/' : $route;
}

function collect_request_payload_parts() {
    $ignored = ['password', 'confirm_password', 'new_password', 'current_password'];
    $parts = [
        'uri' => $_SERVER['REQUEST_URI'] ?? '',
        'query' => $_SERVER['QUERY_STRING'] ?? '',
    ];
    foreach ($_GET as $key => $value) {
        $parts['get_' . $key] = is_array($value) ? json_encode($value) : (string)$value;
    }
    foreach ($_POST as $key => $value) {
        if (in_array($key, $ignored, true)) continue;
        $parts['post_' . $key] = is_array($value) ? json_encode($value) : (string)$value;
    }
    foreach ($_FILES as $key => $value) {
        $names = $value['name'] ?? '';
        $parts['file_' . $key] = is_array($names) ? json_encode($names) : (string)$names;
    }
    return $parts;
}

function current_actor_username($conn) {
    if (isset($_SESSION['username']) && $_SESSION['username'] !== '') {
        return $_SESSION['username'];
    }
    if (isset($_SESSION['user_id'])) {
        $uid = (int)$_SESSION['user_id'];
        $res = $conn->query("SELECT username FROM users WHERE id=$uid");
        if ($res && $res->num_rows > 0) {
            return $res->fetch_assoc()['username'];
        }
    }
    return null;
}

function log_security_event($conn, $event_type, $severity, $details, $payload = '', $actor_username = null) {
    $uid = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 'NULL';
    $actor = $actor_username ?: current_actor_username($conn);
    $safe_actor = $actor ? "'" . $conn->real_escape_string(substr($actor, 0, 80)) . "'" : 'NULL';
    $ip = $conn->real_escape_string(get_client_ip());
    $ua = $conn->real_escape_string(substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255));
    $uri = $conn->real_escape_string($_SERVER['REQUEST_URI'] ?? '');
    $type = $conn->real_escape_string($event_type);
    $sev = $conn->real_escape_string($severity);
    $safe_details = $conn->real_escape_string($details);
    $safe_payload = $conn->real_escape_string(substr($payload, 0, 2000));

    $conn->query("
        INSERT INTO security_events (user_id, actor_username, ip_address, user_agent, event_type, severity, request_uri, payload, details, occurred_at, created_at)
        VALUES ($uid, $safe_actor, '$ip', '$ua', '$type', '$sev', '$uri', '$safe_payload', '$safe_details', NOW(), NOW())
    ");
}

function payload_has_security_indicator($payload) {
    $checks = [
        'sql_injection' => '/(\bunion\b.*\bselect\b|\b(?:or|and)\b\s+[\w\'"]+\s*=\s*[\w\'"]+|sleep\s*\(|benchmark\s*\(|--|#|\/\*)/i',
        'xss_probe' => '/(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie|<img\b|<svg\b)/i',
        'path_traversal' => '/(\.\.\/|\.\.\\\\|%2e%2e|\/etc\/passwd|win\.ini)/i',
        'command_injection' => '/(\|\||&&|`|\$\(|\bnc\b|\bcurl\b|\bwget\b|\bchmod\b|\btouch\b|\bwhoami\b|\bid\b)/i',
        'ssrf_probe' => '/(file:\/\/|dict:\/\/|gopher:\/\/|127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|::1)/i',
    ];
    foreach ($checks as $event_type => $pattern) {
        if (preg_match($pattern, $payload)) return $event_type;
    }
    return null;
}

function ai_fix_payload_matches($event_type, $payload) {
    $checks = [
        'sql_injection' => '/(\bunion\b.*\bselect\b|\b(?:or|and)\b\s+[\w\'"]+\s*=\s*[\w\'"]+|sleep\s*\(|benchmark\s*\(|--|#|\/\*)/i',
        'xss_probe' => '/(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie|<img\b|<svg\b)/i',
        'path_traversal' => '/(\.\.\/|\.\.\\\\|%2e%2e|\/etc\/passwd|win\.ini)/i',
        'command_injection' => '/(\|\||&&|`|\$\(|\bnc\b|\bcurl\b|\bwget\b|\bchmod\b|\btouch\b|\bwhoami\b|\bid\b)/i',
        'ssrf_probe' => '/(file:\/\/|dict:\/\/|gopher:\/\/|127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|::1)/i',
        'oauth_scope_escalation' => '/(\badmin\b|\bmoderator\b|\bwrite:admin\b|\bsuperuser\b)/i',
    ];
    return isset($checks[$event_type]) && preg_match($checks[$event_type], $payload);
}

function ai_fix_rule_active($conn, $event_type, $route = null) {
    $route = normalize_security_route($route);
    $safe_type = $conn->real_escape_string($event_type);
    $safe_route = $conn->real_escape_string($route);
    $res = $conn->query("
        SELECT id
        FROM ai_fix_rules
        WHERE is_active=1 AND event_type='$safe_type' AND route='$safe_route'
        LIMIT 1
    ");
    return $res && $res->num_rows > 0;
}

function ai_fix_has_code_patch($route, $event_type) {
    $patched = [
        '/login.php' => ['sql_injection'],
        '/search.php' => ['sql_injection', 'xss_probe'],
        '/index.php' => ['xss_probe', 'private_disclosure'],
        '/post.php' => ['xss_probe'],
        '/profile.php' => ['xss_probe', 'private_disclosure'],
        '/messages.php' => ['xss_probe', 'idor_messages'],
        '/fetch_messages.php' => ['xss_probe', 'idor_messages'],
        '/api/get_messages.php' => ['idor_messages', 'xss_probe'],
        '/api/send_message.php' => ['idor_messages', 'xss_probe'],
        '/settings.php' => ['command_injection', 'xss_probe', 'avatar_upload_bypass'],
        '/preview.php' => ['ssrf_probe', 'xss_probe'],
        '/oauth.php' => ['oauth_scope_escalation'],
        '/includes/db.php' => ['weak_session'],
    ];
    return isset($patched[$route]) && in_array($event_type, $patched[$route], true);
}

function ai_safe_html($value) {
    return nl2br(htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
}

function ai_message_access_allowed($conn, $me, $to) {
    $me = (int)$me;
    $to = (int)$to;
    if ($me <= 0 || $to <= 0 || $me === $to) return false;
    $res = $conn->query("
        SELECT id
        FROM friend_requests
        WHERE status='accepted'
          AND ((sender_id=$me AND receiver_id=$to) OR (sender_id=$to AND receiver_id=$me))
        LIMIT 1
    ");
    return $res && $res->num_rows > 0;
}

function ai_json_escape_messages($messages) {
    foreach ($messages as &$message) {
        if (isset($message['content'])) {
            $message['content'] = htmlspecialchars((string)$message['content'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }
    }
    return $messages;
}

function enforce_ai_fix_rules($conn) {
    static $done = false;
    if ($done) return;
    $done = true;

    $route = normalize_security_route();
    $safe_route = $conn->real_escape_string($route);
    $rules = $conn->query("
        SELECT event_type, fix_summary
        FROM ai_fix_rules
        WHERE is_active=1 AND route='$safe_route'
        ORDER BY updated_at DESC
    ");
    if (!$rules || $rules->num_rows === 0) return;

    $parts = collect_request_payload_parts();
    $payload = implode("\n", $parts);
    while ($rule = $rules->fetch_assoc()) {
        if (!ai_fix_payload_matches($rule['event_type'], $payload)) continue;
        if (ai_fix_has_code_patch($route, $rule['event_type'])) {
            log_security_event(
                $conn,
                'ai_fix_code_patch_' . $rule['event_type'],
                'low',
                'AI Fix secure code path handled a payload on ' . $route,
                $payload
            );
            continue;
        }

        log_security_event(
            $conn,
            'ai_fix_blocked_' . $rule['event_type'],
            'high',
            'AI Fix blocked an exploit attempt on ' . $route,
            $payload
        );
        http_response_code(403);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>AI Fix blocked</title>';
        echo '<style>body{font-family:Arial,sans-serif;background:#f6fff9;color:#1f2937;padding:40px}.box{max-width:720px;margin:auto;background:#fff;border-left:6px solid #27ae60;border-radius:8px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,.08)}h1{color:#1e874b;margin-top:0}code{background:#eef2f7;border-radius:6px;padding:3px 6px}</style>';
        echo '</head><body><div class="box">';
        echo '<h1>AI Fix blocked this request</h1>';
        echo '<p>This route is protected by an active AI Fix rule powered by ' . htmlspecialchars(ai_security_source_name()) . ' guidance.</p>';
        echo '<p><strong>Route:</strong> <code>' . htmlspecialchars($route) . '</code></p>';
        echo '<p><strong>Detected:</strong> <code>' . htmlspecialchars($rule['event_type']) . '</code></p>';
        echo '<p>The original vulnerable lab code is still present, but this AI Fix rule now blocks matching exploit traffic.</p>';
        echo '</div></body></html>';
        exit;
    }
}

function inspect_request_for_intrusion($conn) {
    static $done = false;
    if ($done) return;
    $done = true;

    $parts = collect_request_payload_parts();
    $payload = strtolower(implode("\n", $parts));

    $checks = [
        ['sql_injection', 'critical', '/(\bunion\b.*\bselect\b|\b(?:or|and)\b\s+[\w\'"]+\s*=\s*[\w\'"]+|sleep\s*\(|benchmark\s*\(|--|#|\/\*)/i', 'Possible SQL injection payload'],
        ['xss_probe', 'high', '/(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)/i', 'Possible XSS payload'],
        ['path_traversal', 'high', '/(\.\.\/|\.\.\\\\|%2e%2e|\/etc\/passwd|win\.ini)/i', 'Possible path traversal attempt'],
        ['command_injection', 'critical', '/(\|\||&&|`|\$\(|\bnc\b|\bcurl\b|\bwget\b|\bchmod\b|\btouch\b)/i', 'Possible command injection payload'],
        ['ssrf_probe', 'critical', '/(127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|::1)/i', 'Possible SSRF/internal network probing'],
    ];

    foreach ($checks as $check) {
        if (preg_match($check[2], $payload)) {
            log_security_event($conn, $check[0], $check[1], $check[3], implode("\n", $parts));
            return;
        }
    }

    $raw_payload = implode("\n", $parts);
    $route = normalize_security_route();
    $memory = ai_known_attack_from_memory($conn, $route, $raw_payload);
    if ($memory) {
        log_security_event(
            $conn,
            'learned_attack',
            'high',
            'AI learned attack: ' . $memory['attack_name'] . ' - ' . ($memory['fix_guidance'] ?: 'Known pattern from agent memory'),
            $raw_payload
        );
        return;
    }

    if (ai_payload_looks_unknown_suspicious($raw_payload)) {
        log_security_event(
            $conn,
            'unknown_attack',
            'medium',
            'Unknown suspicious payload. Ask the AI Agent to research and learn this pattern.',
            $raw_payload
        );
    }
}

function log_if_suspicious_payload($conn, $payload, $context, $extra_details = '') {
    $event_type = payload_has_security_indicator($payload);
    if (!$event_type) return false;

    $severity = in_array($event_type, ['sql_injection', 'command_injection', 'ssrf_probe'], true) ? 'critical' : 'high';
    $labels = [
        'sql_injection' => 'Possible SQL injection attempt',
        'xss_probe' => 'Possible XSS/stored script attempt',
        'path_traversal' => 'Possible path traversal attempt',
        'command_injection' => 'Possible command injection attempt',
        'ssrf_probe' => 'Possible SSRF/internal resource access attempt',
    ];
    $details = $context . ': ' . $labels[$event_type];
    if ($extra_details !== '') $details .= ' - ' . $extra_details;
    log_security_event($conn, $event_type, $severity, $details, $payload);
    return true;
}

function require_login() {
    if (!isset($_SESSION['user_id'])) {
        header('Location: login.php');
        exit;
    }
}

function require_admin() {
    require_login();
    if (empty($_SESSION['is_admin'])) {
        header('Location: user.php');
        exit;
    }
}

function require_regular_user() {
    require_login();
    if (!empty($_SESSION['is_admin'])) {
        header('Location: admin.php');
        exit;
    }
}

function enforce_not_banned($conn) {
    if (empty($_SESSION['user_id'])) return;
    $uid = (int)$_SESSION['user_id'];
    $res = $conn->query("SELECT is_banned FROM users WHERE id=$uid");
    if ($res && $res->num_rows > 0) {
        $user = $res->fetch_assoc();
        if (!empty($user['is_banned'])) {
            log_security_event($conn, 'banned_user_access', 'medium', 'Banned user attempted to access the site');
            session_destroy();
            setcookie('CONNECTHUB_SESSION', '', time()-3600, '/');
            setcookie('remember_token', '', time()-3600, '/');
            header('Location: login.php?banned=1');
            exit;
        }
    }
}

function enforce_single_session($conn) {
    if (empty($_SESSION['user_id'])) return;
    $uid = (int)$_SESSION['user_id'];
    $res = $conn->query("SELECT session_token FROM users WHERE id=$uid");
    if ($res && $res->num_rows > 0) {
        $user = $res->fetch_assoc();
        $db_token = $user['session_token'];
        
        if (!empty($db_token) && (!isset($_SESSION['session_token']) || $_SESSION['session_token'] !== $db_token)) {
            log_security_event($conn, 'session_conflict', 'low', 'User logged out due to concurrent login from another device/browser');
            
            $_SESSION = [];
            if (ini_get("session.use_cookies")) {
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            session_destroy();
            setcookie('remember_token', '', time()-3600, '/');
            
            header('Location: /login.php?logged_out_elsewhere=1');
            exit;
        }
    }
}

function enforce_ip_blocking($conn) {
    $ip = get_client_ip();
    if (empty($ip)) return;

    $stmt = $conn->prepare("SELECT blocked_reason FROM blocked_ips WHERE ip_address = ?");
    if ($stmt) {
        $stmt->bind_param('s', $ip);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && $res->num_rows > 0) {
            $row = $res->fetch_assoc();
            $reason = $row['blocked_reason'] ?: 'No reason provided';
            http_response_code(403);
            header('Content-Type: text/html; charset=utf-8');
            echo '<!doctype html><html><head><meta charset="utf-8"><title>Access Denied (IP Blocked)</title>';
            echo '<style>body{font-family:Arial,sans-serif;background:#fff5f5;color:#1f2937;padding:40px}.box{max-width:720px;margin:auto;background:#fff;border-left:6px solid #e53e3e;border-radius:8px;padding:24px;box-shadow:0 12px 30px rgba(0,0,0,.08)}h1{color:#c53030;margin-top:0}code{background:#eef2f7;border-radius:6px;padding:3px 6px}</style>';
            echo '</head><body><div class="box">';
            echo '<h1>Access Denied (IP Blocked)</h1>';
            echo '<p>Your IP address <code>' . htmlspecialchars($ip) . '</code> has been blocked by the system administrator.</p>';
            echo '<p><strong>Reason:</strong> ' . htmlspecialchars($reason) . '</p>';
            echo '</div></body></html>';
            exit;
        }
    }
}
?>
