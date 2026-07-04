<?php
require_once '../includes/db.php';
require_admin();

header('Content-Type: application/json; charset=utf-8');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// Retrieve Gemini API Key from agent config.
function get_gemini_api_key($conn) {
    $stmt = $conn->prepare("SELECT config_value FROM ai_agent_config WHERE config_key = 'gemini_api_key' LIMIT 1");
    if ($stmt) {
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && $row = $res->fetch_assoc()) {
            return $row['config_value'];
        }
    }
    return '';
}

function allowed_gemini_models() {
    return [
        'gemini-2.5-flash' => 'Gemini 2.5 Flash - balanced',
        'gemini-2.5-flash-lite' => 'Gemini 2.5 Flash-Lite - fastest',
        'gemini-2.5-pro' => 'Gemini 2.5 Pro - stronger reasoning',
        'gemini-2.0-flash' => 'Gemini 2.0 Flash - fallback',
        'gemini-flash-latest' => 'Gemini Flash Latest - auto alias',
    ];
}

function normalize_gemini_model($model) {
    $model = trim((string)$model);
    $model = preg_replace('/[^a-zA-Z0-9._:-]/', '', $model);
    return $model !== '' ? $model : 'gemini-2.5-flash';
}

function get_gemini_model($conn) {
    $stmt = $conn->prepare("SELECT config_value FROM ai_agent_config WHERE config_key = 'gemini_model' LIMIT 1");
    if ($stmt) {
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && $row = $res->fetch_assoc()) {
            return normalize_gemini_model($row['config_value']);
        }
    }
    return 'gemini-2.5-flash';
}

function save_gemini_model($conn, $model) {
    $model = normalize_gemini_model($model);
    $stmt = $conn->prepare("REPLACE INTO ai_agent_config (config_key, config_value) VALUES ('gemini_model', ?)");
    if (!$stmt) return false;
    $stmt->bind_param('s', $model);
    return $stmt->execute();
}

function gemini_generate_url($model, $apiKey) {
    return "https://generativelanguage.googleapis.com/v1beta/models/" . rawurlencode(normalize_gemini_model($model)) . ":generateContent?key=" . $apiKey;
}

function gemini_extract_text($result) {
    return $result['candidates'][0]['content']['parts'][0]['text'] ?? '';
}

function infer_event_type_from_file_path($filePath) {
    if (strpos($filePath, 'login.php') !== false) return 'sql_injection';
    if (strpos($filePath, 'search.php') !== false) return 'sql_injection';
    if (strpos($filePath, 'settings.php') !== false) return 'command_injection';
    if (strpos($filePath, 'preview.php') !== false) return 'ssrf_probe';
    if (strpos($filePath, 'oauth.php') !== false) return 'oauth_scope_escalation';
    if (strpos($filePath, 'messages.php') !== false) return 'idor_messages';
    if (strpos($filePath, 'get_messages.php') !== false) return 'idor_messages';
    if (strpos($filePath, 'send_message.php') !== false) return 'idor_messages';
    if (strpos($filePath, 'index.php') !== false) return 'xss_probe';
    if (strpos($filePath, 'post.php') !== false) return 'xss_probe';
    if (strpos($filePath, 'profile.php') !== false) return 'private_disclosure';
    return 'code_patch';
}

function apply_ai_fix_rule_for_file($conn, $filePath, $admin_id, $summary = null) {
    $event_type = infer_event_type_from_file_path($filePath);
    $route = '/' . ltrim(str_replace('\\', '/', $filePath), '/');
    $summary = $summary ?: 'Quick Protect rule applied because the generated source patch did not match the current file exactly.';
    $route_fix_types = [
        '/login.php' => ['sql_injection'],
        '/search.php' => ['sql_injection', 'xss_probe'],
        '/index.php' => ['xss_probe', 'private_disclosure'],
        '/post.php' => ['xss_probe', 'private_disclosure'],
        '/profile.php' => ['xss_probe', 'private_disclosure'],
        '/messages.php' => ['xss_probe', 'idor_messages'],
        '/fetch_messages.php' => ['xss_probe', 'idor_messages'],
        '/api/get_messages.php' => ['xss_probe', 'idor_messages'],
        '/api/send_message.php' => ['xss_probe', 'idor_messages'],
        '/settings.php' => ['command_injection', 'avatar_upload_bypass', 'xss_probe'],
        '/preview.php' => ['ssrf_probe', 'xss_probe'],
        '/oauth.php' => ['oauth_scope_escalation'],
    ];
    $event_types = $route_fix_types[$route] ?? [$event_type];
    if (!in_array($event_type, $event_types, true)) {
        array_unshift($event_types, $event_type);
    }

    $safe_route = $conn->real_escape_string($route);
    $safe_summary = $conn->real_escape_string($summary);
    foreach ($event_types as $type) {
        $safe_type = $conn->real_escape_string($type);
        $conn->query("
            INSERT INTO ai_fix_rules (event_type, route, source_name, source_url, fix_summary, is_active, created_by, created_at, updated_at)
            VALUES ('$safe_type', '$safe_route', 'ConnectHub Sentinel', 'https://ai.google.dev/gemini-api/docs', '$safe_summary', 1, $admin_id, NOW(), NOW())
            ON DUPLICATE KEY UPDATE is_active=1, fix_summary='$safe_summary', updated_at=NOW()
        ");
        remember_ai_agent_fix($conn, $type, $route, $summary, $admin_id, 'ConnectHub Sentinel', 'https://ai.google.dev/gemini-api/docs');
    }

    return [$event_type, $route];
}

function mark_security_events_protected($conn, $event_type, $route, $summary, $admin_id) {
    $safe_type = $conn->real_escape_string($event_type);
    $safe_route = $conn->real_escape_string($route);
    $safe_summary = $conn->real_escape_string($summary);
    $admin_id = (int)$admin_id;

    $conn->query("
        UPDATE security_events
        SET ai_fixed_at=COALESCE(ai_fixed_at, NOW()),
            ai_fix_summary='$safe_summary',
            resolved_at=COALESCE(resolved_at, NOW()),
            resolved_by=$admin_id
        WHERE deleted_at IS NULL
          AND event_type='$safe_type'
          AND REPLACE(REPLACE(SUBSTRING_INDEX(COALESCE(request_uri, ''), '?', 1), '///', '/'), '//', '/')='$safe_route'
    ");
}

function load_agent_memory_context($conn) {
    $memories = [];
    $res = $conn->query("
        SELECT event_type, route, fix_summary, source_name, updated_at
        FROM ai_agent_memory
        ORDER BY updated_at DESC
        LIMIT 30
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $memories[] = $row;
        }
    }

    if (empty($memories)) {
        return "No persistent agent memory has been trained yet.";
    }

    return json_encode($memories, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

function route_to_source_file($route) {
    $route = normalize_security_route($route);
    if (strpos($route, '/api/') === 0) {
        return __DIR__ . '/../' . ltrim($route, '/');
    }
    return __DIR__ . '/..' . $route;
}

function inspect_source_hotspots($route, $limit = 10) {
    $file = route_to_source_file($route);
    if (!is_file($file)) {
        return [
            'file' => normalize_security_route($route),
            'hotspots' => ['Source file not found for this route.']
        ];
    }

    $patterns = '/\$_GET|\$_POST|\$_REQUEST|\$_FILES|->query\s*\(|mysqli_query|echo\s+|innerHTML|file_get_contents|curl_exec|shell_exec|exec\s*\(|system\s*\(|passthru|move_uploaded_file|include\s*\(|require\s*\(/i';
    $lines = file($file, FILE_IGNORE_NEW_LINES);
    $hotspots = [];
    foreach ($lines as $idx => $line) {
        if (preg_match($patterns, $line)) {
            $hotspots[] = 'line ' . ($idx + 1) . ': ' . trim($line);
            if (count($hotspots) >= $limit) break;
        }
    }

    if (empty($hotspots)) {
        $hotspots[] = 'No obvious risky sink found by static scan.';
    }

    $relative = str_replace('\\', '/', substr($file, strlen(realpath(__DIR__ . '/../')) + 1));
    return [
        'file' => 'app/' . $relative,
        'hotspots' => $hotspots
    ];
}

function load_code_hotspots_context($conn) {
    $routes = [
        '/login.php',
        '/search.php',
        '/index.php',
        '/post.php',
        '/messages.php',
        '/api/get_messages.php',
        '/api/send_message.php',
        '/settings.php',
        '/preview.php',
        '/oauth.php',
    ];

    $res = $conn->query("
        SELECT DISTINCT request_uri
        FROM security_events
        WHERE deleted_at IS NULL
        ORDER BY occurred_at DESC, id DESC
        LIMIT 5
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $route = normalize_security_route($row['request_uri'] ?? '');
            if (!in_array($route, $routes, true)) $routes[] = $route;
        }
    }

    $context = [];
    foreach (array_slice($routes, 0, 14) as $route) {
        $context[$route] = inspect_source_hotspots($route, 6);
    }
    return json_encode($context, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
}

function infer_unknown_attack_research($payload) {
    $p = strtolower(urldecode((string)$payload));
    if (preg_match('/\{\{|\$\{|\bconstructor\b|\bprototype\b/', $p)) {
        return [
            'attack_name' => 'Template / Expression Injection',
            'signature_hint' => 'Template markers such as {{...}}, ${...}, constructor, or prototype access',
            'reference_url' => 'https://owasp.org/www-project-web-security-testing-guide/',
            'fix_guidance' => 'Validate template input, never evaluate user-controlled expressions, escape output, and keep user data as plain text.'
        ];
    }
    if (preg_match('/php:\/\/|data:|expect:|zip:|phar:/', $p)) {
        return [
            'attack_name' => 'PHP Stream Wrapper Abuse',
            'signature_hint' => 'Dangerous wrapper schemes such as php://, data:, expect:, zip:, or phar:',
            'reference_url' => 'https://owasp.org/www-community/attacks/Path_Traversal',
            'fix_guidance' => 'Allowlist URL schemes and local paths, block PHP stream wrappers, and avoid passing user-controlled paths into file APIs.'
        ];
    }
    if (preg_match('/\r|\n|%0d|%0a|set-cookie:|location:/', $p)) {
        return [
            'attack_name' => 'HTTP Header Injection',
            'signature_hint' => 'CRLF/header tokens such as %0d%0a, Set-Cookie, or Location',
            'reference_url' => 'https://owasp.org/www-community/attacks/HTTP_Response_Splitting',
            'fix_guidance' => 'Reject CR/LF in header-bound values, use framework redirect helpers, and encode output before headers are emitted.'
        ];
    }
    if (preg_match('/base64|eval|atob|fromcharcode|javascript:/', $p)) {
        return [
            'attack_name' => 'Obfuscated Script Injection',
            'signature_hint' => 'Obfuscation tokens such as base64, eval, atob, fromCharCode, or javascript:',
            'reference_url' => 'https://owasp.org/www-community/attacks/xss/',
            'fix_guidance' => 'Escape output by context, sanitize allowed HTML, block dangerous URL schemes, and add a strict Content Security Policy.'
        ];
    }
    return [
        'attack_name' => 'Unknown Suspicious Web Payload',
        'signature_hint' => 'Repeated suspicious payload fingerprint on this route',
        'reference_url' => 'https://owasp.org/www-project-top-ten/',
        'fix_guidance' => 'Review the highlighted source sinks, validate input by allowlist, use parameterized APIs, and encode output by context.'
    ];
}

function gemini_research_unknown_attack($apiKey, $model, $route, $payload, $hotspots) {
    if (empty($apiKey)) return null;

    $prompt = "Classify this suspicious web security event for a PHP lab. Use public web-security references such as OWASP or CWE when naming the issue. Return ONLY compact JSON with keys: attack_name, signature_hint, reference_url, fix_guidance.\n\nRoute: $route\nPayload:\n$payload\n\nRelevant source hotspots:\n" . implode("\n", $hotspots);
    $url = gemini_generate_url($model, $apiKey);
    $data = [
        'contents' => [
            [
                'role' => 'user',
                'parts' => [
                    ['text' => $prompt]
                ]
            ]
        ]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 12);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) return null;
    $result = json_decode($response, true);
    $text = gemini_extract_text($result);
    $text = trim(preg_replace('/^```(?:json)?|```$/m', '', trim($text)));
    $jsonStart = strpos($text, '{');
    $jsonEnd = strrpos($text, '}');
    if ($jsonStart === false || $jsonEnd === false) return null;
    $parsed = json_decode(substr($text, $jsonStart, $jsonEnd - $jsonStart + 1), true);
    if (!is_array($parsed) || empty($parsed['attack_name'])) return null;

    return [
        'attack_name' => substr((string)$parsed['attack_name'], 0, 120),
        'signature_hint' => substr((string)($parsed['signature_hint'] ?? 'Gemini learned payload fingerprint'), 0, 255),
        'reference_url' => substr((string)($parsed['reference_url'] ?? 'https://owasp.org/www-project-top-ten/'), 0, 255),
        'fix_guidance' => (string)($parsed['fix_guidance'] ?? 'Validate input, avoid dangerous sinks, and encode output by context.')
    ];
}

// 1. Save API Key Action
if ($action === 'save_key') {
    $key = trim($input['key'] ?? '');
    if (empty($key)) {
        echo json_encode(['error' => 'API Key cannot be empty.']);
        exit;
    }
    
    // Save to persistent agent config so Lab Reset does not erase the agent key.
    $stmt = $conn->prepare("REPLACE INTO ai_agent_config (config_key, config_value) VALUES ('gemini_api_key', ?)");
    if ($stmt) {
        $stmt->bind_param('s', $key);
        if ($stmt->execute()) {
            echo json_encode(['success' => true, 'message' => 'API Key updated successfully!']);
        } else {
            echo json_encode(['error' => 'Database error saving API Key.']);
        }
    } else {
        echo json_encode(['error' => 'SQL prepare failed.']);
    }
    exit;
}

// 1b. Save Model Action
if ($action === 'save_model') {
    $model = normalize_gemini_model($input['model'] ?? '');
    if (save_gemini_model($conn, $model)) {
        echo json_encode(['success' => true, 'message' => 'Model updated successfully!', 'model' => $model]);
    } else {
        echo json_encode(['error' => 'Database error saving model.']);
    }
    exit;
}

// 2. Get API Key Status Action
if ($action === 'get_key_status') {
    $key = get_gemini_api_key($conn);
    $model = get_gemini_model($conn);
    echo json_encode([
        'configured' => !empty($key),
        'masked_key' => !empty($key) ? substr($key, 0, 6) . '...' . substr($key, -4) : '',
        'model' => $model,
        'models' => allowed_gemini_models()
    ]);
    exit;
}

// 3. Chat Action
if ($action === 'chat') {
    $apiKey = get_gemini_api_key($conn);
    $model = get_gemini_model($conn);
    if (empty($apiKey)) {
        echo json_encode(['error' => 'Gemini API Key is not configured. Please open settings inside the Chatbox and enter your key.']);
        exit;
    }

    $message = trim($input['message'] ?? '');
    if (empty($message)) {
        echo json_encode(['error' => 'Message is empty.']);
        exit;
    }

    // Retrieve security context details to guide the AI
    $recent_events = [];
    $res = $conn->query("
        SELECT event_type, severity, request_uri, payload, details, occurred_at 
        FROM security_events 
        WHERE deleted_at IS NULL 
        ORDER BY occurred_at DESC, id DESC 
        LIMIT 10
    ");
    if ($res) {
        while ($row = $res->fetch_assoc()) {
            $recent_events[] = $row;
        }
    }
    $context = json_encode($recent_events, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    $agent_memory = load_agent_memory_context($conn);
    $code_hotspots = load_code_hotspots_context($conn);

    // Context files structure to tell the agent where vulnerability entrypoints exist and how to test them
    $files_map = "
    Lab Guide & Vulnerability Testing Map:
    
    1. SQL Injection - Login:
       - Path: app/login.php
       - Payload: Username 'admin\' AND 1=1 #' / Password: 'any'
       - Goal: Bypass login and access the admin account.
       
    2. SQL Injection - User Search:
       - Path: app/search.php?q=
       - Payload: ' UNION SELECT 1,username,password,email,'default-male.svg' FROM users-- -
       - Goal: Expose password hashes and emails of all users.
       
    3. Reflected XSS - Search:
       - Path: app/search.php?q=
       - Payload: \"><script>alert(document.cookie)</script>
       - Goal: Trigger a popup displaying session cookies.
       
    4. Stored XSS - Feed Post:
       - Path: app/index.php (Feed posting)
       - Payload: <script>alert(document.cookie)</script> or <img src=x onerror=alert(document.cookie)>
       - Goal: Script executes when any user loads the feed.
       
    5. Stored XSS - Comments:
       - Path: app/post.php?id=<id> (Creating comment)
       - Payload: <img src=x onerror=alert(document.cookie)>
       - Goal: Script executes when any user views the post details.
       
    6. Stored XSS - Private Message:
       - Path: app/messages.php?to=<id> (Sending message)
       - Payload: <img src=x onerror=alert(document.cookie)>
       - Goal: Script executes when recipient opens the private chat.
       
    7. Private Posts Disclosure (IDOR):
       - Path: app/profile.php?id=<id>
       - Exploit: Log in as Bob (bob123), view Alice's profile (id=2).
       - Goal: Disclose and read Alice's private posts.
       
    8. Private Messages Disclosure (IDOR):
       - Path: app/messages.php?to=<id> or app/api/get_messages.php?to=<id>&last_id=0
       - Exploit: Change ID parameter to read conversations of other users.
       
    9. Weak Session / Session Hijacking:
       - Path: app/includes/db.php & app/login.php
       - Vulnerability: session cookie lacks HttpOnly/Secure flags. Remember token is MD5(username + time()).
       
    10. Command Injection - Avatar Upload:
        - Path: app/settings.php
        - Exploit: Rename upload image file to: pwned.jpg'; id; echo '
        - Goal: Exiftool runs the shell command and outputs system identity in the response.
        
    11. Avatar Upload Bypass:
        - Path: app/settings.php
        - Exploit: Upload plain text test.txt instead of an image.
        - Goal: System accepts the file without verifying MIME-type or extension.
        
    12. SSRF - URL Preview:
        - Path: app/preview.php
        - Payload: file:///etc/passwd or http://127.0.0.1/admin.php
        - Goal: Server fetches local files or internal admin page and prints to user.
        
    13. OAuth Scope Escalation:
        - Path: app/oauth.php
        - Exploit: Query with provider=github&simulate=1&scope=admin or select scope 'admin' on OAuth UI.
        - Goal: Server accepts client scope without verification.
    ";

    $systemInstruction = "You are ConnectHub Sentinel, a focused AppSec assistant for the ConnectHub Vulnerable Social Media PHP Lab.
Your main skill is answering the administrator/student's exact question with the right level of detail.

Intent routing rules:
1. If the user asks for a definition or explanation, such as 'SQL injection la gi', 'XSS la gi', or just names a vulnerability, explain the concept first. Do NOT jump directly to fix steps or patches.
2. If the user asks 'vi sao', 'nguyen nhan', 'tai sao bi loi', explain the root cause in the ConnectHub code and mention the likely file/route.
3. If the user asks 'cach test', 'kiem thu', 'payload', or 'demo', explain only lab-safe testing steps from the Lab Guide and include the matching route/payload.
4. If the user asks 'fix', 'va', 'patch', 'bao ve', 'sua code', or clicks an apply-patch workflow, then provide remediation steps and, when useful, a source patch.
5. If the user asks for a report/slide answer, give a short presentation-style answer, not code.
6. Keep the first answer short and direct. Use bullets only when they make the answer clearer.

Answer shape:
- Start by answering the question directly in 1-2 sentences.
- Add ConnectHub-specific context only after the direct answer.
- Only include code patches when the user clearly asks to fix or patch.
- If a question is ambiguous, state the likely interpretation and answer that first.

Safety boundary:
This is an educational lab owned by the user. Testing instructions must stay scoped to this lab and its listed routes.

$files_map

Recent system security events captured:
$context

Persistent agent memory retained across Lab Reset:
$agent_memory

Relevant source-code hotspots the agent should inspect when explaining fixes:
$code_hotspots

IMPORTANT FORMATTING RULE FOR SOURCE PATCHES:
If you want to suggest a direct source code hotpatch, you MUST format it exactly like this in your markdown output, so the frontend UI can detect and apply it:

```patch
[PATCH] file_path: app/search.php
[SEARCH]
\$q = \$_GET['q'] ?? '';
\$res = \$conn->query(\"SELECT * FROM users WHERE username LIKE '%\$q%'\");
[REPLACE]
\$q = \$_GET['q'] ?? '';
\$stmt = \$conn->prepare(\"SELECT * FROM users WHERE username LIKE ?\");
\$search_term = \"%\$q%\";
\$stmt->bind_param('s', \$search_term);
\$stmt->execute();
\$res = \$stmt->get_result();
```

Make sure the [SEARCH] block matches the vulnerable code EXACTLY, including indentation. Keep the patches clean, correct, and robust. Only use this patch format when the user explicitly asks for a fix, patch, protection, or source-code change.";

    // Call selected Gemini model.
    $url = gemini_generate_url($model, $apiKey);
    
    $data = [
        'contents' => [
            [
                'role' => 'user',
                'parts' => [
                    ['text' => $message]
                ]
            ]
        ],
        'systemInstruction' => [
            'parts' => [
                ['text' => $systemInstruction]
            ]
        ]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        echo json_encode(['error' => 'API connection error: ' . curl_error($ch)]);
        curl_close($ch);
        exit;
    }
    curl_close($ch);

    if ($httpCode !== 200) {
        $errorRes = json_decode($response, true);
        $errMsg = $errorRes['error']['message'] ?? 'Gemini API returned HTTP ' . $httpCode;
        echo json_encode(['error' => 'Gemini API error: ' . $errMsg]);
        exit;
    }

    $result = json_decode($response, true);
    $reply = gemini_extract_text($result) ?: 'Could not parse response from Gemini API.';
    
    echo json_encode(['reply' => $reply]);
    exit;
}

// 4. Learn unknown attack from an event and store the signature for future detections.
if ($action === 'learn_unknown') {
    $eventId = (int)($input['event_id'] ?? 0);
    if ($eventId <= 0) {
        echo json_encode(['error' => 'Invalid event id.']);
        exit;
    }

    $res = $conn->query("SELECT * FROM security_events WHERE id=$eventId AND deleted_at IS NULL LIMIT 1");
    if (!$res || $res->num_rows === 0) {
        echo json_encode(['error' => 'Security event not found.']);
        exit;
    }

    $event = $res->fetch_assoc();
    $route = normalize_security_route($event['request_uri'] ?? '');
    $payload = $event['payload'] ?? '';
    $research = infer_unknown_attack_research($payload);
    $hotspots = inspect_source_hotspots($route, 8);
    $geminiResearch = gemini_research_unknown_attack(get_gemini_api_key($conn), get_gemini_model($conn), $route, $payload, $hotspots['hotspots']);
    if ($geminiResearch) {
        $research = array_merge($research, $geminiResearch);
    }
    $admin_id = $_SESSION['user_id'] ?? null;
    $code_location = $hotspots['file'];

    remember_ai_attack_signature(
        $conn,
        $route,
        $payload,
        $research['attack_name'],
        $research['signature_hint'],
        $research['reference_url'],
        $code_location,
        $research['fix_guidance'],
        $admin_id
    );

    $summary = 'AI learned ' . $research['attack_name'] . ' on ' . $route . '. Next matching payload on this route will be classified as AI Learned Attack.';
    remember_ai_agent_fix($conn, 'learned_attack', $route, $summary, $admin_id, 'ConnectHub AI Agent', $research['reference_url']);

    $safe_summary = $conn->real_escape_string($summary);
    $conn->query("UPDATE security_events SET ai_fix_summary='$safe_summary' WHERE id=$eventId");

    echo json_encode([
        'success' => true,
        'attack_name' => $research['attack_name'],
        'route' => $route,
        'code_location' => $code_location,
        'hotspots' => $hotspots['hotspots'],
        'reference_url' => $research['reference_url'],
        'fix_guidance' => $research['fix_guidance'],
        'message' => $summary
    ]);
    exit;
}

// 5. Apply Patch Action
if ($action === 'apply_patch') {
    $filePath = trim($input['file_path'] ?? '');
    $searchCode = $input['search_code'] ?? '';
    $replaceCode = $input['replace_code'] ?? '';

    if (empty($filePath) || $searchCode === '') {
        echo json_encode(['error' => 'Invalid patch parameters.']);
        exit;
    }

    // Clean target file path, ensuring relative directory traversal is prevented
    $filePath = ltrim($filePath, '/\\');
    // Remove leading 'app/' if AI output included it, because we are already in 'app/api/'
    if (strpos($filePath, 'app/') === 0) {
        $filePath = substr($filePath, 4);
    }
    
    $basePath = realpath(__DIR__ . '/../');
    $targetPath = realpath($basePath . '/' . $filePath);

    if ($targetPath === false || strpos($targetPath, $basePath) !== 0) {
        echo json_encode(['error' => 'Path traversal detected or invalid file location.']);
        exit;
    }

    if (!file_exists($targetPath)) {
        echo json_encode(['error' => 'Target file does not exist: ' . htmlspecialchars($filePath)]);
        exit;
    }

    $content = file_get_contents($targetPath);
    if ($content === false) {
        echo json_encode(['error' => 'Cannot read target file.']);
        exit;
    }

    // Direct search (strip carriage returns to prevent line ending mismatches)
    $normalizedContent = str_replace("\r\n", "\n", $content);
    $normalizedSearch = str_replace("\r\n", "\n", $searchCode);
    $normalizedReplace = str_replace("\r\n", "\n", $replaceCode);

    if (strpos($normalizedContent, $normalizedSearch) === false) {
        // Try searching without trailing/leading whitespace mismatches
        $trimmedContent = trim($normalizedContent);
        $trimmedSearch = trim($normalizedSearch);
        $trimmedReplace = trim($normalizedReplace);
        if (strpos($trimmedContent, $trimmedSearch) === false) {
            $admin_id = $_SESSION['user_id'] ?? 0;
            [$event_type, $route] = apply_ai_fix_rule_for_file(
                $conn,
                $filePath,
                $admin_id,
                'Source patch did not match current code exactly, so ConnectHub Sentinel activated the existing Quick Protect path for this route.'
            );
            mark_security_events_protected(
                $conn,
                $event_type,
                $route,
                'Quick Protect activated because the generated source patch did not match the current source file exactly.',
                $admin_id
            );
            $safe_file_path = $conn->real_escape_string($filePath);
            $safe_payload = $conn->real_escape_string('Route: ' . $route . '; Type: ' . $event_type);
            $conn->query("
                INSERT INTO security_events (user_id, actor_username, ip_address, event_type, severity, details, payload, occurred_at)
                VALUES ($admin_id, 'AI Agent', '127.0.0.1', 'quick_protect_applied_without_patch', 'medium', 'Quick Protect rule activated because source patch did not match $safe_file_path', '$safe_payload', NOW())
            ");
            echo json_encode([
                'success' => true,
                'fallback_rule' => true,
                'message' => 'The generated source patch did not match the current file exactly, so Sentinel activated Quick Protect for ' . htmlspecialchars($route) . ' instead. This route is now protected by the existing lab rule path.'
            ]);
            exit;
        }
        // Use trimmed replace if using trimmed search
        $normalizedContent = str_replace($trimmedSearch, $trimmedReplace, $normalizedContent);
    } else {
        $normalizedContent = str_replace($normalizedSearch, $trimmedReplace ?? $normalizedReplace, $normalizedContent);
    }

    // Create the first backup only. Keeping the original .bak lets Reset Lab State
    // restore the vulnerable lab code even after multiple AI source patches.
    $backupPath = $targetPath . '.bak';
    if (!file_exists($backupPath) && !copy($targetPath, $backupPath)) {
        echo json_encode(['error' => 'Could not create a safety backup copy of the target file. Check write permissions.']);
        exit;
    }

    // Write patched content
    if (file_put_contents($targetPath, $normalizedContent) === false) {
        echo json_encode(['error' => 'Writing patch to file failed. Check permissions on ' . htmlspecialchars($filePath)]);
        exit;
    }

    // Log the hotpatch event
    $admin_id = $_SESSION['user_id'] ?? 0;
    $conn->query("
        INSERT INTO security_events (user_id, actor_username, ip_address, event_type, severity, details, payload, occurred_at)
        VALUES ($admin_id, 'AI Agent', '127.0.0.1', 'ai_hotpatch_applied', 'medium', 'AI Agent successfully hotpatched $filePath', 'File: $filePath', NOW())
    ");

    $summary = "Source code patch applied directly via ConnectHub Sentinel using Gemini.";
    [$event_type, $route] = apply_ai_fix_rule_for_file($conn, $filePath, $admin_id, $summary);
    mark_security_events_protected($conn, $event_type, $route, $summary, $admin_id);

    echo json_encode([
        'success' => true,
        'message' => 'Vulnerability successfully patched! A safety backup was saved to ' . htmlspecialchars($filePath) . '.bak.'
    ]);
    exit;
}

echo json_encode(['error' => 'Unknown action.']);
exit;
