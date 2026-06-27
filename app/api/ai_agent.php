<?php
require_once '../includes/db.php';
require_admin();

header('Content-Type: application/json; charset=utf-8');

$input = json_decode(file_get_contents('php://input'), true);
$action = $input['action'] ?? '';

// Retrieve Gemini API Key from app_meta
function get_gemini_api_key($conn) {
    $stmt = $conn->prepare("SELECT meta_value FROM app_meta WHERE meta_key = 'gemini_api_key' LIMIT 1");
    if ($stmt) {
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && $row = $res->fetch_assoc()) {
            return $row['meta_value'];
        }
    }
    return '';
}

// 1. Save API Key Action
if ($action === 'save_key') {
    $key = trim($input['key'] ?? '');
    if (empty($key)) {
        echo json_encode(['error' => 'API Key cannot be empty.']);
        exit;
    }
    
    // Save to database
    $stmt = $conn->prepare("REPLACE INTO app_meta (meta_key, meta_value) VALUES ('gemini_api_key', ?)");
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

// 2. Get API Key Status Action
if ($action === 'get_key_status') {
    $key = get_gemini_api_key($conn);
    echo json_encode([
        'configured' => !empty($key),
        'masked_key' => !empty($key) ? substr($key, 0, 6) . '...' . substr($key, -4) : ''
    ]);
    exit;
}

// 3. Chat Action
if ($action === 'chat') {
    $apiKey = get_gemini_api_key($conn);
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

    // Context files structure to tell the agent where vulnerability entrypoints exist
    $files_map = "
    Relevant Files in Lab Workspace:
    - /login.php: SQL Injection, weak session
    - /search.php: SQL Injection in search query, Reflected XSS
    - /index.php: Feed page, Stored XSS, private post disclosure
    - /post.php: View post details, Stored XSS
    - /profile.php: User profile, IDOR private disclosure
    - /messages.php & /api/get_messages.php & /api/send_message.php: Private messages, IDOR message disclosure, Stored XSS
    - /settings.php: Avatar upload bypass, Command Injection in image metadata processing
    - /preview.php: URL preview, Server-Side Request Forgery (SSRF)
    - /oauth.php: OAuth scope validation, OAuth scope escalation
    - /includes/db.php: PHP database connection & weak session configuration
    ";

    $systemInstruction = "You are a professional AppSec AI Agent in charge of maintaining and patching the ConnectHub Vulnerable Social Media PHP Lab.
You must help the administrator secure the application against OWASP Top 10 vulnerabilities.

$files_map

Recent system security events captured:
$context

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

Make sure the [SEARCH] block matches the vulnerable code EXACTLY, including indentation. Keep the patches clean, correct, and robust. Always explain what the vulnerability was and how your patch remediates it.";

    // Call Gemini API (3.5 Flash)
    $url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent?key=" . $apiKey;
    
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
    $reply = $result['candidates'][0]['content']['parts'][0]['text'] ?? 'Could not parse response from Gemini API.';
    
    echo json_encode(['reply' => $reply]);
    exit;
}

// 4. Apply Patch Action
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
        if (strpos($trimmedContent, $trimmedSearch) === false) {
            echo json_encode([
                'error' => 'Could not locate the exact vulnerable block inside the file. Please check if the patch code has already been applied or contains a discrepancy.'
            ]);
            exit;
        }
        // Use trimmed replace if using trimmed search
        $normalizedContent = str_replace($trimmedSearch, $trimmedReplace, $normalizedContent);
    } else {
        $normalizedContent = str_replace($normalizedSearch, $trimmedReplace ?? $normalizedReplace, $normalizedContent);
    }

    // Create a backup file first
    $backupPath = $targetPath . '.bak';
    if (!copy($targetPath, $backupPath)) {
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

    // Also register an AI Fix rule so the custom rules display shows it protected
    $event_type = 'code_patch';
    if (strpos($filePath, 'login.php') !== false) $event_type = 'sql_injection';
    else if (strpos($filePath, 'search.php') !== false) $event_type = 'sql_injection';
    else if (strpos($filePath, 'settings.php') !== false) $event_type = 'command_injection';
    else if (strpos($filePath, 'preview.php') !== false) $event_type = 'ssrf_probe';
    else if (strpos($filePath, 'oauth.php') !== false) $event_type = 'oauth_scope_escalation';
    else if (strpos($filePath, 'messages.php') !== false) $event_type = 'idor_messages';
    
    $route = '/' . $filePath;
    $summary = $conn->real_escape_string("Source code patch applied directly via Gemini AI Agent.");
    $conn->query("
        INSERT INTO ai_fix_rules (event_type, route, source_name, source_url, fix_summary, is_active, created_by, created_at, updated_at)
        VALUES ('$event_type', '$route', 'Gemini AI Agent', 'https://ai.google.dev', '$summary', 1, $admin_id, NOW(), NOW())
        ON DUPLICATE KEY UPDATE is_active=1, fix_summary='$summary', updated_at=NOW()
    ");

    echo json_encode([
        'success' => true,
        'message' => 'Vulnerability successfully patched! A safety backup was saved to ' . htmlspecialchars($filePath) . '.bak.'
    ]);
    exit;
}

echo json_encode(['error' => 'Unknown action.']);
exit;
