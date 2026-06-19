<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$me = (int)$_SESSION['user_id'];
$preview = $error = '';
$url = '';
$ssrf_ai_fixed = ai_fix_rule_active($conn, 'ssrf_probe', '/preview.php');
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/preview.php');

function preview_host_is_private($host) {
    $ip = gethostbyname($host);
    if (!$ip || $ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) return true;
    if (!filter_var($ip, FILTER_VALIDATE_IP)) return true;
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['url'])) {
    $url = $_POST['url'];
    log_if_suspicious_payload($conn, $url, 'URL preview request', 'url=' . $url);

    $can_fetch = true;
    if ($ssrf_ai_fixed) {
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = $parts['host'] ?? '';
        if (!in_array($scheme, ['http', 'https'], true) || $host === '' || preview_host_is_private($host)) {
            $can_fetch = false;
            $error = 'AI Fix rejected this URL because it targets a blocked scheme or private/internal address.';
        }
    }

    if ($can_fetch) {
        $ch = curl_init($url);
        $curl_options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 10,
        ];
        if ($ssrf_ai_fixed) {
            $curl_options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
            $curl_options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;
        } else {
            // VULN LAB: file:// and other dangerous schemes allowed when AI Fix is not trained.
            $curl_options[CURLOPT_PROTOCOLS] = CURLPROTO_ALL;
        }
        curl_setopt_array($ch, $curl_options);
        $preview = curl_exec($ch);
        $error_msg = curl_error($ch);
        curl_close($ch);

        if ($preview === false) {
            $error = "Error fetching URL: $error_msg";
            $preview = '';
        }
    }

    $safe_url = $conn->real_escape_string($url);
    $safe_result = $conn->real_escape_string(substr($preview, 0, 500));
    $conn->query("INSERT INTO url_previews (user_id, url, result) VALUES ($me, '$safe_url', '$safe_result')");
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="preview-page animate-fade-in">
    <div class="card">
        <h2><i class="fas fa-globe" style="color: var(--primary); margin-right: 6px;"></i> URL Preview</h2>
        <p class="text-muted">Enter a URL to generate a dynamic response preview</p>
        <form method="POST" style="margin-bottom: 20px;">
            <div class="form-group">
                <input type="text" name="url" class="form-control"
                       placeholder="https://example.com"
                       value="<?= htmlspecialchars($url) ?>">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fas fa-arrows-spin"></i> Fetch Preview</button>
        </form>

        <details class="vuln-hint">
            <summary><i class="fas fa-lightbulb"></i> Lab Hint - SSRF Vulnerability</summary>
            <div style="margin-top: 10px;">
                <p style="margin-bottom: 8px;">Try fetching these internal resources:</p>
                <ul>
                    <li><code>file:///etc/passwd</code> - Read local files</li>
                    <li><code>http://127.0.0.1/admin.php</code> - Internal access</li>
                    <li><code>http://169.254.169.254/latest/meta-data/</code> - Cloud metadata</li>
                </ul>
            </div>
        </details>
    </div>

    <?php if ($error): ?>
    <div class="alert alert-danger"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($preview): ?>
    <div class="card preview-result">
        <h4 style="margin-bottom: 12px;"><i class="fas fa-square-poll-horizontal" style="color: var(--accent); margin-right: 6px;"></i> Preview of: <code><?= htmlspecialchars($url) ?></code></h4>
        <div class="preview-content">
            <pre><?= $xss_ai_fixed ? htmlspecialchars($preview) : $preview ?></pre>
        </div>
    </div>
    <?php endif; ?>
</div>
<?php require_once 'includes/footer.php'; ?>
