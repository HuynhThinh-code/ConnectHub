<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$me = (int)$_SESSION['user_id'];
$success = $error = '';
$metadata_output = '';
$command_ai_fixed = ai_fix_rule_active($conn, 'command_injection', '/settings.php');
$avatar_ai_fixed = ai_fix_rule_active($conn, 'avatar_upload_bypass', '/settings.php');
$xss_ai_fixed = ai_fix_rule_active($conn, 'xss_probe', '/settings.php');

$user = $conn->query("SELECT * FROM users WHERE id=$me")->fetch_assoc();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = $_POST['full_name'];
    $bio = $_POST['bio'];

    if (!empty($_FILES['avatar']['name'])) {
        $orig = $_FILES['avatar']['name'];
        $tmp = $_FILES['avatar']['tmp_name'];
        log_if_suspicious_payload($conn, $orig, 'Profile avatar upload filename', 'filename=' . $orig);
        $upload_ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
        if (!in_array($upload_ext, ['jpg', 'jpeg', 'png', 'gif', 'webp'], true)) {
            log_security_event($conn, 'avatar_upload_bypass', 'high', 'Avatar upload attempted with a non-image extension', 'filename=' . $orig);
        }

        if ($command_ai_fixed || $avatar_ai_fixed) {
            $ext = $upload_ext;
            $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
            $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            $mime = '';
            if (function_exists('finfo_open')) {
                $finfo = finfo_open(FILEINFO_MIME_TYPE);
                $mime = $finfo ? finfo_file($finfo, $tmp) : '';
                if ($finfo) finfo_close($finfo);
            }
            if ($mime === '' && function_exists('getimagesize')) {
                $image_info = @getimagesize($tmp);
                $mime = $image_info['mime'] ?? '';
            }
            if (!in_array($ext, $allowed, true) || ($avatar_ai_fixed && !in_array($mime, $allowed_mimes, true))) {
                $error = 'AI Fix rejected this avatar type.';
            } else {
                $safe_name = 'avatar_' . $me . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
                $dest = UPLOAD_DIR . $safe_name;
                move_uploaded_file($tmp, $dest);
                $cmd = "exiftool " . escapeshellarg($dest) . " 2>&1";
                $metadata_output = shell_exec($cmd);
                $stmt = $conn->prepare("UPDATE users SET avatar=? WHERE id=?");
                $stmt->bind_param("si", $safe_name, $me);
                $stmt->execute();
                $user['avatar'] = $safe_name;
                $success = 'Avatar updated with AI Fix protection!';
            }
        } else {
            // VULN LAB: command injection via filename when AI Fix is not trained for this route.
            $dest = UPLOAD_DIR . $orig;
            move_uploaded_file($tmp, $dest);
            $cmd = "exiftool '$dest' 2>&1";
            $metadata_output = shell_exec($cmd);
            $conn->query("UPDATE users SET avatar='$orig' WHERE id=$me");
            $user['avatar'] = $orig;
            $success = 'Avatar updated!';
        }
    }

    log_if_suspicious_payload($conn, $bio, 'Profile bio update', 'user_id=' . $me);
    if ($xss_ai_fixed || $command_ai_fixed) {
        $stmt = $conn->prepare("UPDATE users SET full_name=?, bio=? WHERE id=?");
        $stmt->bind_param("ssi", $full_name, $bio, $me);
        $stmt->execute();
    } else {
        // VULN LAB: stored XSS/SQL injection in profile update when AI Fix is not trained.
        $conn->query("UPDATE users SET full_name='$full_name', bio='$bio' WHERE id=$me");
    }
    $user['full_name'] = $full_name;
    $user['bio'] = $bio;
    if (!$success && !$error) $success = 'Profile updated!';
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="settings-page animate-fade-in">
    <div class="card">
        <h2><i class="fas fa-sliders" style="color: var(--primary); margin-right: 6px;"></i> Settings</h2>
        <?php if ($success): ?>
            <div class="alert alert-success"><i class="fas fa-circle-check"></i> <?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-danger"><i class="fas fa-triangle-exclamation"></i> <?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" enctype="multipart/form-data">
            <div class="avatar-preview">
                <img src="/uploads/<?= htmlspecialchars($user['avatar']) ?>" class="avatar-lg" id="avatarPreview">
                <div class="form-group" style="margin-bottom: 0;">
                    <label style="margin-bottom: 8px;"><i class="fas fa-image"></i> Profile Picture</label>
                    <label style="cursor: pointer; font-size: 0.85rem; font-weight: 600; display: inline-flex; align-items: center; color: var(--accent-dark); user-select: none; background: var(--accent-light); padding: 8px 16px; border-radius: 8px; border: 1px solid rgba(78,205,196,0.15); transition: var(--transition-smooth);">
                        <i class="fas fa-upload" style="margin-right: 6px;"></i> Choose Photo
                        <input type="file" name="avatar" style="display: none;" onchange="previewAvatar(this)">
                    </label>
                    <small class="text-muted" style="display: block; margin-top: 8px;"><i class="fas fa-lightbulb" style="color: var(--secondary);"></i> Tip: Image metadata is processed via exiftool</small>
                </div>
            </div>
            <div class="form-group">
                <label><i class="fas fa-id-card"></i> Full Name</label>
                <input type="text" name="full_name" class="form-control" value="<?= htmlspecialchars($user['full_name']) ?>" required>
            </div>
            <div class="form-group">
                <label><i class="fas fa-pen"></i> Bio</label>
                <textarea name="bio" class="form-control" rows="3" placeholder="Tell us about yourself..."><?= htmlspecialchars($user['bio']) ?></textarea>
            </div>
            <button type="submit" class="btn btn-primary"><i class="fas fa-floppy-disk"></i> Save Changes</button>
        </form>

        <?php if ($metadata_output): ?>
        <div class="metadata-box">
            <h4><i class="fas fa-terminal"></i> Image Metadata (exiftool output):</h4>
            <pre><?= htmlspecialchars($metadata_output) ?></pre>
        </div>
        <?php endif; ?>
    </div>

    <div class="card">
        <h3><i class="fas fa-shield-halved" style="color: var(--warning); margin-right: 6px;"></i> Change Password</h3>
        <form method="POST" action="change_password.php">
            <div class="form-group">
                <label><i class="fas fa-lock"></i> New Password</label>
                <input type="password" name="new_password" class="form-control" required placeholder="Enter new password">
            </div>
            <button type="submit" class="btn btn-warning"><i class="fas fa-key"></i> Update Password</button>
        </form>
    </div>
</div>
<script>
function previewAvatar(input) {
    if (input.files && input.files[0]) {
        var reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('avatarPreview').src = e.target.result;
        };
        reader.readAsDataURL(input.files[0]);
    }
}
</script>
<?php require_once 'includes/footer.php'; ?>
