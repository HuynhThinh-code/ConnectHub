<?php
require_once 'includes/db.php';
if (!isset($_SESSION['user_id'])) { header('Location: login.php'); exit; }
$me = $_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_pass = $_POST['new_password'];
    // VULN: no current password required, no CSRF token
    $hash = md5($new_pass);
    $conn->query("UPDATE users SET password='$hash' WHERE id=$me");
    header('Location: settings.php?msg=Password+updated');
    exit;
}
header('Location: settings.php');
