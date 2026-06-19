<?php
require_once 'includes/db.php';
session_destroy();
setcookie('CONNECTHUB_SESSION', '', time()-3600, '/');
setcookie('remember_token', '', time()-3600, '/');
header('Location: login.php');
exit;
