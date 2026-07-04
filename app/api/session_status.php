<?php
require_once '../includes/db.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

echo json_encode([
    'authenticated' => !empty($_SESSION['user_id']),
    'user_id' => $_SESSION['user_id'] ?? null,
    'is_admin' => !empty($_SESSION['is_admin']),
]);
