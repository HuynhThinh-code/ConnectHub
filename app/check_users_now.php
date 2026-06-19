<?php
$conn = new mysqli('db', 'root', 'root', 'connecthub');
$res = $conn->query('SELECT id, username, email, full_name FROM users');
while ($row = $res->fetch_assoc()) {
    echo $row['id'] . ' | ' . $row['username'] . ' | ' . $row['email'] . ' | ' . $row['full_name'] . "\n";
}
?>
