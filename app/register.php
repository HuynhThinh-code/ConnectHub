<?php
require_once 'includes/db.php';
$error = $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username  = $conn->real_escape_string($_POST['username']);
    $email     = $conn->real_escape_string($_POST['email']);
    $password  = $_POST['password'];
    $full_name = $conn->real_escape_string($_POST['full_name']);
    $gender    = (isset($_POST['gender']) && $_POST['gender'] === 'female') ? 'female' : 'male';
    $avatar    = $gender === 'female' ? 'default-female.svg' : 'default-male.svg';

    // VULN: no input validation, MD5 password (weak hash)
    $check = $conn->query("SELECT id FROM users WHERE username='$username' OR email='$email'");
    if ($check->num_rows > 0) {
        $error = 'Username or email already exists.';
    } else {
        $pass_hash = md5($password);
        $insert = $conn->query("INSERT INTO users (username, email, password, full_name, gender, avatar) VALUES ('$username','$email','$pass_hash','$full_name','$gender','$avatar')");
        if ($insert) {
            $success = 'Account created! <a href="login.php">Login now</a>';
        } else {
            $error = 'Database error: ' . $conn->error;
        }
    }
}
?>
<?php require_once 'includes/header.php'; ?>
<div class="auth-box animate-fade-in">
    <h2><i class="fas fa-user-plus"></i> Register</h2>
    <?php if ($error): ?>
        <div class="alert alert-danger">
            <i class="fas fa-triangle-exclamation"></i> <?= $error ?>
        </div>
    <?php endif; ?>
    <?php if ($success): ?>
        <div class="alert alert-success">
            <i class="fas fa-circle-check"></i> <?= $success ?>
        </div>
    <?php endif; ?>
    <form method="POST">
        <div class="form-group">
            <label><i class="fas fa-id-card"></i> Full Name</label>
            <input type="text" name="full_name" class="form-control" required placeholder="Enter full name">
        </div>
        <div class="form-group">
            <label><i class="fas fa-user"></i> Username</label>
            <input type="text" name="username" class="form-control" required placeholder="Choose a username">
        </div>
        <div class="form-group">
            <label><i class="fas fa-envelope"></i> Email</label>
            <input type="email" name="email" class="form-control" required placeholder="Enter email address">
        </div>
        <div class="form-group">
            <label><i class="fas fa-venus-mars"></i> Gender</label>
            <div class="gender-options">
                <label>
                    <input type="radio" name="gender" value="male" checked>
                    <span><i class="fas fa-mars"></i> Male</span>
                </label>
                <label>
                    <input type="radio" name="gender" value="female">
                    <span><i class="fas fa-venus"></i> Female</span>
                </label>
            </div>
        </div>
        <div class="form-group">
            <label><i class="fas fa-key"></i> Password</label>
            <div class="password-field">
                <input type="password" name="password" class="form-control" required placeholder="Create a password">
                <button type="button" class="password-toggle" aria-label="Show password" title="Show password"><i class="fas fa-eye"></i></button>
            </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 8px;"><i class="fas fa-user-plus"></i> Create Account</button>
    </form>
    <p>Already have an account? <a href="login.php">Login here</a></p>
</div>
<?php require_once 'includes/footer.php'; ?>
