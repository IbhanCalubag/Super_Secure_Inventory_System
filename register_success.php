<?php
require_once 'config.php';
require_once 'security.php';

$security = getSecurityManager();
session_start();

// Only allow if redirected from registration
if (!isset($_SESSION['new_user_email'])) {
    header('Location: register.php');
    exit;
}

$email = htmlspecialchars($_SESSION['new_user_email']);
unset($_SESSION['new_user_email']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Registration Successful - Inventory System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: url("It's%20all%201's%20and%200's.gif") no-repeat center center fixed; background-size: cover; height:100vh; display:flex; justify-content:center; align-items:center; }
        .success-box { background:#fff; padding:25px 20px; border-radius:15px; box-shadow:0 10px 25px rgba(0,0,0,0.25); width:360px; text-align:center; }
        h1 { color:#27ae60; margin-bottom:15px; font-size:24px; }
        p { font-size:14px; color:#333; margin-bottom:15px; }
        .btn { display:inline-block; padding:10px 20px; background:#667eea; color:white; border:none; border-radius:6px; font-size:14px; text-decoration:none; transition:0.3s; }
        .btn:hover { background:#5a67d8; }
        .security-badge { background:#27ae60; color:white; padding:5px 10px; border-radius:20px; font-size:11px; margin-bottom:15px; display:inline-flex; align-items:center; justify-content:center; gap:4px; }
    </style>
</head>
<body>
    <div class="success-box">
        <div class="security-badge"><i class="fas fa-shield-alt"></i> Enhanced Security Enabled</div>
        <h1>Registration Successful!</h1>
        <p>Your account <strong><?= $email ?></strong> has been created securely.</p>
        <p>You can now login and access the system.</p>
        <a href="login.php" class="btn"><i class="fas fa-sign-in-alt"></i> Go to Login</a>
    </div>
</body>
</html>
