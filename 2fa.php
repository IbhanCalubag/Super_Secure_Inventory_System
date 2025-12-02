<?php
require_once 'config.php';
require_once 'security.php';
if (session_status() === PHP_SESSION_NONE) session_start();
$security = getSecurityManager();

if (!isset($_SESSION['2fa_user_id'])) {
    header('Location: login.php');
    exit;
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_movie = trim($_POST['favorite_movie'] ?? '');
    if (empty($input_movie)) {
        $error = "Please enter your favorite movie for verification.";
    } else {
        require_once 'db.php';
        $db = getDB();
        $stmt = $db->prepare("SELECT favorite_movie FROM users WHERE id = :id");
        $stmt->execute([':id' => $_SESSION['2fa_user_id']]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && strtolower($user['favorite_movie']) === strtolower($input_movie)) {
            $_SESSION['user_id'] = $_SESSION['2fa_user_id'];
            $_SESSION['user_name'] = $_SESSION['2fa_user_name'];
            $_SESSION['user_email'] = $_SESSION['2fa_user_email'];
            unset($_SESSION['2fa_user_id'], $_SESSION['2fa_user_name'], $_SESSION['2fa_user_email']);
            $security->logEvent('login_success', 'User logged in successfully after 2FA', $_SESSION['user_id']);
            header('Location: index.php');
            exit;
        } else {
            $error = "Favorite movie does not match. Try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>2FA Verification - Secure Inventory</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: Arial; background: url("It's%20all%201's%20and%200's.gif") no-repeat center center fixed; background-size: cover; height:100vh; display:flex; justify-content:center; align-items:center; }
        .box { background:#fff; padding:25px; border-radius:12px; box-shadow:0 10px 25px rgba(0,0,0,0.25); width:360px; text-align:center; }
        h1 { margin-bottom:20px; font-size:22px; color:#333; }
        .form-group { margin-bottom:15px; text-align:left; }
        label { display:block; margin-bottom:4px; font-weight:bold; }
        .input-container { position: relative; }
        input { width:100%; padding:12px; border:2px solid #ddd; border-radius:6px; font-size:14px; }
        input:focus { border-color:#667eea; outline:none; box-shadow:0 0 3px rgba(102,126,234,0.4); }
        .btn { background:#667eea; color:#fff; padding:10px; border:none; border-radius:6px; cursor:pointer; width:100%; }
        .btn:hover { background:#5a67d8; }
        .error { background:#ffe7e7; color:#d63031; padding:8px; border-radius:6px; margin-bottom:10px; border-left:4px solid #d63031; }
        .toggle-eye { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #667eea; font-size: 16px; }
    </style>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="box">
        <h1>2-Factor Authentication</h1>
        <?php if ($error): ?><div class="error"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <form method="POST" autocomplete="off">
            <div class="form-group">
                <label for="favorite_movie">Enter Your Favorite Movie</label>
                <div class="input-container">
                    <input type="password" id="favorite_movie" name="favorite_movie" required
                           placeholder="Your favorite movie" autocomplete="off">
                    <i id="toggle_movie" class="fas fa-eye toggle-eye"></i>
                </div>
            </div>
            <button type="submit" class="btn">Verify</button>
        </form>
    </div>

    <script>
        const movieInput = document.getElementById('favorite_movie');
        const toggleMovie = document.getElementById('toggle_movie');

        toggleMovie.addEventListener('click', () => {
            if (movieInput.type === 'password') {
                movieInput.type = 'text';
                toggleMovie.classList.replace('fa-eye','fa-eye-slash');
            } else {
                movieInput.type = 'password';
                toggleMovie.classList.replace('fa-eye-slash','fa-eye');
            }
        });
    </script>
</body>
</html>
