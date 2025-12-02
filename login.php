<?php
require_once 'config.php';
require_once 'security.php';

$security = getSecurityManager();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

// Capture error and email from query string
$error = $_GET['error'] ?? '';
$entered_email = $_GET['email'] ?? '';
$csrf_token = $security->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - Secure Inventory System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: url("It's all 1's and 0's.gif") no-repeat center center fixed;
            background-size: cover;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-box {
            background: #fff;
            padding: 40px 35px;
            border-radius: 15px;
            box-shadow: 0 15px 40px rgba(0,0,0,0.3);
            width: 400px;
            text-align: center;
            position: relative;
        }
        .login-box h1 {
            color: #333;
            margin-bottom: 30px;
            font-size: 28px;
        }
        .security-badge {
            background: #27ae60;
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 12px;
            margin-bottom: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 5px;
            width: 100%;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 6px;
            color: #555;
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: 0.3s;
        }
        input:focus {
            border-color: #667eea;
            box-shadow: 0 0 5px rgba(102,126,234,0.5);
            outline: none;
        }
        .btn {
            background: #667eea;
            color: white;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
            transition: 0.3s;
        }
        .btn:hover {
            background: #5a67d8;
        }
        .error {
            background: #ffe7e7;
            color: #d63031;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            border-left: 4px solid #d63031;
            text-align: left;
        }
        .register-link {
            text-align: center;
            margin-top: 20px;
            color: #555;
            font-size: 14px;
        }
        .register-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }

        /* Added for password toggle */
        .input-container { position: relative; }
        .toggle-eye { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); cursor: pointer; color: #667eea; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Login to Your Account</h1>
        <div class="security-badge">
            <i class="fas fa-shield-alt"></i> Enhanced Security Enabled
        </div>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" action="login_process.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required
                       placeholder="Enter your email" autocomplete="off"
                       value="<?= htmlspecialchars($entered_email) ?>">
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <div class="input-container">
                    <input type="password" id="password" name="password" required
                           placeholder="Enter your password" autocomplete="new-password">
                    <i id="toggle_password" class="fas fa-eye toggle-eye"></i>
                </div>
            </div>

            <button type="submit" class="btn">Login</button>
        </form>

        <div class="register-link">
            Don't have an account? <a href="register.php">Register here</a>
        </div>
    </div>

    <script>
        const passwordInput = document.getElementById('password');
        const togglePassword = document.getElementById('toggle_password');

        togglePassword.addEventListener('click', () => {
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                togglePassword.classList.replace('fa-eye','fa-eye-slash');
            } else {
                passwordInput.type = 'password';
                togglePassword.classList.replace('fa-eye-slash','fa-eye');
            }
        });
    </script>
</body>
</html>
