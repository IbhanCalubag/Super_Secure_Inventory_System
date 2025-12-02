<?php
require_once 'config.php';
require_once 'security.php';

$security = getSecurityManager();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Redirect logged-in users
if (isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$error = '';
$csrf_token = $security->generateCSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$security->checkRateLimit('registration', 3, 3600)) {
        $error = "Too many registration attempts. Please try again later.";
    } elseif (!$security->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Security token invalid. Please try again.";
    } else {
        require_once 'db.php';

        $name = $security->sanitizeInput(trim($_POST['name']));
        $email = $security->sanitizeInput(trim($_POST['email']));
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];
        $favorite_movie = $security->sanitizeInput(trim($_POST['favorite_movie'] ?? ''));

        if (empty($name) || strlen($name) < 2) {
            $error = "Name must be at least 2 characters long";
        } elseif (!$security->validateEmail($email)) {
            $error = "Invalid email format";
        } elseif (empty($favorite_movie)) {
            $error = "Please provide your favorite movie for 2FA";
        } else {
            $password_validation = $security->validatePassword($password);
            if ($password_validation !== true) {
                $error = $password_validation;
            } elseif ($password !== $confirm_password) {
                $error = "Passwords do not match!";
            } else {
                $db = getDB();
                try {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $db->prepare("INSERT INTO users (name, email, password, favorite_movie) VALUES (:name, :email, :password, :favorite_movie)");
                    $stmt->execute([
                        ':name' => $name,
                        ':email' => $email,
                        ':password' => $hashed_password,
                        ':favorite_movie' => $favorite_movie
                    ]);

                    $user_id = $db->lastInsertId();

                    // Save password history
                    $stmt = $db->prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)");
                    $stmt->execute([$user_id, $hashed_password]);

                    // Log registration
                    $security->logEvent('user_registered', 'New user registered via email', $user_id);

                    // Save email to session for success page
                    $_SESSION['new_user_email'] = $email;

                    // Redirect to success page
                    header('Location: register_success.php');
                    exit;

                } catch (PDOException $e) {
                    $error = "Email already exists! Please use a different email.";
                    $security->logEvent('registration_failed', 'Duplicate email attempt: ' . $email, null, $_SERVER['REMOTE_ADDR']);
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Secure Registration - Inventory System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: url("It's%20all%201's%20and%200's.gif") no-repeat center center fixed; background-size: cover; height:100vh; display:flex; justify-content:center; align-items:center; }
        .register-box { background:#fff; padding:15px; border-radius:15px; box-shadow:0 10px 25px rgba(0,0,0,0.25); width:360px; text-align:center; }
        h1 { color:#333; margin-bottom:15px; font-size:24px; }
        .security-badge { background:#27ae60; color:white; padding:5px 10px; border-radius:20px; font-size:11px; margin-bottom:8px; display:inline-flex; align-items:center; justify-content:center; gap:4px; width:100%; }
        .form-group { margin-bottom:8px; text-align:left; }
        label { display:block; margin-bottom:3px; color:#555; font-weight:600; font-size:13px; }
        input { width:100%; padding:6px 8px; border:2px solid #ddd; border-radius:6px; font-size:14px; }
        input:focus { border-color:#667eea; box-shadow:0 0 3px rgba(102,126,234,0.4); outline:none; }
        .btn { background:#667eea; color:white; padding:8px; border:none; border-radius:6px; font-size:14px; cursor:pointer; width:100%; margin-top:6px; transition:0.3s; }
        .btn:hover { background:#5a67d8; }
        .error { background:#ffe7e7; color:#d63031; padding:8px; border-radius:6px; margin-bottom:8px; border-left:4px solid #d63031; text-align:left; font-size:13px; }
        .login-link { text-align:center; margin-top:6px; color:#555; font-size:13px; }
        .login-link a { color:#667eea; text-decoration:none; font-weight:600; }
        .password-requirements { background:#f8f9fa; padding:5px; border-radius:5px; font-size:11px; color:#666; margin-top:3px; }
        .requirement { margin:2px 0; }
        .requirement.met { color:#27ae60; }
        .requirement.unmet { color:#e74c3c; }
        .toggle-eye { position:absolute; right:10px; top:50%; transform:translateY(-50%); cursor:pointer; color:#667eea; }
        .input-container { position:relative; }
    </style>
    <script>
        function validatePassword() {
            const password = document.getElementById('password').value;
            const requirements = {
                length: password.length >= 8,
                lowercase: /[a-z]/.test(password),
                uppercase: /[A-Z]/.test(password),
                number: /[0-9]/.test(password),
                special: /[!@#$%^&*()\-_=+{};:,<.>]/.test(password)
            };

            document.getElementById('req-length').className = requirements.length ? 'requirement met' : 'requirement unmet';
            document.getElementById('req-lowercase').className = requirements.lowercase ? 'requirement met' : 'requirement unmet';
            document.getElementById('req-uppercase').className = requirements.uppercase ? 'requirement met' : 'requirement unmet';
            document.getElementById('req-number').className = requirements.number ? 'requirement met' : 'requirement unmet';
            document.getElementById('req-special').className = requirements.special ? 'requirement met' : 'requirement unmet';

            return Object.values(requirements).every(req => req);
        }
    </script>
</head>
<body>
    <div class="register-box">
        <h1>Secure Account Registration</h1>
        <div class="security-badge"><i class="fas fa-shield-alt"></i> Enhanced Security Enabled</div>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="POST" onsubmit="return validatePassword()" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">

            <div class="form-group">
                <label for="name">Full Name:</label>
                <input type="text" id="name" name="name" required value="<?= isset($_POST['name']) ? htmlspecialchars($_POST['name']) : '' ?>" placeholder="Enter your full name" minlength="2" maxlength="100" autocomplete="off">
            </div>

            <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="email" id="email" name="email" required value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>" placeholder="Enter your email" autocomplete="off">
            </div>

            <div class="form-group">
                <label for="favorite_movie">Favorite Movie (for 2FA):</label>
                <div class="input-container">
                    <input type="password" id="favorite_movie" name="favorite_movie" required 
                           value="<?= isset($_POST['favorite_movie']) ? htmlspecialchars($_POST['favorite_movie']) : '' ?>" 
                           placeholder="Enter your favorite movie" autocomplete="new-password">
                    <i id="toggle_fav_movie" class="fas fa-eye toggle-eye"></i>
                </div>
            </div>

            <div class="form-group">
                <label for="password">Password:</label>
                <div class="input-container">
                    <input type="password" id="password" name="password" required placeholder="Create a secure password" minlength="8" onkeyup="validatePassword()" autocomplete="new-password">
                    <i id="toggle_password" class="fas fa-eye toggle-eye"></i>
                </div>
                <div class="password-requirements">
                    <strong>Password Requirements:</strong>
                    <div id="req-length" class="requirement unmet">At least 8 characters</div>
                    <div id="req-lowercase" class="requirement unmet">One lowercase letter</div>
                    <div id="req-uppercase" class="requirement unmet">One uppercase letter</div>
                    <div id="req-number" class="requirement unmet">One number</div>
                    <div id="req-special" class="requirement unmet">One special character</div>
                </div>
            </div>

            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <div class="input-container">
                    <input type="password" id="confirm_password" name="confirm_password" required placeholder="Confirm your password" autocomplete="new-password">
                    <i id="toggle_confirm_password" class="fas fa-eye toggle-eye"></i>
                </div>
            </div>

            <button type="submit" class="btn">Create Secure Account</button>
        </form>

        <div class="login-link">
            Already have an account? <a href="login.php">Login here</a>
        </div>
    </div>

    <script>
        // Favorite Movie toggle
        const favMovieInput = document.getElementById('favorite_movie');
        const toggleFavMovie = document.getElementById('toggle_fav_movie');
        toggleFavMovie.addEventListener('click', () => {
            if (favMovieInput.type === 'password') {
                favMovieInput.type = 'text';
                toggleFavMovie.classList.replace('fa-eye','fa-eye-slash');
            } else {
                favMovieInput.type = 'password';
                toggleFavMovie.classList.replace('fa-eye-slash','fa-eye');
            }
        });

        // Password toggle
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

        // Confirm Password toggle
        const confirmPasswordInput = document.getElementById('confirm_password');
        const toggleConfirmPassword = document.getElementById('toggle_confirm_password');
        toggleConfirmPassword.addEventListener('click', () => {
            if (confirmPasswordInput.type === 'password') {
                confirmPasswordInput.type = 'text';
                toggleConfirmPassword.classList.replace('fa-eye','fa-eye-slash');
            } else {
                confirmPasswordInput.type = 'password';
                toggleConfirmPassword.classList.replace('fa-eye-slash','fa-eye');
            }
        });
    </script>
</body>
</html>
