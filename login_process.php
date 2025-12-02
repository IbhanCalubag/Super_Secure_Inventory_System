<?php
require_once 'config.php';
if (session_status() === PHP_SESSION_NONE) session_start();
require_once 'security.php';
$security = getSecurityManager();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_once 'db.php';
    $db = getDB();

    $email = $security->sanitizeInput($_POST['email']);
    $password = $_POST['password'];

    // Fetch user record
    $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        $current_time = time();
        $max_attempts = 5;
        $ban_duration = 300; // 5 minutes in seconds

        // Check if user is temporarily banned
        if ($user['is_temp_banned'] && $user['temp_ban_expires'] > $current_time) {
            $remaining = ceil(($user['temp_ban_expires'] - $current_time)/60);
            header('Location: login.php?error=Account temporarily banned. Try again in '.$remaining.' minute(s).&email='.urlencode($email));
            exit;
        }

        if (password_verify($password, $user['password'])) {
            // Successful login
            $update = $db->prepare("UPDATE users SET failed_login_attempts=0, last_failed_login=NULL, is_temp_banned=0, temp_ban_expires=NULL WHERE id=:id");
            $update->execute([':id'=>$user['id']]);

            $_SESSION['2fa_user_id'] = $user['id'];
            $_SESSION['2fa_user_name'] = $user['name'];
            $_SESSION['2fa_user_email'] = $user['email'];
            header('Location: 2fa.php');
            exit;
        } else {
            // Failed login
            $failed_attempts = $user['failed_login_attempts'] + 1;

            $temp_ban_expires = null;
            $is_temp_banned = 0;
            $error_msg = "Invalid email or password. ";

            if ($failed_attempts >= $max_attempts) {
                $is_temp_banned = 1;
                $temp_ban_expires = $current_time + $ban_duration;
                $error_msg = "Too many failed attempts. Account temporarily banned for 5 minutes.";
                $failed_attempts = 0; // reset counter after ban
            } else {
                $remaining = $max_attempts - $failed_attempts;
                $error_msg .= "You have $remaining attempt(s) left.";
            }

            $update = $db->prepare("UPDATE users SET failed_login_attempts=:fa, last_failed_login=:lf, is_temp_banned=:tb, temp_ban_expires=:te WHERE id=:id");
            $update->execute([
                ':fa' => $failed_attempts,
                ':lf' => $current_time,
                ':tb' => $is_temp_banned,
                ':te' => $temp_ban_expires,
                ':id' => $user['id']
            ]);

            header('Location: login.php?error='.urlencode($error_msg).'&email='.urlencode($email));
            exit;
        }
    } else {
        // Email not found
        header('Location: login.php?error=Invalid email or password.&email='.urlencode($email));
        exit;
    }
} else {
    header('Location: login.php');
    exit;
}
?>
