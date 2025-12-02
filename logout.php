<?php
require_once 'config.php';
require_once 'security.php';

$security = getSecurityManager();

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (isset($_SESSION['user_id'])) {
    $security->logEvent('logout', 'User logged out', $_SESSION['user_id']);
}

session_destroy();

setcookie(session_name(), '', time() - 3600, '/');

header('Location: login.php');
exit;
?>