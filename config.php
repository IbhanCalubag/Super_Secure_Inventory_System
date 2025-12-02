<?php
if (!defined('DEBUG_MODE')) {
    define('DEBUG_MODE', false); 
}
if (!defined('MAX_LOGIN_ATTEMPTS')) {
    define('MAX_LOGIN_ATTEMPTS', 5);
}
if (!defined('LOGIN_TIMEOUT_MINUTES')) {
    define('LOGIN_TIMEOUT_MINUTES', 15);
}
if (!defined('SESSION_TIMEOUT_MINUTES')) {
    define('SESSION_TIMEOUT_MINUTES', 30);
}
if (!defined('CSRF_TOKEN_LIFETIME')) {
    define('CSRF_TOKEN_LIFETIME', 3600); 
}

if (!defined('MAX_REQUEST_SIZE')) {
    define('MAX_REQUEST_SIZE', 10485760); 
}
if (!defined('RATE_LIMIT_REQUESTS')) {
    define('RATE_LIMIT_REQUESTS', 100); 
}
if (!defined('RATE_LIMIT_WINDOW')) {
    define('RATE_LIMIT_WINDOW', 60); 
}
if (!defined('PASSWORD_MIN_LENGTH')) {
    define('PASSWORD_MIN_LENGTH', 8);
}
if (!defined('PASSWORD_MAX_AGE_DAYS')) {
    define('PASSWORD_MAX_AGE_DAYS', 90); 
}

if (!defined('MAX_FILE_SIZE')) {
    define('MAX_FILE_SIZE', 5242880); 
}
if (!defined('ALLOWED_FILE_TYPES')) {
    define('ALLOWED_FILE_TYPES', ['jpg', 'jpeg', 'png', 'pdf']);
}
if (!defined('ALLOWED_MIME_TYPES')) {
    define('ALLOWED_MIME_TYPES', [
        'jpg' => 'image/jpeg',
        'jpeg' => 'image/jpeg', 
        'png' => 'image/png',
        'pdf' => 'application/pdf'
    ]);
}

if (!headers_sent()) {
    header("X-Frame-Options: DENY");
    header("X-Content-Type-Options: nosniff");
    header("X-XSS-Protection: 1; mode=block");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' data: https:; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self';");
    
    
}

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1); 
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.gc_maxlifetime', SESSION_TIMEOUT_MINUTES * 60);
}

if (DEBUG_MODE) {
    error_reporting(E_ALL);
    ini_set('display_errors', 1);
    ini_set('log_errors', 1);
    ini_set('error_log', __DIR__ . '/php_errors.log');
} else {
    error_reporting(0);
    ini_set('display_errors', 0);
    ini_set('log_errors', 1);
    ini_set('error_log', __DIR__ . '/php_errors.log');
}

if ($_SERVER['CONTENT_LENGTH'] > MAX_REQUEST_SIZE) {
    error_log("Request size exceeded: " . $_SERVER['CONTENT_LENGTH']);
    http_response_code(413);
    die('Request too large');
}
?>