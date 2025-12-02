<?php
require_once 'config.php';

echo "<h1> Secure PHP Environment Test</h1>";
echo "<div style='background: #e7f7ff; padding: 20px; border-radius: 10px; margin: 10px 0;'>";
echo "<h3 style='color: #2c3e50;'><i class='fas fa-shield-alt'></i> Security Features Enabled</h3>";
echo "<ul>";
echo "<li>CSRF Protection: " . (defined('CSRF_TOKEN_LIFETIME') ? " Enabled" : " Disabled") . "</li>";
echo "<li>Brute Force Protection: " . (defined('MAX_LOGIN_ATTEMPTS') ? " Enabled (" . MAX_LOGIN_ATTEMPTS . " attempts)" : " Disabled") . "</li>";
echo "<li>Session Timeout: " . (defined('SESSION_TIMEOUT_MINUTES') ? " Enabled (" . SESSION_TIMEOUT_MINUTES . " minutes)" : " Disabled") . "</li>";
echo "<li>Debug Mode: " . (DEBUG_MODE ? " Enabled (Not for production)" : " Disabled") . "</li>";
echo "</ul>";
echo "</div>";

echo "<p>If you can see this, PHP is running correctly.</p>";
echo "<p>Server time: " . date('Y-m-d H:i:s') . "</p>";

try {
    $pdo = new PDO("sqlite:database.sqlite");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "<p style='color: green;'><i class='fas fa-database'></i> Database connection successful!</p>";
    
    $tables = $pdo->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    $security_tables = ['security_logs', 'login_attempts', 'audit_logs'];
    $missing_tables = array_diff($security_tables, $tables);
    
    if (empty($missing_tables)) {
        echo "<p style='color: green;'><i class='fas fa-check-circle'></i> All security tables present</p>";
    } else {
        echo "<p style='color: orange;'><i class='fas fa-exclamation-triangle'></i> Missing security tables: " . implode(', ', $missing_tables) . "</p>";
        echo "<p>Run <a href='init.php'>init.php</a> to create missing tables.</p>";
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'><i class='fas fa-exclamation-circle'></i> Database error: " . $e->getMessage() . "</p>";
}

echo "<div style='background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0;'>";
echo "<h3>Security Function Test</h3>";
require_once 'security.php';
$security = getSecurityManager();

$token = $security->generateCSRFToken();
echo "<p>CSRF Token Generation: " . ($token ? " Working" : " Failed") . "</p>";

$test_input = "<script>alert('xss')</script>";
$sanitized = $security->sanitizeInput($test_input);
echo "<p>Input Sanitization: " . (strpos($sanitized, '<script>') === false ? "Working" : " Failed") . "</p>";

echo "</div>";

echo "<a href='init.php' style='background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;'>Initialize Database</a>";
echo "<a href='login.php' style='background: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;'>Go to Login</a>";
?>


