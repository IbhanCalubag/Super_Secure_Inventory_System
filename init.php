<?php
require_once 'config.php';
require_once 'db.php';

$db = getDB();

$tables = ['users', 'products', 'security_logs', 'login_attempts', 'audit_logs', 'rate_limits', 'password_history'];
foreach ($tables as $table) {
    try {
        $db->exec("DROP TABLE IF EXISTS $table");
    } catch (Exception $e) {
    }
}

$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    login_count INTEGER DEFAULT 0,
    locked_until DATETIME NULL,
    password_changed DATETIME DEFAULT CURRENT_TIMESTAMP,
    two_factor_secret TEXT NULL,
    two_factor_enabled INTEGER DEFAULT 0
)");

$db->exec("CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    price REAL NOT NULL,
    description TEXT,
    sku TEXT UNIQUE,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)");

$db->exec("CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    description TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
)");

$db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    attempts INTEGER DEFAULT 1,
    last_attempt DATETIME DEFAULT CURRENT_TIMESTAMP
)");

$db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp INTEGER NOT NULL
)");

$db->exec("CREATE TABLE IF NOT EXISTS password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)");

$db->exec("CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id INTEGER,
    old_values TEXT,
    new_values TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
)");

$db->exec("CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp ON security_logs(timestamp)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_security_logs_type ON security_logs(type)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_timestamp ON rate_limits(timestamp)");
$db->exec("CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id)");

$password = password_hash('SecureAdmin123!', PASSWORD_DEFAULT);
try {
    $stmt = $db->prepare("INSERT OR IGNORE INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
    $stmt->execute(['Security Administrator', 'admin@secured-inventory.com', $password, 'admin']);
    
    $admin_id = $db->lastInsertId();
    $stmt = $db->prepare("INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)");
    $stmt->execute([$admin_id, $password]);
    
    echo "<p style='color: green;'>Default admin user created successfully.</p>";
} catch (Exception $e) {
    echo "<p style='color: orange;'>Admin user already exists or creation failed: " . $e->getMessage() . "</p>";
}

$tables_created = $db->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
$expected_tables = ['users', 'products', 'security_logs', 'login_attempts', 'audit_logs', 'rate_limits', 'password_history'];
$missing_tables = array_diff($expected_tables, $tables_created);

if (empty($missing_tables)) {
    echo "<h1 style='color: green;'> Enhanced Secure Database Setup Complete!</h1>";
    echo "<p>All security tables created successfully: " . implode(', ', $tables_created) . "</p>";
} else {
    echo "<h1 style='color: red;'> Database Setup Incomplete!</h1>";
    echo "<p>Missing tables: " . implode(', ', $missing_tables) . "</p>";
}

echo "<div style='background: #e7f7ff; padding: 20px; border-radius: 10px; margin: 20px 0;'>";
echo "<h3>Enhanced Security Features:</h3>";
echo "<ul>";
echo "<li>Web Application Firewall</li>";
echo "<li>Brute Force Protection (Max " . MAX_LOGIN_ATTEMPTS . " attempts)</li>";
echo "<li>Session Timeout (" . SESSION_TIMEOUT_MINUTES . " minutes)</li>";
echo "<li>CSRF Protection</li>";
echo "<li>Security Logging (SIEM)</li>";
echo "<li>Input Validation & Sanitization</li>";
echo "<li>Audit Logging</li>";
echo "<li>Rate Limiting (" . RATE_LIMIT_REQUESTS . " requests/min)</li>";
echo "<li>Password Policies (Complexity, Expiration)</li>";
echo "<li>Account Lockout</li>";
echo "<li>Enhanced File Upload Security</li>";
echo "</ul>";
echo "</div>";

echo "<div style='background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0;'>";
echo "<h3>Default Admin Login:</h3>";
echo "<p><strong>Email:</strong> admin@secured-inventory.com</p>";
echo "<p><strong>Password:</strong> SecureAdmin123!</p>";
echo "</div>";

echo "<a href='login.php' style='background: #4CAF50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px;'>Go to Secure Login Page</a>";
?>