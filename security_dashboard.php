<?php
require_once 'config.php';
require_once 'security.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id']) || $_SESSION['user_role'] !== 'admin') {
    header('Location: login.php');
    exit;
}

require_once 'db.php';
$security = getSecurityManager();
$db = getDB();

$stats = [
    'failed_logins_24h' => $db->query("SELECT COUNT(*) FROM security_logs WHERE type = 'login_failed' AND timestamp >= datetime('now', '-1 day')")->fetchColumn(),
    'csrf_attempts_24h' => $db->query("SELECT COUNT(*) FROM security_logs WHERE type = 'csrf_attempt' AND timestamp >= datetime('now', '-1 day')")->fetchColumn(),
    'rate_limits_24h' => $db->query("SELECT COUNT(*) FROM security_logs WHERE type = 'rate_limit_exceeded' AND timestamp >= datetime('now', '-1 day')")->fetchColumn(),
    'locked_accounts' => $db->query("SELECT COUNT(*) FROM users WHERE locked_until > datetime('now')")->fetchColumn(),
    'total_users' => $db->query("SELECT COUNT(*) FROM users")->fetchColumn(),
    'total_products' => $db->query("SELECT COUNT(*) FROM products")->fetchColumn(),
];

$recent_events = $db->query("SELECT sl.*, u.email as user_email 
                            FROM security_logs sl 
                            LEFT JOIN users u ON sl.user_id = u.id 
                            ORDER BY sl.timestamp DESC 
                            LIMIT 20")->fetchAll(PDO::FETCH_ASSOC);

$security->logEvent('security_dashboard_access', 'Accessed security dashboard', $_SESSION['user_id']);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Security Dashboard - Enhanced Protection</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; margin: 10px 0; }
        .critical { color: #e74c3c; }
        .warning { color: #f39c12; }
        .info { color: #3498db; }
        .success { color: #27ae60; }
        .btn { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin: 5px; }
        .log-entry { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; font-size: 14px; }
        .log-critical { border-left: 5px solid #e74c3c; background: #ffeaea; }
        .log-warning { border-left: 5px solid #f39c12; background: #fff3cd; }
        .log-info { border-left: 5px solid #3498db; background: #e7f7ff; }
        .security-features { background: white; padding: 20px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Enhanced Security Dashboard</h1>
            <p>Comprehensive security monitoring and management</p>
        </div>
        
        <div style="text-align: center; margin: 20px 0;">
            <a href="security_logs.php" class="btn">View Security Logs</a>
            <a href="audit_logs.php" class="btn">View Audit Trail</a>
            <a href="index.php" class="btn" style="background: #27ae60;">Back to Dashboard</a>
            <a href="backup_database.php" class="btn" style="background: #e67e22;">Backup Database</a>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Failed Logins (24h)</h3>
                <div class="stat-number <?= $stats['failed_logins_24h'] > 10 ? 'critical' : 'info' ?>">
                    <?= $stats['failed_logins_24h'] ?>
                </div>
            </div>
            <div class="stat-card">
                <h3>CSRF Attempts (24h)</h3>
                <div class="stat-number <?= $stats['csrf_attempts_24h'] > 0 ? 'warning' : 'success' ?>">
                    <?= $stats['csrf_attempts_24h'] ?>
                </div>
            </div>
            <div class="stat-card">
                <h3>Rate Limits (24h)</h3>
                <div class="stat-number <?= $stats['rate_limits_24h'] > 5 ? 'warning' : 'info' ?>">
                    <?= $stats['rate_limits_24h'] ?>
                </div>
            </div>
            <div class="stat-card">
                <h3>Locked Accounts</h3>
                <div class="stat-number <?= $stats['locked_accounts'] > 0 ? 'warning' : 'success' ?>">
                    <?= $stats['locked_accounts'] ?>
                </div>
            </div>
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="stat-number info"><?= $stats['total_users'] ?></div>
            </div>
            <div class="stat-card">
                <h3>Total Products</h3>
                <div class="stat-number info"><?= $stats['total_products'] ?></div>
            </div>
        </div>
        
        <div class="security-features">
            <h3>Security Features Status</h3>
            <ul>
                <li> Rate Limiting: <strong>Active</strong> (<?= RATE_LIMIT_REQUESTS ?> requests/minute)</li>
                <li> Password Policies: <strong>Enforced</strong> (<?= PASSWORD_MIN_LENGTH ?>+ chars, complexity required)</li>
                <li> Account Lockout: <strong>Active</strong> (<?= MAX_LOGIN_ATTEMPTS ?> attempts max)</li>
                <li> Session Security: <strong>Active</strong> (<?= SESSION_TIMEOUT_MINUTES ?> minute timeout)</li>
                <li> File Upload Security: <strong>Enhanced</strong> (MIME validation, size limits)</li>
                <li> CSRF Protection: <strong>Active</strong> (All forms protected)</li>
                <li> Security Headers: <strong>Enabled</strong> (CSP, HSTS, XSS protection)</li>
                <li> SQL Injection Prevention: <strong>Multi-layered</strong></li>
                <li> Audit Logging: <strong>Comprehensive</strong></li>
                <li> Backup System: <strong>Available</strong></li>
            </ul>
        </div>
        
        <div class="security-features">
            <h3>Recent Security Events</h3>
            <?php if (empty($recent_events)): ?>
                <p>No recent security events.</p>
            <?php else: ?>
                <?php foreach($recent_events as $event): 
                    $log_class = 'log-info';
                    if (strpos($event['type'], 'failed') !== false || strpos($event['type'], 'attempt') !== false) {
                        $log_class = 'log-warning';
                    }
                    if (strpos($event['type'], 'brute_force') !== false || strpos($event['type'], 'csrf') !== false || strpos($event['type'], 'rate_limit') !== false) {
                        $log_class = 'log-critical';
                    }
                ?>
                <div class="log-entry <?= $log_class ?>">
                    <strong><?= htmlspecialchars($event['type']) ?></strong>
                    <br>Description: <?= htmlspecialchars($event['description']) ?>
                    <br>User: <?= $event['user_email'] ? htmlspecialchars($event['user_email']) : 'System' ?>
                    <br>IP: <?= htmlspecialchars($event['ip_address']) ?>
                    <br>Time: <?= $event['timestamp'] ?>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>