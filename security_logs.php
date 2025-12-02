<?php
require_once 'config.php';

require_once 'security.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

if ($_SESSION['user_role'] !== 'admin') {
    header('Location: index.php?error=Access denied');
    exit;
}

require_once 'db.php';
$security = getSecurityManager();
$security->logEvent('security_access', 'Accessed security logs', $_SESSION['user_id']);

$db = getDB();
$stmt = $db->prepare("SELECT sl.*, u.email as user_email 
                     FROM security_logs sl 
                     LEFT JOIN users u ON sl.user_id = u.id 
                     ORDER BY sl.timestamp DESC 
                     LIMIT 100");
$stmt->execute();
$logs = $stmt->fetchAll(PDO::FETCH_ASSOC);

$stats_stmt = $db->prepare("SELECT type, COUNT(*) as count 
                           FROM security_logs 
                           WHERE timestamp >= datetime('now', '-1 day')
                           GROUP BY type");
$stats_stmt->execute();
$daily_stats = $stats_stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html>
<head>
    <title>Security Logs - Secure Inventory System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .log-entry { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .log-critical { border-left: 5px solid #e74c3c; background: #ffeaea; }
        .log-warning { border-left: 5px solid #f39c12; background: #fff3cd; }
        .log-info { border-left: 5px solid #3498db; background: #e7f7ff; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: center; border-top: 4px solid #3498db; }
        .btn { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-alt"></i> Security Logs & Monitoring</h1>
            <p>Real-time security event tracking and analysis</p>
        </div>
        
        <div class="stats-grid">
            <?php foreach($daily_stats as $stat): ?>
            <div class="stat-card">
                <h3><?= $stat['count'] ?></h3>
                <p><?= ucfirst($stat['type']) ?> Events (24h)</p>
            </div>
            <?php endforeach; ?>
        </div>
        
        <h2>Recent Security Events</h2>
        <?php foreach($logs as $log): 
            $log_class = 'log-info';
            if (strpos($log['type'], 'failed') !== false || strpos($log['type'], 'attempt') !== false) {
                $log_class = 'log-warning';
            }
            if (strpos($log['type'], 'brute_force') !== false || strpos($log['type'], 'csrf') !== false) {
                $log_class = 'log-critical';
            }
        ?>
        <div class="log-entry <?= $log_class ?>">
            <strong><?= htmlspecialchars($log['type']) ?></strong>
            <br>Description: <?= htmlspecialchars($log['description']) ?>
            <br>User: <?= $log['user_email'] ? htmlspecialchars($log['user_email']) : 'System' ?>
            <br>IP: <?= htmlspecialchars($log['ip_address']) ?>
            <br>Time: <?= $log['timestamp'] ?>
            <br>Agent: <?= htmlspecialchars(substr($log['user_agent'], 0, 100)) ?>
        </div>
        <?php endforeach; ?>
        
        <a href="index.php" class="btn">
            <i class="fas fa-arrow-left"></i> Back to Dashboard
        </a>
    </div>
</body>
</html>