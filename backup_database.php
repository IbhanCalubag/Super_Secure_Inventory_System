<?php
require_once 'config.php';


function backupDatabase() {
    $db_file = __DIR__ . '/database.sqlite';
    $backup_dir = __DIR__ . '/backups';
    
    if (!is_dir($backup_dir)) {
        mkdir($backup_dir, 0755, true);
    }
    
    $backup_file = $backup_dir . '/database_backup_' . date('Y-m-d_H-i-s') . '.sqlite';
    
    try {
        if (copy($db_file, $backup_file)) {
            if (function_exists('gzcompress')) {
                $compressed_file = $backup_file . '.gz';
                $data = file_get_contents($backup_file);
                $compressed = gzcompress($data, 9);
                file_put_contents($compressed_file, $compressed);
                unlink($backup_file);
                $backup_file = $compressed_file;
            }
            
            $files = glob($backup_dir . '/database_backup_*');
            $now = time();
            foreach ($files as $file) {
                if (is_file($file)) {
                    if ($now - filemtime($file) >= 30 * 24 * 60 * 60) { 
                        unlink($file);
                    }
                }
            }
            
            error_log("Database backup created: " . $backup_file);
            return $backup_file;
        }
    } catch (Exception $e) {
        error_log("Backup failed: " . $e->getMessage());
        return false;
    }
    
    return false;
}

if (php_sapi_name() === 'cli') {
    $result = backupDatabase();
    if ($result) {
        echo "Backup completed: " . $result . "\n";
    } else {
        echo "Backup failed\n";
    }
} else {
    require_once 'security.php';
    
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (!isset($_SESSION['user_id']) || $_SESSION['user_role'] !== 'admin') {
        header('Location: login.php');
        exit;
    }
    
    $security = getSecurityManager();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!$security->validateCSRFToken($_POST['csrf_token'] ?? '')) {
            die("Security token invalid");
        }
        
        $result = backupDatabase();
        if ($result) {
            $security->logEvent('backup_created', 'Database backup created manually', $_SESSION['user_id']);
            echo "<h2 style='color: green;'>Backup Created Successfully!</h2>";
            echo "<p>Backup file: " . htmlspecialchars(basename($result)) . "</p>";
        } else {
            echo "<h2 style='color: red;'>Backup Failed!</h2>";
        }
    } else {
        $csrf_token = $security->generateCSRFToken();
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Database Backup</title>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .btn { background: #e67e22; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }
                .info { background: #e7f7ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1><i class="fas fa-database"></i> Database Backup</h1>
                
                <div class="info">
                    <strong>Backup Information:</strong>
                    <ul>
                        <li>Backups are compressed using GZIP</li>
                        <li>Old backups (30+ days) are automatically deleted</li>
                        <li>Backups are stored in the /backups directory</li>
                        <li>All backup actions are logged for security</li>
                    </ul>
                </div>
                
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                    <button type="submit" class="btn">
                        <i class="fas fa-download"></i> Create Backup Now
                    </button>
                </form>
                
                <div style="margin-top: 20px;">
                    <a href="security_dashboard.php" style="color: #3498db;">Back to Security Dashboard</a> |
                    <a href="index.php" style="color: #3498db;">Back to Main Dashboard</a>
                </div>
            </div>
        </body>
        </html>
        <?php
    }
}
?>