<?php
class AuditLogger {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    public function logAction($action, $resource_type, $resource_id = null, $old_values = null, $new_values = null) {
        $user_id = $_SESSION['user_id'] ?? null;
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
        
        $stmt = $this->pdo->prepare("INSERT INTO audit_logs (user_id, action, resource_type, resource_id, old_values, new_values, ip_address) 
                                   VALUES (?, ?, ?, ?, ?, ?, ?)");
        
        $stmt->execute([
            $user_id,
            $action,
            $resource_type,
            $resource_id,
            $old_values ? json_encode($old_values) : null,
            $new_values ? json_encode($new_values) : null,
            $ip_address
        ]);
    }
    
    public function logProductChange($action, $product_id, $old_values = null, $new_values = null) {
        $this->logAction($action, 'product', $product_id, $old_values, $new_values);
    }
    
    public function logUserAction($action, $user_id = null, $old_values = null, $new_values = null) {
        $this->logAction($action, 'user', $user_id, $old_values, $new_values);
    }
}

function getAuditLogger() {
    static $auditLogger = null;
    if ($auditLogger === null) {
        $pdo = getDB();
        $auditLogger = new AuditLogger($pdo);
    }
    return $auditLogger;
}
?>

