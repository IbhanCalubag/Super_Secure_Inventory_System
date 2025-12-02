<?php

class SecurityManager {
    private $pdo = null;
    
    public function __construct($pdo = null) {
        $this->pdo = $pdo;
    }
    
    public function checkRateLimit($identifier, $max_requests = null, $window = null) {
        if (!$this->pdo) return true;
        
        $max_requests = $max_requests ?: RATE_LIMIT_REQUESTS;
        $window = $window ?: RATE_LIMIT_WINDOW;
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $current_time = time();
        
        try {
            $this->pdo->exec("DELETE FROM rate_limits WHERE timestamp < " . ($current_time - $window));
            
            $stmt = $this->pdo->prepare("SELECT COUNT(*) as count FROM rate_limits WHERE identifier = ? AND ip_address = ? AND timestamp > ?");
            $stmt->execute([$identifier, $ip_address, $current_time - $window]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($result['count'] >= $max_requests) {
                $this->logEvent('rate_limit_exceeded', "Rate limit exceeded for {$identifier}", null, $ip_address);
                return false;
            }
            

            $stmt = $this->pdo->prepare("INSERT INTO rate_limits (identifier, ip_address, timestamp) VALUES (?, ?, ?)");
            $stmt->execute([$identifier, $ip_address, $current_time]);
            
            return true;
        } catch (Exception $e) {
            error_log("Rate limit check failed: " . $e->getMessage());
            return true; 
        }
    }
    
    public function validatePassword($password) {
        if (strlen($password) < PASSWORD_MIN_LENGTH) {
            return "Password must be at least " . PASSWORD_MIN_LENGTH . " characters long";
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            return "Password must contain at least one lowercase letter";
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            return "Password must contain at least one uppercase letter";
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            return "Password must contain at least one number";
        }
        
        if (!preg_match('/[!@#$%^&*()\-_=+{};:,<.>]/', $password)) {
            return "Password must contain at least one special character";
        }
        
        $common_passwords = ['password', '123456', 'qwerty', 'letmein', 'welcome'];
        if (in_array(strtolower($password), $common_passwords)) {
            return "Password is too common. Please choose a more secure password";
        }
        
        return true;
    }
    
    public function checkPasswordAge($user_id) {
        if (!$this->pdo) return true;
        
        try {
            $stmt = $this->pdo->prepare("SELECT password_changed FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && $user['password_changed']) {
                $password_age = time() - strtotime($user['password_changed']);
                $max_age = PASSWORD_MAX_AGE_DAYS * 24 * 60 * 60;
                
                if ($password_age > $max_age) {
                    return false; 
                }
            }
            
            return true;
        } catch (Exception $e) {
            error_log("Password age check failed: " . $e->getMessage());
            return true;
        }
    }
    
    public function isAccountLocked($email) {
        if (!$this->pdo) return false;
        
        try {
            $stmt = $this->pdo->prepare("SELECT locked_until FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
                return true; 
            }
            
            return false;
        } catch (Exception $e) {
            error_log("Account lock check failed: " . $e->getMessage());
            return false;
        }
    }
    
    public function lockAccount($email, $minutes = 30) {
        if (!$this->pdo) return;
        
        try {
            $locked_until = date('Y-m-d H:i:s', time() + ($minutes * 60));
            $stmt = $this->pdo->prepare("UPDATE users SET locked_until = ? WHERE email = ?");
            $stmt->execute([$locked_until, $email]);
            
            $this->logEvent('account_locked', "Account locked for {$minutes} minutes", null, $_SERVER['REMOTE_ADDR']);
        } catch (Exception $e) {
            error_log("Account lock failed: " . $e->getMessage());
        }
    }
    
    public function validateFileUpload($file) {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return "Upload error: " . $file['error'];
        }
        
        if ($file['size'] > MAX_FILE_SIZE) {
            return "File too large. Maximum size: " . (MAX_FILE_SIZE / 1024 / 1024) . "MB";
        }
        
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if (!in_array($file_extension, ALLOWED_FILE_TYPES)) {
            return "Invalid file type. Allowed: " . implode(', ', ALLOWED_FILE_TYPES);
        }
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        $allowed_mimes = ALLOWED_MIME_TYPES;
        if (!in_array($mime_type, $allowed_mimes) || $mime_type !== $allowed_mimes[$file_extension]) {
            return "Invalid file type detected. Upload rejected for security.";
        }
        
        if (strpos($mime_type, 'image/') === 0) {
            $image_info = getimagesize($file['tmp_name']);
            if (!$image_info) {
                return "Invalid image file";
            }
        }
        
        return true;
    }
    
    public function secureFileStorage($file, $upload_dir = null) {
        $upload_dir = $upload_dir ?: __DIR__ . '/uploads';
        
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        
        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $filename = bin2hex(random_bytes(16)) . '.' . $extension;
        $filepath = $upload_dir . '/' . $filename;
        
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            return $filename; 
        }
        
        return false;
    }
    
    public function generateCSRFToken() {
        if (empty($_SESSION['csrf_token']) || time() > $_SESSION['csrf_token_expiry']) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_expiry'] = time() + CSRF_TOKEN_LIFETIME;
        }
        return $_SESSION['csrf_token'];
    }
    
    public function validateCSRFToken($token) {
        if (empty($_SESSION['csrf_token']) || empty($token)) {
            return false;
        }
        
        if (time() > $_SESSION['csrf_token_expiry']) {
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_expiry']);
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token);
    }
    
    public function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeInput'], $input);
        }
        
        $input = trim($input);
        $input = stripslashes($input);
        $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        return $input;
    }
    
    public function sanitizeSQL($input) {
        if (is_array($input)) {
            return array_map([$this, 'sanitizeSQL'], $input);
        }
        
        $sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', 'OR', 'AND'];
        $input = str_ireplace($sql_keywords, '', $input);
        $input = preg_replace('/[^a-zA-Z0-9_\-@\. ]/', '', $input);
        
        return $input;
    }
    
    public function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }
    
    public function validateNumber($number, $min = null, $max = null) {
        if (!is_numeric($number)) return false;
        if ($min !== null && $number < $min) return false;
        if ($max !== null && $number > $max) return false;
        return true;
    }
    
    public function checkLoginAttempts($email) {
        if (!$this->pdo) return true;
        
        try {
            if ($this->isAccountLocked($email)) {
                return false;
            }
            
            $stmt = $this->pdo->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE email = ?");
            $stmt->execute([$email]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result) return true;
            
            $timeout = LOGIN_TIMEOUT_MINUTES * 60;
            if (time() - strtotime($result['last_attempt']) > $timeout) {
                $this->resetLoginAttempts($email);
                return true;
            }
            
            if ($result['attempts'] >= MAX_LOGIN_ATTEMPTS) {
                $this->lockAccount($email);
                return false;
            }
            
            return $result['attempts'] < MAX_LOGIN_ATTEMPTS;
        } catch (Exception $e) {
            error_log("Login attempts check failed: " . $e->getMessage());
            return true;
        }
    }
    
    public function recordLoginAttempt($email, $success) {
        if (!$this->pdo) return;
        
        try {
            if ($success) {
                $this->resetLoginAttempts($email);
                $stmt = $this->pdo->prepare("UPDATE users SET locked_until = NULL WHERE email = ?");
                $stmt->execute([$email]);
                return;
            }
            
            $stmt = $this->pdo->prepare("INSERT INTO login_attempts (email, attempts, last_attempt) 
                                       VALUES (?, 1, datetime('now')) 
                                       ON DUPLICATE KEY UPDATE 
                                       attempts = attempts + 1, last_attempt = datetime('now')");
            $stmt->execute([$email]);
        } catch (Exception $e) {
            error_log("Login attempt recording failed: " . $e->getMessage());
        }
    }
    
    private function resetLoginAttempts($email) {
        if (!$this->pdo) return;
        
        try {
            $stmt = $this->pdo->prepare("DELETE FROM login_attempts WHERE email = ?");
            $stmt->execute([$email]);
        } catch (Exception $e) {
            error_log("Reset login attempts failed: " . $e->getMessage());
        }
    }
    
    public function validateSession() {
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['last_activity'])) {
            return false;
        }
        
        if (!$this->checkPasswordAge($_SESSION['user_id'])) {
            $this->logEvent('password_expired', 'Password has expired', $_SESSION['user_id']);
            session_destroy();
            header('Location: login.php?error=Password expired. Please reset your password.');
            exit;
        }
        
        $timeout = SESSION_TIMEOUT_MINUTES * 60;
        if (time() - $_SESSION['last_activity'] > $timeout) {
            $this->logEvent('session_timeout', 'Session expired due to inactivity', $_SESSION['user_id'] ?? null);
            session_destroy();
            return false;
        }
        
        if (time() - $_SESSION['created'] > 1800) { 
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
        
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    public function logEvent($type, $description, $user_id = null, $ip_address = null) {
        if (!$this->pdo) {
            error_log("Security Event [{$type}]: {$description} - User: {$user_id} - IP: {$ip_address}");
            return;
        }
        
        $ip_address = $ip_address ?: ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        try {
            $stmt = $this->pdo->prepare("INSERT INTO security_logs (type, description, user_id, ip_address, user_agent, timestamp) 
                                       VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)");
            $stmt->execute([$type, $description, $user_id, $ip_address, $user_agent]);
        } catch (Exception $e) {
            error_log("Failed to log security event: " . $e->getMessage());
        }
    }
}

function getSecurityManager() {
    static $securityManager = null;
    if ($securityManager === null) {
        try {
            if (function_exists('getDB')) {
                $pdo = getDB();
                $securityManager = new SecurityManager($pdo);
            } else {
                $securityManager = new SecurityManager(null);
            }
        } catch (Exception $e) {
            $securityManager = new SecurityManager(null);
            error_log("Security manager initialized without database: " . $e->getMessage());
        }
    }
    return $securityManager;
}

function secureSessionStart() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    
    if (empty($_SESSION['created'])) {
        $_SESSION['created'] = time();
    }
    if (empty($_SESSION['last_activity'])) {
        $_SESSION['last_activity'] = time();
    }
    
    $security = getSecurityManager();
    if (!$security->checkRateLimit('page_request', 100, 60)) {
        http_response_code(429);
        die('Too many requests. Please try again later.');
    }
    
    if (isset($_SESSION['user_id'])) {
        if (!$security->validateSession()) {
            header('Location: login.php?error=Session expired');
            exit;
        }
    }
}
?>