<?php
require_once 'config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once 'security.php';

if (isset($_SESSION['user_id'])) {
    secureSessionStart();
}

if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require_once 'db.php';
require_once 'audit_logger.php';

$db = getDB();
$security = getSecurityManager();
$auditLogger = getAuditLogger();

$security->logEvent('page_access', 'Accessed dashboard', $_SESSION['user_id']);

$user_stmt = $db->prepare("SELECT name, email, created_at, last_login, login_count FROM users WHERE id = :user_id");
$user_stmt->execute([':user_id' => $_SESSION['user_id']]);
$user_info = $user_stmt->fetch(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$security->validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $security->logEvent('csrf_attempt', 'Invalid CSRF token in product operation', $_SESSION['user_id']);
        header('Location: index.php?error=Security token invalid');
        exit;
    }
    
    if (isset($_POST['add_product'])) {
        $name = $security->sanitizeInput($_POST['name']);
        $quantity = (int)$_POST['quantity'];
        $price = (float)$_POST['price'];
        $description = $security->sanitizeInput($_POST['description']);
        $sku = $security->sanitizeInput($_POST['sku']);
        
        if (empty($name) || !$security->validateNumber($quantity, 0) || !$security->validateNumber($price, 0)) {
            $error = "Invalid input data";
        } else {
            $stmt = $db->prepare("INSERT INTO products (name, quantity, price, description, sku, user_id) VALUES (:name, :quantity, :price, :description, :sku, :user_id)");
            $stmt->execute([
                ':name' => $name,
                ':quantity' => $quantity,
                ':price' => $price,
                ':description' => $description,
                ':sku' => $sku ?: null,
                ':user_id' => $_SESSION['user_id']
            ]);
            
            $product_id = $db->lastInsertId();
            $auditLogger->logProductChange('create', $product_id, null, [
                'name' => $name,
                'quantity' => $quantity,
                'price' => $price,
                'description' => $description,
                'sku' => $sku
            ]);
            
            $success = "Product added successfully!";
            $security->logEvent('product_created', 'Product created: ' . $name, $_SESSION['user_id']);
        }
    }
    
    if (isset($_POST['update_product'])) {
        $product_id = (int)$_POST['product_id'];
        $name = $security->sanitizeInput($_POST['name']);
        $quantity = (int)$_POST['quantity'];
        $price = (float)$_POST['price'];
        $description = $security->sanitizeInput($_POST['description']);
        $sku = $security->sanitizeInput($_POST['sku']);
        
        $old_stmt = $db->prepare("SELECT * FROM products WHERE id = :id AND user_id = :user_id");
        $old_stmt->execute([':id' => $product_id, ':user_id' => $_SESSION['user_id']]);
        $old_product = $old_stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($old_product) {
            $stmt = $db->prepare("UPDATE products SET name = :name, quantity = :quantity, price = :price, description = :description, sku = :sku, updated_at = CURRENT_TIMESTAMP WHERE id = :id AND user_id = :user_id");
            $stmt->execute([
                ':name' => $name,
                ':quantity' => $quantity,
                ':price' => $price,
                ':description' => $description,
                ':sku' => $sku ?: null,
                ':id' => $product_id,
                ':user_id' => $_SESSION['user_id']
            ]);
            
            $auditLogger->logProductChange('update', $product_id, [
                'name' => $old_product['name'],
                'quantity' => $old_product['quantity'],
                'price' => $old_product['price'],
                'description' => $old_product['description'],
                'sku' => $old_product['sku']
            ], [
                'name' => $name,
                'quantity' => $quantity,
                'price' => $price,
                'description' => $description,
                'sku' => $sku
            ]);
            
            $success = "Product updated successfully!";
            $security->logEvent('product_updated', 'Product updated: ' . $name, $_SESSION['user_id']);
        }
    }
}

if (isset($_GET['delete'])) {
    $product_id = (int)$_GET['delete'];
    
    $old_stmt = $db->prepare("SELECT * FROM products WHERE id = :id AND user_id = :user_id");
    $old_stmt->execute([':id' => $product_id, ':user_id' => $_SESSION['user_id']]);
    $old_product = $old_stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($old_product) {
        $stmt = $db->prepare("DELETE FROM products WHERE id = :id AND user_id = :user_id");
        $stmt->execute([
            ':id' => $product_id,
            ':user_id' => $_SESSION['user_id']
        ]);
        
        $auditLogger->logProductChange('delete', $product_id, [
            'name' => $old_product['name'],
            'quantity' => $old_product['quantity'],
            'price' => $old_product['price'],
            'description' => $old_product['description'],
            'sku' => $old_product['sku']
        ], null);
        
        $success = "Product deleted successfully!";
        $security->logEvent('product_deleted', 'Product deleted: ' . $old_product['name'], $_SESSION['user_id']);
    }
}

$stmt = $db->prepare("SELECT * FROM products WHERE user_id = :user_id ORDER BY id DESC");
$stmt->execute([':user_id' => $_SESSION['user_id']]);
$products = $stmt->fetchAll(PDO::FETCH_ASSOC);

$total_value = 0;
$total_products = count($products);
$low_stock_count = 0;
$out_of_stock_count = 0;

foreach ($products as $product) {
    $total_value += $product['quantity'] * $product['price'];
    if ($product['quantity'] < 10 && $product['quantity'] > 0) {
        $low_stock_count++;
    }
    if ($product['quantity'] == 0) {
        $out_of_stock_count++;
    }
}

$editing_product = null;
if (isset($_GET['edit'])) {
    $product_id = (int)$_GET['edit'];
    $stmt = $db->prepare("SELECT * FROM products WHERE id = :id AND user_id = :user_id");
    $stmt->execute([':id' => $product_id, ':user_id' => $_SESSION['user_id']]);
    $editing_product = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($editing_product) {
        $security->logEvent('product_edit', 'Started editing product: ' . $editing_product['name'], $_SESSION['user_id']);
    }
}

$login_method = $_SESSION['login_method'] ?? 'email';
$google_profile_picture = $_SESSION['google_profile_picture'] ?? '';
$google_given_name = $_SESSION['google_given_name'] ?? '';
$google_family_name = $_SESSION['google_family_name'] ?? '';

$csrf_token = $security->generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Secure Inventory Management System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
            --dark: #2c3e50;
            --gray: #95a5a6;
        }

        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f7fa; 
            color: #333;
            line-height: 1.6;
        }

        .header {
            background: linear-gradient(135deg, var(--primary), #1a2530);
            color: white;
            padding: 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }

        .top-bar {
            background: rgba(0,0,0,0.1);
            padding: 10px 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }

        .top-bar-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
        }

        .welcome-text {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .login-badge {
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .user-details {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: white;
            background-size: cover;
            background-position: center;
        }

        .logout-btn {
            background: rgba(255,255,255,0.15);
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 6px;
            border: 1px solid rgba(255,255,255,0.2);
            transition: all 0.3s;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .logout-btn:hover {
            background: rgba(255,255,255,0.25);
        }

        .main-header {
            padding: 25px 0;
        }

        .header-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-title h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .header-title p {
            opacity: 0.8;
            font-size: 16px;
        }

        .header-stats {
            display: flex;
            gap: 20px;
        }

        .stat-badge {
            background: rgba(255,255,255,0.1);
            padding: 10px 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.2);
        }

        .stat-number {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }

        .stat-label {
            font-size: 12px;
            opacity: 0.8;
        }

        .main-content {
            padding: 30px 0;
        }

        .content-grid {
            display: grid;
            grid-template-columns: 1fr 350px;
            gap: 30px;
        }

        @media (max-width: 992px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.08);
            text-align: center;
            border-left: 4px solid var(--secondary);
            transition: transform 0.3s, box-shadow 0.3s;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--secondary);
        }

        .stat-card:nth-child(1) { border-color: var(--secondary); }
        .stat-card:nth-child(1)::before { background: var(--secondary); }
        .stat-card:nth-child(2) { border-color: var(--success); }
        .stat-card:nth-child(2)::before { background: var(--success); }
        .stat-card:nth-child(3) { border-color: var(--warning); }
        .stat-card:nth-child(3)::before { background: var(--warning); }
        .stat-card:nth-child(4) { border-color: var(--danger); }
        .stat-card:nth-child(4)::before { background: var(--danger); }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.12);
        }

        .stat-icon {
            font-size: 2.5em;
            margin-bottom: 15px;
            opacity: 0.8;
        }

        .stat-number {
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-card:nth-child(1) .stat-number { color: var(--secondary); }
        .stat-card:nth-child(2) .stat-number { color: var(--success); }
        .stat-card:nth-child(3) .stat-number { color: var(--warning); }
        .stat-card:nth-child(4) .stat-number { color: var(--danger); }

        .stat-label {
            color: var(--gray);
            font-size: 0.9em;
            font-weight: 500;
        }

        .card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.08);
            margin-bottom: 30px;
            overflow: hidden;
        }

        .card-header {
            background: var(--primary);
            color: white;
            padding: 20px 25px;
            border-bottom: 1px solid #eee;
        }

        .card-header h2 {
            font-size: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .card-body {
            padding: 25px;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 2fr 1fr 1fr 1fr auto;
            gap: 15px;
            align-items: end;
        }

        @media (max-width: 768px) {
            .form-grid {
                grid-template-columns: 1fr;
            }
        }

        .form-group {
            margin-bottom: 0;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
            font-size: 14px;
        }

        input, textarea, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }

        input:focus, textarea:focus, select:focus {
            border-color: var(--secondary);
            outline: none;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }

        .btn {
            padding: 12px 24px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-primary {
            background: var(--secondary);
            color: white;
        }

        .btn-primary:hover {
            background: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(52, 152, 219, 0.3);
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-success:hover {
            background: #219653;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(39, 174, 96, 0.3);
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        .btn-danger:hover {
            background: #c0392b;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(231, 76, 60, 0.3);
        }

        .btn-warning {
            background: var(--warning);
            color: white;
        }

        .btn-warning:hover {
            background: #e67e22;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(243, 156, 18, 0.3);
        }

        .btn-sm {
            padding: 8px 16px;
            font-size: 12px;
        }

        .alert {
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            border-left: 4px solid;
            animation: slideIn 0.5s ease-out;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        @keyframes slideIn {
            from { transform: translateY(-20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }

        .alert-success {
            background: #d4edda;
            color: #155724;
            border-color: #c3e6cb;
        }

        .alert-danger {
            background: #f8d7da;
            color: #721c24;
            border-color: #f5c6cb;
        }

        .table-container {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 3px 15px rgba(0,0,0,0.08);
            margin-top: 20px;
            overflow-x: auto;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 800px;
        }

        th {
            background: #f8f9fa;
            padding: 15px 12px;
            text-align: left;
            font-weight: 600;
            color: #555;
            border-bottom: 2px solid #e1e5e9;
            font-size: 14px;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #e1e5e9;
            vertical-align: top;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .low-stock {
            background: #fff3cd !important;
            border-left: 4px solid var(--warning);
        }

        .out-of-stock {
            background: #f8d7da !important;
            border-left: 4px solid var(--danger);
        }

        .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .stock-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
        }

        .stock-low {
            background: #fff3cd;
            color: #856404;
        }

        .stock-out {
            background: #f8d7da;
            color: #721c24;
        }

        .stock-ok {
            background: #d1ecf1;
            color: #0c5460;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: #666;
        }

        .empty-state-icon {
            font-size: 4em;
            margin-bottom: 20px;
            opacity: 0.5;
            color: var(--gray);
        }

        .sidebar {
            background: white;
            border-radius: 12px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.08);
            overflow: hidden;
        }

        .user-profile {
            padding: 25px;
            text-align: center;
            border-bottom: 1px solid #eee;
        }

        .profile-avatar {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            background: var(--secondary);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 15px;
            font-size: 32px;
            color: white;
            font-weight: bold;
            background-size: cover;
            background-position: center;
        }

        .profile-name {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .profile-email {
            color: var(--gray);
            font-size: 14px;
            margin-bottom: 10px;
        }

        .profile-meta {
            font-size: 12px;
            color: var(--gray);
            margin-bottom: 5px;
        }

        .quick-actions {
            padding: 20px;
        }

        .quick-actions h3 {
            font-size: 16px;
            margin-bottom: 15px;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .action-list {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .action-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 12px;
            border-radius: 8px;
            text-decoration: none;
            color: #555;
            transition: background 0.3s;
        }

        .action-item:hover {
            background: #f5f7fa;
        }

        .action-icon {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            background: #f5f7fa;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--secondary);
        }

        .footer {
            text-align: center;
            margin: 40px 0 20px 0;
            color: #888;
            font-size: 0.9em;
        }

        .security-indicator {
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 12px;
            margin-left: 10px;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .security-alert {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 12px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
        }

        .google-badge {
            background: linear-gradient(135deg, #4285F4, #34A853, #FBBC05, #EA4335);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            display: inline-flex;
            align-items: center;
            gap: 5px;
            margin-left: 10px;
        }

        .google-info {
            background: linear-gradient(135deg, #4285F4, #34A853);
            color: white;
            padding: 8px 12px;
            border-radius: 8px;
            margin: 5px 0;
            font-size: 12px;
        }

        .google-profile-section {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid #4285F4;
        }

        .google-profile-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
        }

        .google-profile-avatar {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            border: 3px solid #4285F4;
            background-size: cover;
            background-position: center;
        }

        .google-profile-details {
            flex: 1;
        }

        .google-profile-name {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }

        .google-profile-email {
            color: #666;
            font-size: 14px;
        }

        .google-profile-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            font-size: 12px;
        }

        .google-info-item {
            padding: 5px;
            background: white;
            border-radius: 5px;
            border: 1px solid #e1e5e9;
        }

        .google-info-label {
            font-weight: bold;
            color: #4285F4;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="top-bar">
            <div class="container">
                <div class="top-bar-content">
                    <div class="welcome-text">
                        <i class="fas fa-user-shield"></i>
                        Welcome, <strong><?= htmlspecialchars($_SESSION['user_name']) ?></strong>
                        <span class="security-indicator">
                            <i class="fas fa-shield-alt"></i> Secure Session
                        </span>
                    </div>
                    <div class="user-info">
                        <div class="user-details">
                            <div class="user-avatar" style="<?= $google_profile_picture ? 'background-image: url(' . htmlspecialchars($google_profile_picture) . ')' : '' ?>">
                                <?php if (!$google_profile_picture): ?>
                                    <?= strtoupper(substr($_SESSION['user_name'], 0, 1)) ?>
                                <?php endif; ?>
                            </div>
                            <div>
                                <div><?= htmlspecialchars($_SESSION['user_email']) ?></div>
                                <div class="login-badge">
                                    <i class="fas fa-clock"></i>
                                    Session expires in: <?= ceil((SESSION_TIMEOUT_MINUTES * 60 - (time() - $_SESSION['last_activity'])) / 60) ?> min
                                </div>
                            </div>
                        </div>
                        <a href="logout.php" class="logout-btn">
                            <i class="fas fa-sign-out-alt"></i> Secure Logout
                        </a>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="main-header">
            <div class="container">
                <div class="header-content">
                    <div class="header-title">
                        <h1>Secure Inventory Management System</h1>
                        <p>Enhanced security with activity monitoring and protection</p>
                    </div>
                    <div class="header-stats">
                        <div class="stat-badge">
                            <span class="stat-number"><?= $total_products ?></span>
                            <span class="stat-label">Products</span>
                        </div>
                        <div class="stat-badge">
                            <span class="stat-number">$<?= number_format($total_value, 2) ?></span>
                            <span class="stat-label">Total Value</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="main-content">
            <?php if (isset($success)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> <?= $success ?>
                </div>
            <?php endif; ?>
            
            <?php if (isset($error)): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i> <?= $error ?>
                </div>
            <?php endif; ?>

            <div class="security-alert">
                <i class="fas fa-shield-alt"></i>
                <strong>Security Enabled:</strong> All actions are logged and monitored. Session expires after <?= SESSION_TIMEOUT_MINUTES ?> minutes of inactivity.
            </div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-boxes"></i>
                    </div>
                    <div class="stat-number"><?= $total_products ?></div>
                    <div class="stat-label">Total Products</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-dollar-sign"></i>
                    </div>
                    <div class="stat-number">$<?= number_format($total_value, 2) ?></div>
                    <div class="stat-label">Total Inventory Value</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="stat-number"><?= $low_stock_count ?></div>
                    <div class="stat-label">Low Stock Items</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-times-circle"></i>
                    </div>
                    <div class="stat-number"><?= $out_of_stock_count ?></div>
                    <div class="stat-label">Out of Stock</div>
                </div>
            </div>

            <div class="content-grid">
                <div class="main-column">
                    <div class="card">
                        <div class="card-header">
                            <h2>
                                <i class="fas <?= $editing_product ? 'fa-edit' : 'fa-plus-circle' ?>"></i>
                                <?= $editing_product ? 'Edit Product' : 'Add New Product' ?>
                                <small style="font-size: 12px; opacity: 0.8; margin-left: 10px;">
                                    <i class="fas fa-shield-alt"></i> Secured Form
                                </small>
                            </h2>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <input type="hidden" name="csrf_token" value="<?= $csrf_token ?>">
                                
                                <?php if ($editing_product): ?>
                                    <input type="hidden" name="product_id" value="<?= $editing_product['id'] ?>">
                                <?php endif; ?>
                                
                                <div class="form-grid">
                                    <div class="form-group">
                                        <label for="name">Product Name *</label>
                                        <input type="text" id="name" name="name" required
                                               value="<?= $editing_product ? htmlspecialchars($editing_product['name']) : '' ?>"
                                               placeholder="Enter product name" maxlength="255">
                                    </div>
                                    <div class="form-group">
                                        <label for="quantity">Quantity *</label>
                                        <input type="number" id="quantity" name="quantity" required min="0" max="999999"
                                               value="<?= $editing_product ? $editing_product['quantity'] : '' ?>"
                                               placeholder="0">
                                    </div>
                                    <div class="form-group">
                                        <label for="price">Price ($) *</label>
                                        <input type="number" step="0.01" id="price" name="price" required min="0" max="999999.99"
                                               value="<?= $editing_product ? $editing_product['price'] : '' ?>"
                                               placeholder="0.00">
                                    </div>
                                    <div class="form-group">
                                        <label for="sku">SKU</label>
                                        <input type="text" id="sku" name="sku" maxlength="50"
                                               value="<?= $editing_product ? htmlspecialchars($editing_product['sku']) : '' ?>"
                                               placeholder="Optional stock keeping unit">
                                    </div>
                                    <div class="form-group">
                                        <?php if ($editing_product): ?>
                                            <button type="submit" name="update_product" class="btn btn-success">
                                                <i class="fas fa-save"></i> Update Product
                                            </button>
                                            <a href="index.php" class="btn btn-warning">
                                                <i class="fas fa-times"></i> Cancel
                                            </a>
                                        <?php else: ?>
                                            <button type="submit" name="add_product" class="btn btn-primary">
                                                <i class="fas fa-plus"></i> Add Product
                                            </button>
                                        <?php endif; ?>
                                    </div>
                                </div>
                                <div class="form-group" style="margin-top: 15px;">
                                    <label for="description">Description</label>
                                    <textarea id="description" name="description" rows="2" maxlength="1000"
                                              placeholder="Product description (optional)"><?= $editing_product ? htmlspecialchars($editing_product['description']) : '' ?></textarea>
                                </div>
                            </form>
                        </div>
                    </div>

                    <h2 style="margin: 30px 0 15px 0; color: #333;">
                        <i class="fas fa-list"></i> Your Products (<?= count($products) ?>)
                        <small style="font-size: 12px; color: #666;">
                            <i class="fas fa-history"></i> All changes are audited
                        </small>
                    </h2>
                    
                    <?php if (empty($products)): ?>
                        <div class="empty-state">
                            <div class="empty-state-icon">
                                <i class="fas fa-box-open"></i>
                            </div>
                            <h3 style="color: #666; margin-bottom: 15px;">No products yet!</h3>
                            <p style="color: #888; margin-bottom: 25px;">Start by adding your first product using the form above.</p>
                            <p style="color: #999; font-size: 0.9em;">Your inventory will appear here once you add products.</p>
                        </div>
                    <?php else: ?>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Product</th>
                                        <th>SKU</th>
                                        <th>Stock</th>
                                        <th>Price</th>
                                        <th>Total Value</th>
                                        <th>Description</th>
                                        <th>Last Updated</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach($products as $product): 
                                        $stock_class = '';
                                        $stock_badge = '';
                                        if ($product['quantity'] == 0) {
                                            $stock_class = 'out-of-stock';
                                            $stock_badge = '<span class="stock-badge stock-out">Out of Stock</span>';
                                        } elseif ($product['quantity'] < 10) {
                                            $stock_class = 'low-stock';
                                            $stock_badge = '<span class="stock-badge stock-low">Low Stock</span>';
                                        } else {
                                            $stock_badge = '<span class="stock-badge stock-ok">In Stock</span>';
                                        }
                                    ?>
                                    <tr class="<?= $stock_class ?>">
                                        <td>
                                            <strong><?= htmlspecialchars($product['name']) ?></strong>
                                            <?php if ($product['created_at']): ?>
                                                <br>
                                                <small style="color: #888; font-size: 0.8em;">
                                                    Added: <?= date('M j, Y', strtotime($product['created_at'])) ?>
                                                </small>
                                            <?php endif; ?>
                                        </td>
                                        <td><?= $product['sku'] ? htmlspecialchars($product['sku']) : '—' ?></td>
                                        <td>
                                            <div style="font-weight: bold; font-size: 1.1em; margin-bottom: 5px;">
                                                <?= $product['quantity'] ?> units
                                            </div>
                                            <?= $stock_badge ?>
                                        </td>
                                        <td>$<?= number_format($product['price'], 2) ?></td>
                                        <td><strong>$<?= number_format($product['quantity'] * $product['price'], 2) ?></strong></td>
                                        <td><?= $product['description'] ? htmlspecialchars($product['description']) : '—' ?></td>
                                        <td>
                                            <small style="color: #666;">
                                                <?= date('M j, Y', strtotime($product['updated_at'])) ?>
                                            </small>
                                        </td>
                                        <td>
                                            <div class="actions">
                                                <a href="?edit=<?= $product['id'] ?>" class="btn btn-warning btn-sm">
                                                    <i class="fas fa-edit"></i> Edit
                                                </a>
                                                <a href="?delete=<?= $product['id'] ?>" class="btn btn-danger btn-sm"
                                                onclick="return confirm('SECURITY: Are you sure you want to delete \"<?= htmlspecialchars($product['name']) ?>\"? This action will be logged and cannot be undone.')">
                                                    <i class="fas fa-trash"></i> Delete
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                </div>

                <div class="sidebar">
                    <div class="user-profile">
                        <div class="profile-avatar" style="<?= $google_profile_picture ? 'background-image: url(' . htmlspecialchars($google_profile_picture) . ')' : '' ?>">
                            <?php if (!$google_profile_picture): ?>
                                <?= strtoupper(substr($_SESSION['user_name'], 0, 1)) ?>
                            <?php endif; ?>
                        </div>
                        <div class="profile-name"><?= htmlspecialchars($_SESSION['user_name']) ?></div>
                        <div class="profile-email"><?= htmlspecialchars($_SESSION['user_email']) ?></div>
                        
                        <div class="profile-meta">
                            <i class="fas fa-shield-alt" style="color: #4CAF50;"></i> 
                            Secure Session Active
                        </div>
                        
                        <?php if ($user_info): ?>
                            <div class="profile-meta">
                                <i class="fas fa-calendar-alt"></i> 
                                Member since <?= date('M Y', strtotime($user_info['created_at'])) ?>
                            </div>
                            <div class="profile-meta">
                                <i class="fas fa-sign-in-alt"></i> 
                                Last login: <?= $user_info['last_login'] ? date('M j, Y g:i A', strtotime($user_info['last_login'])) : 'First login' ?>
                            </div>
                            <div class="profile-meta">
                                <i class="fas fa-history"></i> 
                                Total logins: <?= $user_info['login_count'] ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="quick-actions">
                        <h3><i class="fas fa-bolt"></i> Quick Actions</h3>
                        <div class="action-list">
                            <a href="#" class="action-item" onclick="document.getElementById('name').focus(); return false;">
                                <div class="action-icon">
                                    <i class="fas fa-plus"></i>
                                </div>
                                <div>Add New Product</div>
                            </a>
                            <a href="security_logs.php" class="action-item">
                                <div class="action-icon">
                                    <i class="fas fa-clipboard-list"></i>
                                </div>
                                <div>View Security Logs</div>
                            </a>
                            <a href="audit_logs.php" class="action-item">
                                <div class="action-icon">
                                    <i class="fas fa-history"></i>
                                </div>
                                <div>Audit Trail</div>
                            </a>
                            <a href="logout.php" class="action-item">
                                <div class="action-icon">
                                    <i class="fas fa-sign-out-alt"></i>
                                </div>
                                <div>Secure Logout</div>
                            </a>
                        </div>
                    </div>
                </div>
            </div>

            <div class="footer">
                <p>Secure Inventory Management System • 
                Enhanced Security Enabled • 
                Session active for <?= ceil((SESSION_TIMEOUT_MINUTES * 60 - (time() - $_SESSION['last_activity'])) / 60) ?> more minutes •
                <a href="logout.php" style="color: var(--secondary);">Secure Logout</a>
                </p>
            </div>
        </div>
    </div>

    <script>
        let timeoutMinutes = <?= SESSION_TIMEOUT_MINUTES ?>;
        let lastActivity = <?= $_SESSION['last_activity'] ?>;
        let warningTime = (timeoutMinutes - 5) * 60 * 1000; 
        
        setTimeout(function() {
            if (confirm('Your session will expire in 5 minutes. Would you like to extend your session?')) {
                window.location.reload();
            }
        }, warningTime);
        
        setTimeout(function() {
            var alerts = document.querySelectorAll('.alert');
            Array.prototype.forEach.call(alerts, function(alert) {
                alert.style.transition = 'opacity 0.5s';
                alert.style.opacity = '0';
                setTimeout(function() { alert.remove(); }, 500);
            });
        }, 5000);
    </script>
</body>
</html>