<?php
require_once 'config.php';
require_once 'db.php';

echo "<h1>Database Structure Check</h1>";

try {
    $db = getDB();
        $tables = $db->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    $expected_tables = ['users', 'products', 'security_logs', 'login_attempts', 'audit_logs'];
    
    echo "<h3>Table Status:</h3>";
    echo "<table border='1' cellpadding='10'>";
    echo "<tr><th>Table</th><th>Exists</th><th>Columns</th></tr>";
    
    foreach ($expected_tables as $table) {
        $exists = in_array($table, $tables);
        echo "<tr>";
        echo "<td><strong>$table</strong></td>";
        echo "<td style='color: " . ($exists ? 'green' : 'red') . ";'>" . ($exists ? ' YES' : ' NO') . "</td>";
        
        if ($exists) {
            $columns = $db->query("PRAGMA table_info($table)")->fetchAll(PDO::FETCH_COLUMN, 1);
            echo "<td>" . implode(', ', $columns) . "</td>";
        } else {
            echo "<td>Table missing</td>";
        }
        echo "</tr>";
    }
    echo "</table>";
    
    echo "<h3>Users Table Details:</h3>";
    if (in_array('users', $tables)) {
        $users_columns = $db->query("PRAGMA table_info(users)")->fetchAll(PDO::FETCH_ASSOC);
        echo "<table border='1' cellpadding='10'>";
        echo "<tr><th>Column</th><th>Type</th><th>Nullable</th><th>Default</th></tr>";
        foreach ($users_columns as $col) {
            echo "<tr>";
            echo "<td>{$col['name']}</td>";
            echo "<td>{$col['type']}</td>";
            echo "<td>" . ($col['notnull'] ? 'NO' : 'YES') . "</td>";
            echo "<td>{$col['dflt_value']}</td>";
            echo "</tr>";
        }
        echo "</table>";
        
        $admin = $db->query("SELECT * FROM users WHERE email = 'admin@secured-inventory.com'")->fetch(PDO::FETCH_ASSOC);
        if ($admin) {
            echo "<p style='color: green;'> Admin user exists</p>";
        } else {
            echo "<p style='color: red;'> Admin user missing</p>";
        }
    }
    
} catch (Exception $e) {
    echo "<p style='color: red;'>Database error: " . $e->getMessage() . "</p>";
}

echo "<h3>Actions:</h3>";
echo "<a href='reset_database.php' style='background: #FF5722; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;'>Reset Database</a>";
echo "<a href='init.php' style='background: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;'>Re-run Init</a>";
echo "<a href='login.php' style='background: #2196F3; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;'>Test Login</a>";
?>