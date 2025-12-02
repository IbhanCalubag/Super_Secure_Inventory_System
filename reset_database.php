<?php
require_once 'config.php';

$db_file = __DIR__ . '/database.sqlite';
if (file_exists($db_file)) {
    if (unlink($db_file)) {
        echo "<p style='color: green;'>Database file deleted successfully.</p>";
    } else {
        echo "<p style='color: red;'>Failed to delete database file.</p>";
    }
} else {
    echo "<p style='color: orange;'>Database file not found. Creating new one.</p>";
}

try {
    require_once 'init.php';
    echo "<h1 style='color: green;'>Database Reset Complete!</h1>";
    echo "<p>All tables have been recreated with the correct schema.</p>";
} catch (Exception $e) {
    echo "<h1 style='color: red;'>Database Reset Failed!</h1>";
    echo "<p>Error: " . $e->getMessage() . "</p>";
}

echo "<a href='login.php' style='background: #4CAF50; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 20px;'>Go to Login</a>";
echo "<a href='test.php' style='background: #2196F3; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; margin: 20px;'>Run Tests</a>";
?>