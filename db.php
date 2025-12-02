<?php
function getDB() {
    $dbFile = __DIR__ . '/database.sqlite';
    
    if (!file_exists($dbFile)) {
        file_put_contents($dbFile, '');
    }
    
    try {
        $pdo = new PDO("sqlite:" . $dbFile);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        
        $pdo->exec("PRAGMA foreign_keys = ON");
        
        return $pdo;
    } catch (PDOException $e) {
        error_log("Database connection failed: " . $e->getMessage());
        if (DEBUG_MODE) {
            die("Database connection failed: " . $e->getMessage());
        } else {
            die("Database connection failed. Please try again later.");
        }
    }
}
?>