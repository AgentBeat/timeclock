<?php
// Script to update database schema to add hourly_wage column

// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    // Connect to the database
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Check if the column already exists
    $stmt = $pdo->query("PRAGMA table_info(users)");
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $hourly_wage_exists = false;
    foreach ($columns as $column) {
        if ($column['name'] === 'hourly_wage') {
            $hourly_wage_exists = true;
            break;
        }
    }
    
    // Add the column if it doesn't exist
    if (!$hourly_wage_exists) {
        echo "Adding hourly_wage column to users table...\n";
        $pdo->exec("ALTER TABLE users ADD COLUMN hourly_wage REAL DEFAULT 0");
        echo "Column added successfully!\n";
    } else {
        echo "The hourly_wage column already exists in the users table.\n";
    }
    
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage() . "\n");
}

echo "Schema update completed.\n";
?> 