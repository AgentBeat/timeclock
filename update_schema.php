<?php
// Script to update database schema to add company_id column

// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    // Connect to the database
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Check if company_id column already exists in users table
    $stmt = $pdo->query("PRAGMA table_info(users)");
    $columns = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $company_id_exists = false;
    foreach ($columns as $column) {
        if ($column['name'] === 'company_id') {
            $company_id_exists = true;
            break;
        }
    }
    
    // Add the column if it doesn't exist
    if (!$company_id_exists) {
        echo "Adding company_id column to users table...\n";
        $pdo->exec("ALTER TABLE users ADD COLUMN company_id INTEGER DEFAULT 1");
        echo "Column added successfully!\n";
        
        // Set all existing users to company_id 1 (default company)
        $pdo->exec("UPDATE users SET company_id = 1");
        echo "Updated existing users to default company_id!\n";
        
        // Update admin user's company name to SellingNorthCarolina.com
        $pdo->exec("UPDATE company_settings SET company_name = 'SellingNorthCarolina.com' WHERE id = 1");
        echo "Updated company name to SellingNorthCarolina.com!\n";
    } else {
        echo "The company_id column already exists in the users table.\n";
    }
    
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage() . "\n");
}

echo "Schema update completed.\n";
?> 