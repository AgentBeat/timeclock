<?php
// Database configuration
$db_file = 'timeclock.sqlite';

// Delete the existing database file if it exists
if (file_exists($db_file)) {
    unlink($db_file);
    echo "Deleted existing database file.<br>";
}

// Create a new database
$dsn = "sqlite:$db_file";

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tables with the updated schema
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            pay_period_type TEXT DEFAULT 'weekly',
            pay_period_start_day INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS time_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            clock_in DATETIME NOT NULL,
            clock_out DATETIME DEFAULT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ");
    
    echo "Created new database schema.<br>";
    
    // Create admin user
    $admin_username = 'admin';
    $admin_name = 'Administrator';
    $admin_password = password_hash('admin123', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("
        INSERT INTO users (username, password, name, is_admin) 
        VALUES (?, ?, ?, 1)
    ");
    $stmt->execute([$admin_username, $admin_password, $admin_name]);
    
    echo "Created admin user.<br>";
    
    // Create test employee
    $emp_username = 'employee1';
    $emp_name = 'Test Employee';
    $emp_password = password_hash('employee123', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("
        INSERT INTO users (username, password, name, pay_period_type, pay_period_start_day, is_admin) 
        VALUES (?, ?, ?, 'weekly', 1, 0)
    ");
    $stmt->execute([$emp_username, $emp_password, $emp_name]);
    
    echo "Created test employee.<br>";
    
    // Show all users in the database
    echo "<br>All users in database:<br>";
    $users = $pdo->query("SELECT id, username, name, is_admin FROM users")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($users as $user) {
        echo "ID: " . $user['id'] . ", Name: " . $user['name'] . ", Username: " . $user['username'] . ", Admin: " . ($user['is_admin'] ? 'Yes' : 'No') . "<br>";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
}
?> 