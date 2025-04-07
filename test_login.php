<?php
// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    echo "<h2>Testing Login Functionality</h2>";
    
    // List all users in the database
    echo "<h3>Users in Database:</h3>";
    $users = $pdo->query("SELECT id, username, is_admin FROM users")->fetchAll(PDO::FETCH_ASSOC);
    echo "<pre>";
    print_r($users);
    echo "</pre>";
    
    // Test admin login
    echo "<h3>Testing Admin Login:</h3>";
    testLogin($pdo, 'admin', 'admin123');
    
    // Test employee login
    echo "<h3>Testing Employee Login:</h3>";
    testLogin($pdo, 'employee1', 'employee123');
    
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

function testLogin($pdo, $username, $password) {
    echo "Attempting login with: $username<br>";
    
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo "User found: " . ($user ? "Yes" : "No") . "<br>";
    
    if ($user) {
        echo "User ID: " . $user['id'] . "<br>";
        echo "Is Admin: " . ($user['is_admin'] ? "Yes" : "No") . "<br>";
        echo "Stored password hash: " . $user['password'] . "<br>";
        
        $password_verified = password_verify($password, $user['password']);
        echo "Password verification: " . ($password_verified ? "Success" : "Failed") . "<br>";
        
        if ($password_verified) {
            echo "Login would succeed!<br>";
        } else {
            echo "Login would fail!<br>";
        }
    } else {
        echo "Login would fail! User not found.<br>";
    }
    
    echo "<hr>";
}
?> 