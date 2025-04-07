<?php
// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Check if employee1 already exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute(['employee1']);
    $exists = $stmt->fetch();
    
    if ($exists) {
        echo "Test employee already exists! (ID: {$exists['id']})<br>";
        echo "Username: employee1<br>";
        echo "Password: employee123<br>";
    } else {
        // Create a test employee
        $username = 'employee1';
        $name = 'Test Employee';
        $password = password_hash('employee123', PASSWORD_DEFAULT);
        $pay_period_type = 'weekly';
        $pay_period_start_day = 1; // Monday
        
        $stmt = $pdo->prepare("
            INSERT INTO users 
            (username, password, name, pay_period_type, pay_period_start_day, is_admin) 
            VALUES (?, ?, ?, ?, ?, 0)
        ");
        $result = $stmt->execute([$username, $password, $name, $pay_period_type, $pay_period_start_day]);
        
        if ($result) {
            echo "Test employee created successfully!<br>";
            echo "Username: employee1<br>";
            echo "Password: employee123<br>";
            
            // Verify the user was created
            $stmt = $pdo->prepare("SELECT id, username, name, is_admin FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            echo "<br>User details: <br>";
            echo "ID: " . $user['id'] . "<br>";
            echo "Name: " . $user['name'] . "<br>";
            echo "Username: " . $user['username'] . "<br>";
            echo "Is Admin: " . ($user['is_admin'] ? 'Yes' : 'No') . "<br>";
        } else {
            echo "Failed to create test employee.<br>";
        }
    }
    
    // Show all users in the database
    echo "<br><br>All users in database:<br>";
    $users = $pdo->query("SELECT id, username, name, is_admin FROM users")->fetchAll(PDO::FETCH_ASSOC);
    foreach ($users as $user) {
        echo "ID: " . $user['id'] . ", Name: " . $user['name'] . ", Username: " . $user['username'] . ", Admin: " . ($user['is_admin'] ? 'Yes' : 'No') . "<br>";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
}
?> 