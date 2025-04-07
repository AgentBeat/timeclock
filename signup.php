<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

// Initialize variables
$company_name = '';
$email = '';
$errors = [];
$success = null;

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Handle form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Get posted data
        $company_name = trim($_POST['company_name'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        
        // Validate input
        if (empty($company_name)) {
            $errors[] = "Company name is required";
        }
        
        if (empty($email)) {
            $errors[] = "Email is required";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format";
        }
        
        if (empty($password)) {
            $errors[] = "Password is required";
        } elseif (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters";
        }
        
        if ($password !== $confirm_password) {
            $errors[] = "Passwords do not match";
        }
        
        // Check if email already exists as username
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $stmt->execute([$email]);
        if ($stmt->fetchColumn() > 0) {
            $errors[] = "Email already in use";
        }
        
        // If no errors, create new company and admin user
        if (empty($errors)) {
            try {
                // Begin transaction
                $pdo->beginTransaction();
                
                // First check if company_settings table exists
                $result = $pdo->query("SELECT name FROM sqlite_master WHERE type='table' AND name='company_settings'");
                $tableExists = $result->fetchColumn() !== false;
                
                if (!$tableExists) {
                    // Create company_settings table if it doesn't exist
                    $pdo->exec("
                        CREATE TABLE IF NOT EXISTS company_settings (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            company_name TEXT DEFAULT 'My Company',
                            company_email TEXT DEFAULT '',
                            company_address TEXT DEFAULT '',
                            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    ");
                }
                
                // Insert new company settings
                $stmt = $pdo->prepare("INSERT INTO company_settings (company_name, company_email) VALUES (?, ?)");
                $stmt->execute([$company_name, $email]);
                $company_id = $pdo->lastInsertId();
                
                // Insert admin user
                $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO users (username, password, name, is_admin, company_id) VALUES (?, ?, ?, 1, ?)");
                $stmt->execute([$email, $hashed_password, $company_name . " Admin", $company_id]);
                
                // Commit transaction
                $pdo->commit();
                
                // Set success message
                $success = "Your account has been created successfully. You can now <a href='index.php'>login</a>.";
                
                // Clear form data after successful submission
                $company_name = '';
                $email = '';
            } catch (PDOException $e) {
                // Rollback transaction on error
                $pdo->rollBack();
                $errors[] = "Database error: " . $e->getMessage();
            }
        }
    }
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up - TimeClock System</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        /* Base styles */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        body {
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        
        h2, h3 {
            color: #2c3e50;
            margin-bottom: 15px;
        }
        
        h2 {
            font-size: 1.8rem;
            font-weight: 500;
        }
        
        /* Signup Form */
        #signupForm {
            max-width: 500px;
            margin: 60px auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        
        #signupForm h2 {
            text-align: center;
            margin-bottom: 25px;
            color: #2c3e50;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #2c3e50;
        }
        
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border 0.3s ease;
        }
        
        input:focus {
            border-color: #3498db;
            outline: none;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
        }
        
        button {
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: background-color 0.3s ease;
            margin-top: 10px;
        }
        
        button:hover {
            background-color: #2980b9;
        }
        
        .login-link {
            text-align: center;
            margin-top: 20px;
        }
        
        .login-link a {
            color: #3498db;
            text-decoration: none;
        }
        
        .login-link a:hover {
            text-decoration: underline;
        }
        
        .error-box {
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            border: 1px solid #f5c6cb;
        }
        
        .error-box ul {
            margin-left: 20px;
            margin-bottom: 0;
        }
        
        .success-box {
            background-color: #d4edda;
            color: #155724;
            padding: 10px 15px;
            margin-bottom: 20px;
            border-radius: 4px;
            border: 1px solid #c3e6cb;
        }
    </style>
</head>
<body>
    <div id="signupForm">
        <h2>Create Your TimeClock Account</h2>
        
        <?php if (!empty($errors)): ?>
            <div class="error-box">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>
        
        <?php if (isset($success)): ?>
            <div class="success-box">
                <?php echo $success; ?>
            </div>
        <?php else: ?>
            <form method="post" action="signup.php">
                <div class="form-group">
                    <label for="company_name">Company Name</label>
                    <input type="text" id="company_name" name="company_name" value="<?php echo htmlspecialchars($company_name ?? ''); ?>" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email Address (will be your username)</label>
                    <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($email ?? ''); ?>" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <div class="form-group">
                    <label for="confirm_password">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" required>
                </div>
                
                <button type="submit">Create Account</button>
            </form>
            
            <div class="login-link">
                Already have an account? <a href="index.php">Log in</a>
            </div>
        <?php endif; ?>
    </div>
</body>
</html> 