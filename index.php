<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create tables if they don't exist
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            hourly_wage REAL DEFAULT 0,
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
        
        CREATE TABLE IF NOT EXISTS company_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company_name TEXT DEFAULT 'My Company',
            company_short_name TEXT DEFAULT '',
            company_email TEXT DEFAULT '',
            company_address TEXT DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ");
    
    // Create default admin user if none exists
    $stmt = $pdo->query("SELECT COUNT(*) FROM users WHERE is_admin = 1");
    if ($stmt->fetchColumn() == 0) {
        $default_admin = 'admin';
        $default_password = password_hash('admin123', PASSWORD_DEFAULT);
        $default_name = 'Administrator';
        $pdo->exec("INSERT INTO users (username, password, name, is_admin) VALUES ('$default_admin', '$default_password', '$default_name', 1)");
    }
    
    // Create default company settings if none exists
    $stmt = $pdo->query("SELECT COUNT(*) FROM company_settings");
    if ($stmt->fetchColumn() == 0) {
        $pdo->exec("INSERT INTO company_settings (company_name, company_short_name, company_email, company_address) VALUES ('My Company', 'My Co', 'info@mycompany.com', '123 Main St, Anytown, USA')");
    }
    
    // Check and update database schema if needed
    try {
        // Check if entry_type column exists in time_entries table
        $result = $pdo->query("PRAGMA table_info(time_entries)");
        $columns = $result->fetchAll(PDO::FETCH_ASSOC);
        $hasEntryType = false;
        $hasNonPayable = false;
        $hasManualEntry = false;
        $hasHoursWorked = false;
        
        foreach ($columns as $column) {
            if ($column['name'] === 'entry_type') $hasEntryType = true;
            if ($column['name'] === 'non_payable') $hasNonPayable = true;
            if ($column['name'] === 'manual_entry') $hasManualEntry = true;
            if ($column['name'] === 'hours_worked') $hasHoursWorked = true;
        }
        
        // Add missing columns if needed
        if (!$hasEntryType) {
            $pdo->exec("ALTER TABLE time_entries ADD COLUMN entry_type TEXT DEFAULT 'regular'");
        }
        
        if (!$hasNonPayable) {
            $pdo->exec("ALTER TABLE time_entries ADD COLUMN non_payable INTEGER DEFAULT 0");
        }
        
        if (!$hasManualEntry) {
            $pdo->exec("ALTER TABLE time_entries ADD COLUMN manual_entry INTEGER DEFAULT 0");
        }
        
        if (!$hasHoursWorked) {
            $pdo->exec("ALTER TABLE time_entries ADD COLUMN hours_worked REAL");
            
            // Update existing entries with calculated hours
            $pdo->exec("
                UPDATE time_entries
                SET hours_worked = CASE 
                    WHEN clock_out IS NOT NULL 
                    THEN round((julianday(clock_out) - julianday(clock_in)) * 24, 2)
                    ELSE NULL 
                END
                WHERE hours_worked IS NULL
            ");
        }
        
        // Check if company_short_name column exists in company_settings table
        $result = $pdo->query("PRAGMA table_info(company_settings)");
        $columns = $result->fetchAll(PDO::FETCH_ASSOC);
        $hasCompanyShortName = false;
        
        foreach ($columns as $column) {
            if ($column['name'] === 'company_short_name') $hasCompanyShortName = true;
        }
        
        // Add company_short_name column if it doesn't exist
        if (!$hasCompanyShortName) {
            $pdo->exec("ALTER TABLE company_settings ADD COLUMN company_short_name TEXT DEFAULT ''");
            
            // Initialize with a shortened version of company_name
            $pdo->exec("UPDATE company_settings SET company_short_name = substr(company_name, 1, 10) WHERE company_short_name = ''");
        }
    } catch (PDOException $e) {
        // Log schema update error but continue with the application
        error_log('Error updating database schema: ' . $e->getMessage());
    }
    
} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// Handle API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    // Check for JSON content type
    $contentType = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';
    $isJson = strpos($contentType, 'application/json') !== false;
    
    if ($isJson) {
        $inputData = file_get_contents('php://input');
        $data = json_decode($inputData, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            echo json_encode(['success' => false, 'error' => 'Invalid JSON data']);
            exit;
        }
    } else {
        $data = $_POST;
    }
    
    $action = $data['action'] ?? '';
    
    switch ($action) {
        case 'login':
            handleLogin($pdo);
            break;
        case 'clock_in':
            handleClockIn($pdo);
            break;
        case 'clock_out':
            handleClockOut($pdo);
            break;
        case 'get_entries':
            handleGetEntries($pdo);
            break;
        case 'create_employee':
            handleCreateEmployee($pdo);
            break;
        case 'get_users':
            handleGetUsers($pdo);
            break;
        case 'get_user':
            handleGetUser($pdo);
            break;
        case 'update_user':
            handleUpdateUser($pdo);
            break;
        case 'delete_user':
            handleDeleteUser($pdo);
            break;
        case 'update_time_entry':
            handleUpdateTimeEntry($pdo);
            break;
        case 'delete_time_entry':
            handleDeleteTimeEntry($pdo);
            break;
        case 'check_session':
            handleCheckSession();
            break;
        case 'logout':
            handleLogout();
            break;
        case 'add_manual_time_entry':
            handleAddManualTimeEntry($pdo);
            break;
        case 'get_company_settings':
            handleGetCompanySettings($pdo);
            break;
        case 'update_company_settings':
            handleUpdateCompanySettings($pdo);
            break;
        case 'update_admin_settings':
            handleUpdateAdminSettings($pdo);
            break;
        default:
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}

// Login handler
function handleLogin($pdo) {
    global $data;
    
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $employeeOnly = isset($data['employee_only']) && $data['employee_only'] === true;
    $companyName = $data['company_name'] ?? '';
    
    // Log the request data
    error_log("Login attempt - Username: $username, Company: $companyName");
    
    if (empty($username) || empty($password)) {
        echo json_encode(['success' => false, 'error' => 'Username and password are required']);
        return;
    }
    
    // If this is an employee login, company name is required
    if ($employeeOnly && empty($companyName)) {
        echo json_encode(['success' => false, 'error' => 'Company name is required for employee login']);
        return;
    }
    
    try {
        // If company name is provided, first find the company ID
        $companyId = null;
        if (!empty($companyName)) {
            // Try to find company by full name or short name
            $companyStmt = $pdo->prepare("SELECT id FROM company_settings WHERE company_name = ? OR company_short_name = ?");
            $companyStmt->execute([$companyName, $companyName]);
            $company = $companyStmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$company) {
                echo json_encode(['success' => false, 'error' => 'Company not found']);
                return;
            }
            
            $companyId = $company['id'];
            
            // Now look for the user in this specific company
            $stmt = $pdo->prepare("SELECT u.* FROM users u 
                                  WHERE u.username = ? AND u.company_id = ?");
            $stmt->execute([$username, $companyId]);
        } else {
            // Standard login without company filtering
            $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
            $stmt->execute([$username]);
        }
        
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user && password_verify($password, $user['password'])) {
            // Check if this is an employee-only login and the user is an admin
            if ($employeeOnly && $user['is_admin']) {
                echo json_encode([
                    'success' => false, 
                    'error' => 'Please use the administrator login page.',
                    'is_admin' => true
                ]);
                return;
            }
            
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['is_admin'] = $user['is_admin'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['company_id'] = $user['company_id'];
            
            error_log("Login successful - User ID: {$user['id']}, Admin: {$user['is_admin']}, Company ID: {$user['company_id']}");
            echo json_encode(['success' => true, 'is_admin' => (bool)$user['is_admin']]);
        } else {
            error_log("Login failed - Invalid credentials for username: $username");
            echo json_encode(['success' => false, 'error' => 'Invalid credentials']);
        }
    } catch (PDOException $e) {
        error_log("Login error - Database exception: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Database error']);
    }
}

// Create employee handler
function handleCreateEmployee($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    global $data;
    $name = $data['name'] ?? '';
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';
    $hourly_wage = $data['hourly_wage'] ?? 0;
    $pay_period_type = $data['pay_period_type'] ?? 'weekly';
    $pay_period_start_day = $data['pay_period_start_day'] ?? 0;
    
    // Get the company_id of the currently logged-in admin
    $admin_id = $_SESSION['user_id'];
    $stmt = $pdo->prepare("SELECT company_id FROM users WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);
    $company_id = $admin['company_id'] ?? 1; // Default to 1 if not found
    
    if (empty($name) || empty($username) || empty($password)) {
        echo json_encode(['error' => 'Name, username and password are required']);
        return;
    }
    
    // Validate pay period type
    if (!in_array($pay_period_type, ['weekly', 'bi-weekly'])) {
        $pay_period_type = 'weekly';
    }
    
    // Validate pay period start day (0-6 for weekly, 1-31 for bi-weekly)
    $pay_period_start_day = (int)$pay_period_start_day; // Always convert to integer
    
    if ($pay_period_type === 'weekly') {
        if ($pay_period_start_day < 0 || $pay_period_start_day > 6) {
            $pay_period_start_day = 0; // Default to Sunday
        }
    } else { // bi-weekly
        if ($pay_period_start_day < 1 || $pay_period_start_day > 31) {
            $pay_period_start_day = 1; // Default to 1st of month
        }
    }
    
    try {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("
            INSERT INTO users 
            (username, password, name, hourly_wage, pay_period_type, pay_period_start_day, is_admin, company_id) 
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
        ");
        $stmt->execute([$username, $hashed_password, $name, $hourly_wage, $pay_period_type, $pay_period_start_day, $company_id]);
        echo json_encode(['success' => true, 'message' => 'Employee created successfully']);
    } catch (PDOException $e) {
        if ($e->getCode() == 23000) {
            echo json_encode(['error' => 'Username already exists']);
        } else {
            echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
        }
    }
}

// Get users handler
function handleGetUsers($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    // Get the admin's company_id
    $admin_id = $_SESSION['user_id'];
    $stmt = $pdo->prepare("SELECT company_id FROM users WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);
    $company_id = $admin['company_id'] ?? 1; // Default to 1 if not found
    
    // Only return non-admin users for standard employee operations
    $data = json_decode(file_get_contents('php://input'), true);
    $include_admins = $data['include_admins'] ?? false;
    
    $query = "SELECT id, username, name, pay_period_type, pay_period_start_day, is_admin, created_at 
              FROM users WHERE company_id = ?";
              
    if (!$include_admins) {
        $query .= " AND is_admin = 0";
    }
    
    $query .= " ORDER BY created_at DESC";
    
    $stmt = $pdo->prepare($query);
    $stmt->execute([$company_id]);
    echo json_encode(['users' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
}

// Get user handler
function handleGetUser($pdo) {
    // Check if the user is logged in
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not logged in']);
        return;
    }
    
    global $data;
    $user_id = $data['user_id'] ?? 0;
    
    // If no user_id is provided, use the logged-in user's ID
    if (empty($user_id)) {
        $user_id = $_SESSION['user_id'];
    }
    
    // Allow users to fetch their own data or admins to fetch any user data
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        // Non-admin users can only access their own data
        if ($user_id != $_SESSION['user_id']) {
            echo json_encode(['error' => 'Unauthorized']);
            return;
        }
    }
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($user) {
            echo json_encode(['success' => true, 'user' => $user]);
        } else {
            echo json_encode(['error' => 'User not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

// Update user handler
function handleUpdateUser($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    global $data;
    $userId = $data['user_id'] ?? 0;
    $name = $data['name'] ?? '';
    $password = $data['password'] ?? '';
    $hourly_wage = $data['hourly_wage'] ?? 0;
    $pay_period_type = $data['pay_period_type'] ?? '';
    $pay_period_start_day = $data['pay_period_start_day'] ?? '';
    
    // Log the received data for debugging
    error_log("Update user request - User ID: $userId, Name: $name, Pay Period Type: $pay_period_type, Pay Period Start Day: $pay_period_start_day");
    
    // For bi-weekly, also log the raw value to see if it's getting truncated
    if ($pay_period_type === 'bi-weekly') {
        error_log("Bi-weekly start day (raw value): '" . $pay_period_start_day . "' - Type: " . gettype($pay_period_start_day));
    }
    
    if (empty($userId) || empty($name)) {
        echo json_encode(['error' => 'User ID and name are required']);
        return;
    }
    
    // Validate hourly wage
    $hourly_wage = max(0, floatval($hourly_wage));
    
    // Validate pay period type
    if (!in_array($pay_period_type, ['weekly', 'bi-weekly'])) {
        $pay_period_type = 'weekly';
    }
    
    // Validate pay period start day (0-6 for weekly, 1-31 for bi-weekly)
    $pay_period_start_day = (int)$pay_period_start_day; // Always convert to integer
    
    if ($pay_period_type === 'weekly') {
        if ($pay_period_start_day < 0 || $pay_period_start_day > 6) {
            $pay_period_start_day = 0; // Default to Sunday
        }
    } else { // bi-weekly
        if ($pay_period_start_day < 1 || $pay_period_start_day > 31) {
            $pay_period_start_day = 1; // Default to 1st of month
        }
    }
    
    error_log("Validated data - Pay Period Type: $pay_period_type, Pay Period Start Day: $pay_period_start_day");
    
    try {
        // First, get the current user data to check if we need to update the password
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$user) {
            echo json_encode(['error' => 'User not found']);
            return;
        }
        
        // Build the update query based on whether a password was provided
        if (!empty($password)) {
            // Update with new password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("
                UPDATE users 
                SET name = ?, password = ?, hourly_wage = ?, pay_period_type = ?, pay_period_start_day = ?
                WHERE id = ?
            ");
            
            error_log("Executing update with password change: name='$name', hourly_wage='$hourly_wage', pay_period_type='$pay_period_type', pay_period_start_day='$pay_period_start_day', user_id='$userId'");
            
            $stmt->execute([$name, $hashed_password, $hourly_wage, $pay_period_type, $pay_period_start_day, $userId]);
        } else {
            // Update without changing the password
            $stmt = $pdo->prepare("
                UPDATE users 
                SET name = ?, hourly_wage = ?, pay_period_type = ?, pay_period_start_day = ?
                WHERE id = ?
            ");
            
            error_log("Executing update with params: name='$name', hourly_wage='$hourly_wage', pay_period_type='$pay_period_type', pay_period_start_day='$pay_period_start_day', user_id='$userId'");
            
            $stmt->execute([$name, $hourly_wage, $pay_period_type, $pay_period_start_day, $userId]);
        }
        
        echo json_encode(['success' => true, 'message' => 'Employee updated successfully']);
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

// Delete user handler
function handleDeleteUser($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    global $data;
    $user_id = $data['user_id'] ?? 0;
    
    if ($user_id == $_SESSION['user_id']) {
        echo json_encode(['error' => 'Cannot delete your own account']);
        return;
    }
    
    try {
        $pdo->beginTransaction();
        $stmt = $pdo->prepare("DELETE FROM time_entries WHERE user_id = ?");
        $stmt->execute([$user_id]);
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $pdo->commit();
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        $pdo->rollBack();
        echo json_encode(['error' => 'Database error']);
    }
}

// Clock in handler
function handleClockIn($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not logged in']);
        return;
    }
    
    // Check if user already has an open time entry
    $stmt = $pdo->prepare("SELECT id FROM time_entries WHERE user_id = ? AND clock_out IS NULL");
    $stmt->execute([$_SESSION['user_id']]);
    if ($stmt->fetch()) {
        echo json_encode(['error' => 'Already clocked in']);
        return;
    }
    
    $stmt = $pdo->prepare("INSERT INTO time_entries (user_id, clock_in) VALUES (?, datetime('now', 'localtime'))");
    $stmt->execute([$_SESSION['user_id']]);
    echo json_encode(['success' => true]);
}

// Clock out handler
function handleClockOut($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not logged in']);
        return;
    }
    
    $stmt = $pdo->prepare("
        UPDATE time_entries 
        SET clock_out = datetime('now', 'localtime')
        WHERE user_id = ? AND clock_out IS NULL
    ");
    $stmt->execute([$_SESSION['user_id']]);
    
    if ($stmt->rowCount() > 0) {
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['error' => 'No active clock-in found']);
    }
}

// Get time entries handler
function handleGetEntries($pdo) {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $employee_id = $data['employee_id'] ?? null;
    $start_date = $data['start_date'] ?? null;
    $end_date = $data['end_date'] ?? null;
    
    // Base query
    $query = "
        SELECT e.id, e.user_id, u.username, e.clock_in, e.clock_out, e.hours_worked, e.entry_type, e.non_payable, e.manual_entry
        FROM time_entries e
        JOIN users u ON e.user_id = u.id
        WHERE 1=1
    ";
    $params = [];
    
    // Add filters
    if ($employee_id) {
        $query .= " AND e.user_id = ?";
        $params[] = $employee_id;
    } elseif (isset($_SESSION['is_admin']) && !$_SESSION['is_admin']) {
        // If non-admin, only show their own entries
        $query .= " AND e.user_id = ?";
        $params[] = $_SESSION['user_id'];
    }
    
    if ($start_date) {
        $query .= " AND DATE(e.clock_in) >= ?";
        $params[] = $start_date;
    }
    
    if ($end_date) {
        $query .= " AND DATE(e.clock_in) <= ?";
        $params[] = $end_date;
    }
    
    // Order by most recent first
    $query .= " ORDER BY e.clock_in DESC";
    
    try {
        $stmt = $pdo->prepare($query);
        $stmt->execute($params);
        $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'entries' => $entries]);
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    }
}

// Update time entry handler
function handleUpdateTimeEntry($pdo) {
    // Get the request data
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Log received data for debugging
    error_log("Update time entry request data: " . json_encode($data));
    
    // Check if we have all required data
    if (!isset($data['entry_id']) || !isset($data['clock_in']) || !isset($data['clock_out'])) {
        error_log("Missing required data for time entry update: " . json_encode($data));
        echo json_encode(['success' => false, 'error' => 'Missing required data']);
        return;
    }
    
    $entryId = intval($data['entry_id']);
    $clockIn = $data['clock_in'];
    $clockOut = $data['clock_out'];
    $entryType = isset($data['entry_type']) ? $data['entry_type'] : 'regular';
    $nonPayable = isset($data['non_payable']) ? ($data['non_payable'] ? 1 : 0) : 0;
    
    // Calculate hours worked
    $startTime = strtotime($clockIn);
    $endTime = strtotime($clockOut);
    $hoursWorked = ($endTime - $startTime) / 3600; // Convert seconds to hours
    
    error_log("Processing time entry update - ID: $entryId, Hours: $hoursWorked");
    
    try {
        // Update the time entry
        $stmt = $pdo->prepare('UPDATE time_entries SET clock_in = ?, clock_out = ?, hours_worked = ?, entry_type = ?, non_payable = ? WHERE id = ?');
        $stmt->execute([$clockIn, $clockOut, $hoursWorked, $entryType, $nonPayable, $entryId]);
        
        error_log("Time entry updated successfully - ID: $entryId");
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        error_log("Error updating time entry - ID: $entryId, Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
}

// Delete time entry handler
function handleDeleteTimeEntry($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['error' => 'Unauthorized']);
        return;
    }
    
    $data = json_decode(file_get_contents('php://input'), true);
    $entry_id = $data['entry_id'] ?? 0;
    
    if (empty($entry_id)) {
        echo json_encode(['error' => 'Invalid input']);
        return;
    }
    
    try {
        $stmt = $pdo->prepare("DELETE FROM time_entries WHERE id = ?");
        $stmt->execute([$entry_id]);
        
        if ($stmt->rowCount() > 0) {
            echo json_encode(['success' => true]);
        } else {
            echo json_encode(['error' => 'Time entry not found']);
        }
    } catch (PDOException $e) {
        echo json_encode(['error' => 'Database error']);
    }
}

// Check session handler
function handleCheckSession() {
    if (isset($_SESSION['user_id'])) {
        // Get user's name for the header
        if (!$_SESSION['is_admin']) {
            try {
                global $pdo;
                $stmt = $pdo->prepare("SELECT name FROM users WHERE id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                $name = $user ? $user['name'] : $_SESSION['username'];
                
                echo json_encode([
                    'logged_in' => true, 
                    'is_admin' => $_SESSION['is_admin'],
                    'name' => $name
                ]);
            } catch (PDOException $e) {
                echo json_encode([
                    'logged_in' => true, 
                    'is_admin' => $_SESSION['is_admin']
                ]);
            }
        } else {
            echo json_encode([
                'logged_in' => true, 
                'is_admin' => $_SESSION['is_admin']
            ]);
        }
    } else {
        echo json_encode(['logged_in' => false]);
    }
}

// Logout handler
function handleLogout() {
    session_unset();
    session_destroy();
    echo json_encode(['success' => true]);
}

// Add manual time entry handler
function handleAddManualTimeEntry($pdo) {
    // Get the request data
    $data = json_decode(file_get_contents('php://input'), true);
    
    // Log received data for debugging
    error_log("Add manual time entry request data: " . json_encode($data));
    
    // Check if we have all required data
    if (!isset($data['employee_id']) || !isset($data['clock_in']) || !isset($data['clock_out'])) {
        error_log("Missing required data for manual time entry: " . json_encode($data));
        echo json_encode(['success' => false, 'error' => 'Missing required data']);
        return;
    }
    
    $employeeId = intval($data['employee_id']);
    $clockIn = $data['clock_in'];
    $clockOut = $data['clock_out'];
    $entryType = isset($data['entry_type']) ? $data['entry_type'] : 'regular';
    $nonPayable = isset($data['non_payable']) ? ($data['non_payable'] ? 1 : 0) : 0;
    
    // Calculate hours worked
    $startTime = strtotime($clockIn);
    $endTime = strtotime($clockOut);
    $hoursWorked = ($endTime - $startTime) / 3600; // Convert seconds to hours
    
    error_log("Processing manual time entry - Employee ID: $employeeId, Hours: $hoursWorked");
    
    try {
        // Insert the new time entry
        $stmt = $pdo->prepare('INSERT INTO time_entries (user_id, clock_in, clock_out, hours_worked, entry_type, non_payable, manual_entry) 
                              VALUES (?, ?, ?, ?, ?, ?, 1)');
        $stmt->execute([$employeeId, $clockIn, $clockOut, $hoursWorked, $entryType, $nonPayable]);
        
        error_log("Manual time entry added successfully - Employee ID: $employeeId");
        echo json_encode(['success' => true]);
    } catch (PDOException $e) {
        error_log("Error adding manual time entry - Employee ID: $employeeId, Error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
}

// Get company settings handler
function handleGetCompanySettings($pdo) {
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['error' => 'Not logged in']);
        return;
    }
    
    // Get the user's company_id
    $user_id = $_SESSION['user_id'];
    $stmt = $pdo->prepare("SELECT company_id FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    $company_id = $user['company_id'] ?? 1; // Default to 1 if not found
    
    // Fetch company settings from the database
    $stmt = $pdo->prepare("SELECT * FROM company_settings WHERE id = ?");
    $stmt->execute([$company_id]);
    $settings = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode(['success' => true, 'settings' => $settings]);
}

// Update company settings handler
function handleUpdateCompanySettings($pdo) {
    if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['success' => false, 'error' => 'Unauthorized']);
        return;
    }
    
    // Get the admin's company_id
    $admin_id = $_SESSION['user_id'];
    $stmt = $pdo->prepare("SELECT company_id FROM users WHERE id = ?");
    $stmt->execute([$admin_id]);
    $admin = $stmt->fetch(PDO::FETCH_ASSOC);
    $company_id = $admin['company_id'] ?? 1; // Default to 1 if not found
    
    // Get the updated settings from the request
    global $data;
    
    // Update company name
    $companyName = $data['company_name'] ?? '';
    if (!empty($companyName)) {
        $stmt = $pdo->prepare("UPDATE company_settings SET company_name = ? WHERE id = ?");
        $stmt->execute([$companyName, $company_id]);
    }
    
    // Update company short name
    $companyShortName = $data['company_short_name'] ?? '';
    $stmt = $pdo->prepare("UPDATE company_settings SET company_short_name = ? WHERE id = ?");
    $stmt->execute([$companyShortName, $company_id]);
    
    // Update company email
    $companyEmail = $data['company_email'] ?? '';
    if (!empty($companyEmail)) {
        $stmt = $pdo->prepare("UPDATE company_settings SET company_email = ? WHERE id = ?");
        $stmt->execute([$companyEmail, $company_id]);
    }
    
    // Update company address
    $companyAddress = $data['company_address'] ?? '';
    if (!empty($companyAddress)) {
        $stmt = $pdo->prepare("UPDATE company_settings SET company_address = ? WHERE id = ?");
        $stmt->execute([$companyAddress, $company_id]);
    }
    
    // Update the updated_at timestamp
    $stmt = $pdo->prepare("UPDATE company_settings SET updated_at = datetime('now', 'localtime') WHERE id = ?");
    $stmt->execute([$company_id]);
    
    echo json_encode(['success' => true, 'message' => 'Company settings updated successfully']);
}

// Handle admin credential updates
function handleUpdateAdminSettings($pdo) {
    // Check if user is logged in and is an admin
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
        echo json_encode(['success' => false, 'error' => 'Unauthorized. Admin privileges required.']);
        return;
    }
    
    // Get the data from the request
    global $data;
    $adminEmail = $data['admin_email'] ?? '';
    $currentPassword = $data['admin_current_password'] ?? '';
    $newPassword = $data['admin_new_password'] ?? '';
    
    // Get the current admin's user ID
    $adminId = $_SESSION['user_id'];
    
    try {
        // First, verify the current admin's identity with current password
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ? AND is_admin = 1");
        $stmt->execute([$adminId]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$admin) {
            echo json_encode(['success' => false, 'error' => 'Admin account not found.']);
            return;
        }
        
        // Verify the current password
        if (!password_verify($currentPassword, $admin['password'])) {
            echo json_encode(['success' => false, 'error' => 'Current password is incorrect.']);
            return;
        }
        
        // Check if the new email is already in use by another user
        if ($adminEmail !== $admin['username']) {
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?");
            $stmt->execute([$adminEmail, $adminId]);
            if ($stmt->fetchColumn() > 0) {
                echo json_encode(['success' => false, 'error' => 'Email is already in use by another account.']);
                return;
            }
        }
        
        // Start building the update query
        $updates = [];
        $params = [];
        
        // Update email if it's different
        if ($adminEmail !== $admin['username']) {
            $updates[] = "username = ?";
            $params[] = $adminEmail;
        }
        
        // Update password if provided
        if (!empty($newPassword)) {
            $updates[] = "password = ?";
            $params[] = password_hash($newPassword, PASSWORD_DEFAULT);
        }
        
        // Only proceed if there are changes to make
        if (!empty($updates)) {
            // Add admin ID to params
            $params[] = $adminId;
            
            // Build and execute the update query
            $query = "UPDATE users SET " . implode(", ", $updates) . " WHERE id = ?";
            $stmt = $pdo->prepare($query);
            $stmt->execute($params);
            
            // Update session if email changed
            if ($adminEmail !== $admin['username']) {
                $_SESSION['username'] = $adminEmail;
            }
            
            echo json_encode(['success' => true, 'message' => 'Admin credentials updated successfully.']);
        } else {
            echo json_encode(['success' => true, 'message' => 'No changes were made.']);
        }
    } catch (PDOException $e) {
        echo json_encode(['success' => false, 'error' => 'Database error: ' . $e->getMessage()]);
    }
}

// If not an API request, display the HTML page
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TimeClock System - Admin Portal</title>
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
        
        h3 {
            font-size: 1.4rem;
            font-weight: 500;
        }
        
        /* Login Form */
        #loginForm {
            max-width: 400px;
            margin: 80px auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        
        #loginForm h2 {
            text-align: center;
            margin-bottom: 25px;
            color: #2c3e50;
        }
        
        #loginForm input {
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border 0.3s ease;
        }
        
        #loginForm input:focus {
            border-color: #3498db;
            outline: none;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
        }
        
        #loginForm button {
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
        }
        
        #loginForm button:hover {
            background-color: #2980b9;
        }
        
        /* Time Clock Panel */
        #timeclockPanel {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        
        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background-color: #3498db;
            color: white;
            padding: 20px;
            position: relative;
        }
        
        .panel-header h2 {
            color: white;
            margin: 0;
            font-weight: 500;
        }
        
        .company-info {
            text-align: center;
            padding: 10px 0;
            font-size: 1rem;
            color: #3498db;
            background-color: #f8f9fa;
            border-bottom: 1px solid #ddd;
        }
        
        .company-info span {
            display: block;
            line-height: 1.5;
            margin: 0 20px;
            font-weight: 500;
        }
        
        #supportEmailDisplay {
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        .logout-btn {
            background-color: #e74c3c;
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.5);
            padding: 8px 15px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .logout-btn:hover {
            background-color: #c0392b;
            border-color: white;
        }
        
        .current-time {
            background-color: #ecf0f1;
            padding: 18px 20px;
            font-size: 2rem;
            color: #34495e;
            border-bottom: 1px solid #ddd;
            text-align: center;
            font-weight: 500;
        }
        
        .clock-status {
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
        }
        
        .status-indicator {
            font-size: 1.1rem;
            color: #7f8c8d;
        }
        
        .clocked-in #currentStatus {
            color: #27ae60;
            font-weight: 500;
        }
        
        .not-clocked-in #currentStatus {
            color: #e74c3c;
            font-weight: 500;
        }
        
        .clock-buttons {
            display: flex;
            gap: 15px;
            padding: 20px;
            border-bottom: 1px solid #ddd;
        }
        
        .clock-btn {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        #clockInBtn {
            background-color: #27ae60;
            color: white;
        }
        
        #clockInBtn:hover {
            background-color: #2ecc71;
        }
        
        #clockOutBtn {
            background-color: #e74c3c;
            color: white;
        }
        
        #clockOutBtn:hover {
            background-color: #c0392b;
        }
        
        .clock-btn.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        
        /* Employee Pay Period Section */
        .employee-pay-period-section {
            margin: 0;
            padding: 20px;
            background-color: #fff;
            border-bottom: 1px solid #ddd;
        }
        
        .employee-pay-period-section h3 {
            margin-top: 0;
            margin-bottom: 20px;
            color: #2c3e50;
            font-size: 1.3rem;
        }
        
        .pay-period-info {
            margin-bottom: 15px;
            padding: 12px 15px;
            background-color: #f1f8ff;
            border-radius: 6px;
            border-left: 4px solid #3498db;
            font-weight: 500;
            color: #2c3e50;
            font-size: 0.95rem;
        }
        
        .period-navigation {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        
        .period-navigation button {
            padding: 10px 15px;
            background-color: #ecf0f1;
            color: #34495e;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .period-navigation button:hover {
            background-color: #d6dbdf;
        }
        
        #employeeCurrentPeriod {
            background-color: #3498db;
            color: white;
        }
        
        #employeeCurrentPeriod:hover {
            background-color: #2980b9;
        }
        
        /* Payment Summary */
        #employeePaymentSummary, #paymentSummary {
            margin: 0 0 20px 0;
        }
        
        .summary-panel {
            background-color: #f9f9f9;
            border-radius: 6px;
            padding: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        
        .summary-panel h3 {
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 1.2rem;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        
        .summary-details {
            font-size: 15px;
        }
        
        .summary-details p {
            margin: 8px 0;
            display: flex;
            justify-content: space-between;
        }
        
        .summary-details p strong {
            color: #34495e;
        }
        
        #employeeTotalHours, #employeeHourlyRate, #employeeAmountDue,
        #totalHours, #hourlyRate, #amountDue {
            font-weight: 500;
            text-align: right;
            min-width: 80px;
        }
        
        #employeeAmountDue, #amountDue {
            color: #27ae60;
            font-size: 1.1rem;
        }
        
        /* Time Entries */
        #entriesList {
            padding: 20px;
        }
        
        .employee-entries {
            margin-top: 15px;
        }
        
        .employee-entries h3 {
            margin-bottom: 20px;
            font-size: 1.4rem;
            color: #2c3e50;
            text-align: center;
            padding-bottom: 10px;
            border-bottom: 1px solid #eee;
        }
        
        .employee-entry {
            display: flex;
            margin-bottom: 20px;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        
        .employee-entry:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .entry-date {
            flex: 0 0 120px;
            font-weight: 600;
            font-size: 1.1rem;
            color: #3498db;
            padding-right: 20px;
            border-right: 2px solid #f0f0f0;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }
        
        .entry-details {
            flex: 1;
            padding-left: 20px;
        }
        
        .entry-details p {
            margin: 10px 0;
            color: #34495e;
            font-size: 1.05rem;
            display: flex;
            align-items: center;
        }
        
        .entry-details p strong {
            color: #2c3e50;
            width: 100px;
            display: inline-block;
            font-weight: 600;
        }
        
        /* Helper Classes */
        .hidden {
            display: none !important;
        }
        
        /* Centered header */
        .centered-header {
            position: absolute;
            left: 50%;
            transform: translateX(-50%);
            margin: 0;
            text-align: center;
            white-space: nowrap;
        }
        
        /* Responsive adjustments */
        @media (max-width: 768px) {
            .panel-header {
                flex-direction: column;
                gap: 10px;
                padding: 15px;
            }
            
            .centered-header {
                position: static;
                transform: none;
                margin-bottom: 10px;
            }
            
            .clock-buttons {
                flex-direction: column;
            }
            
            .period-navigation {
                flex-direction: column;
                gap: 10px;
            }
            
            .employee-entry {
                flex-direction: column;
            }
            
            .entry-date {
                border-right: none;
                border-bottom: 1px solid #eee;
                padding: 0 0 10px 0;
                margin-bottom: 10px;
            }
            
            .entry-details {
                padding-left: 0;
                padding-top: 10px;
            }
        }

        .value-display {
            text-align: right;
            min-width: 80px;
        }

        /* Admin Panel */
        #adminPanel {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            display: flex;
            min-height: 600px;
        }

        .admin-section h3 {
            color: #2c3e50;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 1.3rem;
            font-weight: 500;
            border-bottom: 1px solid #edf2f7;
            padding-bottom: 8px;
        }

        /* Admin Dashboard Entries */
        #adminEntriesList {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 10px;
        }

        .admin-entry {
            background-color: #fff;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .admin-entry:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .admin-entry h4 {
            margin-top: 0;
            margin-bottom: 10px;
            color: #3498db;
            font-size: 1.1rem;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 8px;
        }

        .admin-entry p {
            margin: 5px 0;
            color: #34495e;
            display: flex;
            justify-content: space-between;
        }

        .admin-entry p strong {
            font-weight: 600;
            color: #2c3e50;
        }

        /* Admin Panel - Side Menu Styling */
        .side-menu {
            width: 250px;
            background-color: #f8f9fa;
            padding: 0;
            border-radius: 8px 0 0 8px;
            border-right: 1px solid #e9ecef;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }

        .side-menu h2 {
            color: #2c3e50;
            margin: 0;
            padding: 20px;
            font-size: 1.4rem;
            font-weight: 600;
            border-bottom: 1px solid #e9ecef;
            background-color: #f1f4f6;
            border-radius: 8px 0 0 0;
        }

        .side-menu button {
            display: block;
            width: 100%;
            text-align: left;
            padding: 15px 20px;
            margin: 0;
            background-color: transparent;
            border: none;
            border-bottom: 1px solid #e9ecef;
            cursor: pointer;
            transition: all 0.2s ease;
            color: #495057;
            font-size: 1rem;
            font-weight: 500;
            position: relative;
        }

        .side-menu button:hover {
            background-color: #f1f4f6;
            color: #3498db;
            padding-left: 25px;
        }

        .side-menu button.active {
            background-color: #3498db;
            color: white;
            border-right: none;
            padding-left: 25px;
        }

        .side-menu button.active::before {
            content: "";
            position: absolute;
            left: 0;
            top: 0;
            bottom: 0;
            width: 4px;
            background-color: #2980b9;
        }

        .side-menu button:last-child {
            margin-top: 20px;
            border-top: 1px solid #e9ecef;
            color: #e74c3c;
            font-weight: 500;
        }

        .side-menu button:last-child:hover {
            background-color: #fee2e1;
            color: #c0392b;
        }

        .admin-content {
            flex: 1;
            padding: 20px;
            background-color: #fff;
            border-radius: 0 8px 8px 0;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }

        .admin-section {
            display: none;
        }

        .admin-section.active {
            display: block;
        }

        .admin-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }

        .admin-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        .admin-nav button {
            padding: 10px 20px;
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .admin-nav button.active {
            background-color: #3498db;
            color: white;
            border-color: #3498db;
        }

        .admin-nav button:hover {
            background-color: #e9ecef;
        }

        .admin-nav button.active:hover {
            background-color: #2980b9;
        }

        /* Admin Entries */
        .entry {
            background-color: #fff;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 10px;
            margin-bottom: 8px;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            display: flex;
            flex-wrap: wrap;
            box-shadow: 0 1px 3px rgba(0,0,0,0.03);
        }
        
        .entry:hover {
            background-color: #f8f9fa;
            transform: translateY(-1px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.08);
        }
        
        .entry p {
            margin: 3px 12px 3px 0;
            font-size: 0.9rem;
            flex: 1 0 auto;
            min-width: 160px;
            color: #4a5568;
        }
        
        .entry p:first-child {
            font-weight: 600;
            color: #3498db;
        }

        /* Employee Management */
        .user-list {
            display: grid;
            gap: 15px;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        }

        .user-item {
            background-color: #fff;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .user-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .user-item h4 {
            margin-top: 0;
            margin-bottom: 12px;
            color: #3498db;
            font-size: 1.1rem;
            border-bottom: 1px solid #f0f0f0;
            padding-bottom: 8px;
        }

        .user-item p {
            margin: 8px 0;
            color: #34495e;
            display: flex;
            justify-content: space-between;
        }

        .user-item p strong {
            font-weight: 600;
            color: #2c3e50;
        }

        .user-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }

        .edit-btn, .delete-btn {
            padding: 8px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: background-color 0.3s ease;
            flex: 1;
            text-align: center;
        }

        .edit-btn {
            background-color: #3498db;
            color: white;
        }

        .edit-btn:hover {
            background-color: #2980b9;
        }

        .delete-btn {
            background-color: #e74c3c;
            color: white;
        }

        .delete-btn:hover {
            background-color: #c0392b;
        }

        .add-btn {
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 10px 15px;
            font-size: 0.95rem;
            font-weight: 500;
            cursor: pointer;
            margin-bottom: 20px;
            transition: background-color 0.3s ease;
            display: flex;
            align-items: center;
            width: fit-content;
        }

        .add-btn:hover {
            background-color: #219955;
        }

        .add-btn::before {
            content: "+";
            font-size: 1.2rem;
            margin-right: 5px;
            font-weight: bold;
        }

        /* Modal Styling */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            overflow-y: auto;
        }

        .modal-content {
            position: relative;
            background-color: #fff;
            margin: 50px auto;
            padding: 25px;
            width: 90%;
            max-width: 500px;
            border-radius: 8px;
            box-shadow: 0 5px 20px rgba(0, 0, 0, 0.2);
            animation: modalFadeIn 0.3s ease;
        }

        @keyframes modalFadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .close-modal {
            position: absolute;
            right: 20px;
            top: 15px;
            font-size: 24px;
            cursor: pointer;
            color: #aaa;
            transition: color 0.2s ease;
        }

        .close-modal:hover {
            color: #e74c3c;
        }

        .modal h3 {
            margin-top: 0;
            margin-bottom: 20px;
            color: #2c3e50;
            font-size: 1.4rem;
            font-weight: 600;
            border-bottom: 1px solid #e9ecef;
            padding-bottom: 10px;
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 6px;
            color: #34495e;
            font-weight: 500;
            font-size: 0.95rem;
        }

        .form-group input,
        .form-group select {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.95rem;
            transition: border-color 0.2s ease;
        }

        .form-group input:focus,
        .form-group select:focus {
            border-color: #3498db;
            outline: none;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
        }

        /* Modal buttons */
        .modal button {
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 500;
            transition: background-color 0.3s ease;
            margin-top: 10px;
        }

        .modal button:hover {
            background-color: #2980b9;
        }

        #createEmployeeMessage,
        #editEmployeeMessage,
        #addTimeEntryMessage {
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            font-size: 0.95rem;
        }

        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        /* More Compact Timecard Management */
        .timecard-filters {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
        }

        .timecard-filters .employee-selector {
            margin-bottom: 0;
            flex: 1;
            min-width: 200px;
        }

        .timecard-filters .date-filters {
            flex: 2;
            min-width: 300px;
            display: flex;
            gap: 10px;
            align-items: flex-end;
        }

        .timecard-filters label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
        }

        .timecard-filters select,
        .timecard-filters input[type="date"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 0;
            font-size: 14px;
        }

        .timecard-filters button {
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 12px;
            cursor: pointer;
            transition: background-color 0.3s ease;
            font-weight: 500;
            height: 36px;
            margin-bottom: 0;
            min-width: 120px;
        }

        .pay-period-navigation {
            display: flex;
            justify-content: space-between;
            margin: 10px 0;
            flex-wrap: wrap;
            gap: 5px;
        }

        .pay-period-navigation button {
            padding: 8px 12px;
            background-color: #ecf0f1;
            color: #34495e;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            flex: 1;
            min-width: 120px;
            text-align: center;
        }

        .current-period-display {
            background-color: #f1f8ff;
            padding: 10px 15px;
            border-radius: 6px;
            border-left: 4px solid #3498db;
            margin-bottom: 10px;
            font-weight: 500;
            color: #2c3e50;
        }

        .timecard-entry {
            display: flex;
            margin-bottom: 15px;
            padding: 15px;
            background-color: #fff;
            border-radius: 8px;
            border: 1px solid #e0e0e0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .timecard-entry:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }

        .timecard-date {
            flex: 0 0 100px;
            font-weight: 600;
            font-size: 1rem;
            color: #3498db;
            padding-right: 15px;
            border-right: 2px solid #f0f0f0;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .timecard-details {
            flex: 1;
            padding-left: 15px;
        }

        .timecard-details p {
            margin: 5px 0;
            color: #34495e;
            font-size: 0.95rem;
            display: flex;
            align-items: center;
        }

        .timecard-details p strong {
            color: #2c3e50;
            width: 90px;
            display: inline-block;
            font-weight: 600;
        }

        .summary-panel {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
            margin-bottom: 15px;
        }

        .summary-panel h3 {
            margin-top: 0;
            margin-bottom: 10px;
            font-size: 1.1rem;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
        }

        .summary-details p {
            margin: 5px 0;
            display: flex;
            justify-content: space-between;
            font-size: 0.95rem;
            color: #34495e;
        }

        #timecardsSection h3 {
            margin-bottom: 15px;
        }

        /* Form elements for editing */
        .timecard-details .form-group {
            margin-bottom: 10px;
        }

        .timecard-details .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
            font-size: 0.9rem;
        }

        .timecard-details input[type="datetime-local"] {
            width: 100%;
            padding: 6px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .timecard-actions {
            display: flex;
            gap: 8px;
            margin-top: 10px;
        }

        .timecard-actions button {
            padding: 6px 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 500;
        }

        #timecardsEntries {
            padding: 15px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
        }

        .timecard-edit {
            background-color: #3498db;
            color: white;
        }

        .timecard-edit:hover {
            background-color: #2980b9;
        }

        .timecard-delete {
            background-color: #e74c3c;
            color: white;
        }

        .timecard-delete:hover {
            background-color: #c0392b;
        }

        .timecard-filters button:hover {
            background-color: #2980b9;
        }

        #currentPayPeriod {
            background-color: #3498db;
            color: white;
        }

        #currentPayPeriod:hover {
            background-color: #2980b9;
        }

        .pay-period-navigation button:hover {
            background-color: #d6dbdf;
        }

        #totalHours, #hourlyRate, #amountDue {
            font-weight: 500;
            text-align: right;
            min-width: 80px;
        }

        #amountDue {
            color: #27ae60;
            font-weight: 600;
        }

        .no-entries {
            text-align: center;
            padding: 20px;
            color: #7f8c8d;
            font-size: 0.95rem;
            background-color: #f9f9f9;
            border-radius: 8px;
            margin-top: 15px;
        }

        .panel-section {
            background-color: #f9f9f9;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border: 1px solid #e0e0e0;
        }

        .panel-section h4 {
            margin-top: 0;
            margin-bottom: 12px;
            font-size: 1rem;
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 8px;
        }

        .manual-entry-form {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .form-row {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }

        .form-row .form-group {
            flex: 1;
            min-width: 200px;
        }

        .manual-entry-form .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
            font-size: 0.9rem;
        }

        .manual-entry-form .form-group input[type="date"],
        .manual-entry-form .form-group input[type="time"],
        .manual-entry-form .form-group select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            margin-top: 10px;
        }

        .checkbox-group input[type="checkbox"] {
            margin-right: 8px;
        }

        .checkbox-group label {
            margin-bottom: 0 !important;
        }

        #addManualEntryBtn {
            padding: 8px 12px;
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            transition: background-color 0.3s ease;
            width: 100%;
            margin-top: 10px;
        }

        #addManualEntryBtn:hover {
            background-color: #219955;
        }

        .entry-type {
            display: block;
            font-size: 0.8rem;
            font-weight: normal;
            margin-top: 5px;
            color: #666;
        }

        .non-payable-badge {
            display: block;
            font-size: 0.7rem;
            color: #fff;
            background-color: #f39c12;
            padding: 2px 6px;
            border-radius: 4px;
            margin-top: 5px;
            text-align: center;
            font-weight: 500;
        }

        /* Entry type styling */
        .entry-type-regular {
            border-left: 4px solid #3498db;
        }

        .entry-type-sick {
            border-left: 4px solid #e74c3c;
        }

        .entry-type-vacation {
            border-left: 4px solid #27ae60;
        }

        .actions-row {
            margin-bottom: 15px;
            display: flex;
            justify-content: flex-end;
        }

        .add-time-entry-btn {
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 15px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s ease;
            display: flex;
            align-items: center;
        }

        .add-time-entry-btn:hover {
            background-color: #219955;
        }

        .add-time-entry-btn::before {
            content: "+";
            font-size: 1.2rem;
            margin-right: 5px;
            font-weight: bold;
        }

        #timeEntryModal .modal-content {
            max-width: 450px;
        }

        #manualTimeEntryForm {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        #manualTimeEntryForm .form-group {
            margin-bottom: 0;
        }

        #manualTimeEntryForm .form-row {
            display: flex;
            gap: 15px;
        }

        #manualTimeEntryForm .form-row .form-group {
            flex: 1;
        }

        #manualTimeEntryForm label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #2c3e50;
            font-size: 0.9rem;
        }

        #manualTimeEntryForm input[type="date"],
        #manualTimeEntryForm input[type="time"],
        #manualTimeEntryForm select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        #addManualEntryBtn {
            margin-top: 5px;
            padding: 10px;
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.95rem;
            font-weight: 500;
            transition: background-color 0.3s ease;
        }

        #addManualEntryBtn:hover {
            background-color: #219955;
        }

        #addTimeEntryMessage {
            margin-top: 10px;
            padding: 8px;
            border-radius: 4px;
            font-size: 0.9rem;
        }

        #addTimeEntryMessage.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        #addTimeEntryMessage.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .section-header h3 {
            margin: 0;
        }

        .add-time-entry-btn {
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 15px;
            font-size: 0.9rem;
            font-weight: 500;
            cursor: pointer;
            transition: background-color 0.3s ease;
            display: flex;
            align-items: center;
        }

        .add-time-entry-btn:hover {
            background-color: #219955;
        }

        .entry-method-toggle {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            padding: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }

        .entry-method-toggle label {
            display: flex;
            align-items: center;
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
        }

        .entry-method-toggle input[type="radio"] {
            margin-right: 8px;
        }

        #timeRangeInputs .checkbox-group {
            display: flex;
            align-items: center;
            margin-top: 22px; /* Align with inputs */
        }

        #totalHoursInput {
            margin-bottom: 15px;
        }

        #entryPayStatus {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
            background-color: #fff;
            margin-bottom: 10px;
        }

        /* Also update the edit interface for existing entries */
        .entry-type-select,
        .entry-pay-status {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }

        .paid-badge, .unpaid-badge {
            display: block;
            font-size: 0.8rem;
            padding: 2px 6px;
            border-radius: 4px;
            margin-top: 5px;
            text-align: center;
            font-weight: 500;
        }

        .paid-badge {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .unpaid-badge {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        /* Company Settings Styles */
        .company-settings-form {
            max-width: 600px;
            background-color: #fff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            margin-top: 20px;
            border: 1px solid #e0e0e0;
        }
        
        .company-settings-form textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 15px;
            resize: vertical;
            font-family: inherit;
        }
        
        .company-settings-form textarea:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
            outline: none;
        }
        
        .save-settings-btn {
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 12px 20px;
            margin-top: 15px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: background-color 0.3s;
        }
        
        .save-settings-btn:hover {
            background-color: #219955;
        }
        
        .settings-message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            font-size: 15px;
        }
        
        .settings-message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        
        .settings-message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        /* Admin Settings Styles */
        .admin-settings-form {
            max-width: 600px;
            background-color: #fff;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            margin-top: 20px;
            border: 1px solid #e0e0e0;
        }

        .admin-settings-form textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 15px;
            resize: vertical;
            font-family: inherit;
        }

        .admin-settings-form textarea:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
            outline: none;
        }

        .save-admin-settings-btn {
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 12px 20px;
            margin-top: 15px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
            transition: background-color 0.3s;
        }

        .save-admin-settings-btn:hover {
            background-color: #219955;
        }

        .admin-settings-message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            font-size: 15px;
        }

        .admin-settings-message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .admin-settings-message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
    </style>
</head>
<body>
    <div id="loginForm">
        <h2>Administrator Login</h2>
        <input type="text" id="username" placeholder="Username">
        <input type="password" id="password" placeholder="Password">
        <button onclick="login()">Login</button>
        <div class="signup-link" style="text-align: center; margin-top: 20px;">
            <a href="signup.php" style="color: #3498db; text-decoration: none;">Create a new account</a>
        </div>
        <div class="employee-link" style="text-align: center; margin-top: 10px; font-size: 14px;">
            <a href="employee-login.php" style="color: #7f8c8d; text-decoration: none;">Employee Clock In</a>
        </div>
    </div>

    <div id="timeclockPanel" class="hidden">
        <div class="panel-header">
            <h2 id="employeeTimeclockHeader" class="centered-header">TimeClock</h2>
            <button id="logoutBtn" onclick="logout()" class="logout-btn">Log Out</button>
        </div>
        <div id="companyInfo" class="company-info">
            <span id="companyNameDisplay"></span>
            <span id="supportEmailDisplay"></span>
        </div>
        <div id="currentTimeDisplay" class="current-time">
            Current Time: <span id="currentTime"></span>
        </div>
        <div id="clockStatus" class="clock-status">
            <div class="status-indicator">Current Status: <span id="currentStatus">Not Clocked In</span></div>
        </div>
        <div class="clock-buttons">
            <button id="clockInBtn" onclick="clockIn()" class="clock-btn">Clock In</button>
            <button id="clockOutBtn" onclick="clockOut()" class="clock-btn">Clock Out</button>
        </div>
        
        <!-- Employee Pay Period Navigation -->
        <div class="employee-pay-period-section">
            <h3>My Pay Period</h3>
            <div id="employeePayPeriodNav">
                <div id="employeePeriodInfo" class="pay-period-info">Loading pay period information...</div>
                <div class="period-navigation">
                    <button id="employeePrevPeriod" class="prev-period-btn">< Previous Period</button>
                    <button id="employeeCurrentPeriod" class="current-period-btn">Current Pay Period</button>
                    <button id="employeeNextPeriod" class="next-period-btn">Next Period ></button>
                </div>
            </div>
            <div id="employeePaymentSummary">
                <div class="summary-panel">
                    <h3>Payment Summary</h3>
                    <div class="summary-details">
                        <p><strong>Total Hours:</strong> <span id="employeeTotalHours">0.00</span></p>
                        <p><strong>Hourly Rate:</strong> <span id="employeeHourlyRate">$0.00</span></p>
                        <p><strong>Amount Due:</strong> <span id="employeeAmountDue">$0.00</span></p>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="entriesList"></div>
    </div>

    <div id="adminPanel" class="hidden">
        <div class="side-menu">
            <h2>Admin Menu</h2>
            <button onclick="showAdminSection('dashboard')" class="active">Dashboard</button>
            <button onclick="showAdminSection('employees')">Employees</button>
            <button onclick="showAdminSection('timecards')">Timecards</button>
            <button onclick="showAdminSection('settings')">Settings</button>
            <button onclick="logout()" class="logout-btn" style="margin-top: 30px;">Log Out</button>
        </div>
        
        <div class="admin-content">
            <div id="dashboardSection" class="admin-section active">
                <h3>Recent Time Entries</h3>
                <div id="adminEntriesList"></div>
            </div>

            <div id="employeesSection" class="admin-section">
                <h3>Employee Management</h3>
                <button id="addEmployeeBtn" class="add-btn">Add Employee</button>
                <div id="userList" class="user-list"></div>
            </div>

            <div id="timecardsSection" class="admin-section">
                <div class="section-header">
                    <h3>Timecard Management</h3>
                    <button id="addTimeEntryBtn" class="add-time-entry-btn">+ Add Manual Time Entry</button>
                </div>
                
                <div class="timecard-filters">
                    <div class="employee-selector">
                        <label for="employeeFilter">Select Employee:</label>
                        <select id="employeeFilter"></select>
                    </div>
                    
                    <div class="date-filters">
                        <div>
                            <label>From:</label>
                            <input type="date" id="startDate">
                        </div>
                        <div>
                            <label>To:</label>
                            <input type="date" id="endDate">
                        </div>
                        <button onclick="filterTimeEntries()">Filter</button>
                    </div>
                </div>
                
                <div id="payPeriodNav">
                    <div id="currentPeriodInfo" class="current-period-display">Current Pay Period: Loading...</div>
                    <div class="pay-period-navigation">
                        <button id="prevPayPeriod" onclick="navigatePayPeriod('prev')">◀ Previous</button>
                        <button id="currentPayPeriod" onclick="navigatePayPeriod('current')">Current</button>
                        <button id="nextPayPeriod" onclick="navigatePayPeriod('next')">Next ▶</button>
                    </div>
                </div>
                
                <div id="paymentSummary">
                    <div class="summary-panel">
                        <h3>Payment Summary</h3>
                        <div class="summary-details">
                            <p><strong>Total Hours:</strong> <span id="totalHours">0.00</span></p>
                            <p><strong>Hourly Rate:</strong> <span id="hourlyRate">$0.00</span></p>
                            <p><strong>Amount Due:</strong> <span id="amountDue">$0.00</span></p>
                        </div>
                    </div>
                </div>
                
                <div id="timecardsEntries"></div>
            </div>
            
            <div id="settingsSection" class="admin-section">
                <h3>Company Settings</h3>
                <div class="company-settings-form">
                    <div class="form-group">
                        <label for="companyName">Company Name:</label>
                        <input type="text" id="companyName" placeholder="Company Name">
                    </div>
                    <div class="form-group">
                        <label for="companyShortName">Company Short Name:</label>
                        <input type="text" id="companyShortName" placeholder="Short Name">
                    </div>
                    <div class="form-group">
                        <label for="companyEmail">Company Email:</label>
                        <input type="email" id="companyEmail" placeholder="contact@company.com">
                    </div>
                    <div class="form-group">
                        <label for="companyAddress">Company Address:</label>
                        <textarea id="companyAddress" placeholder="Company Address" rows="3"></textarea>
                    </div>
                    <button id="saveSettingsBtn" class="save-settings-btn">Save Settings</button>
                    <div id="settingsMessage" class="settings-message"></div>
                </div>

                <h3 style="margin-top: 30px;">Admin Account Settings</h3>
                <div class="admin-settings-form">
                    <div class="form-group">
                        <label for="adminEmail">Admin Email (Username):</label>
                        <input type="email" id="adminEmail" placeholder="your@email.com">
                    </div>
                    <div class="form-group">
                        <label for="adminCurrentPassword">Current Password:</label>
                        <input type="password" id="adminCurrentPassword" placeholder="Current Password">
                    </div>
                    <div class="form-group">
                        <label for="adminNewPassword">New Password (leave blank to keep current):</label>
                        <input type="password" id="adminNewPassword" placeholder="New Password">
                    </div>
                    <div class="form-group">
                        <label for="adminConfirmPassword">Confirm New Password:</label>
                        <input type="password" id="adminConfirmPassword" placeholder="Confirm New Password">
                    </div>
                    <button id="saveAdminSettingsBtn" class="save-admin-settings-btn">Update Admin Credentials</button>
                    <div id="adminSettingsMessage" class="admin-settings-message"></div>
                </div>
            </div>
        </div>
    </div>

    <div id="employeeModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <h3>Create New Employee</h3>
            <div id="createEmployeeForm">
                <div class="form-group">
                    <label for="newName">Full Name:</label>
                    <input type="text" id="newName" placeholder="Full Name">
                </div>
                <div class="form-group">
                    <label for="newUsername">Username:</label>
                    <input type="text" id="newUsername" placeholder="Username">
                </div>
                <div class="form-group">
                    <label for="newPassword">Password:</label>
                    <input type="password" id="newPassword" placeholder="Password">
                </div>
                <div class="form-group">
                    <label for="newHourlyWage">Hourly Wage ($):</label>
                    <input type="number" id="newHourlyWage" placeholder="0.00" step="0.01" min="0">
                </div>
                <div class="form-group">
                    <label for="payPeriodType">Pay Period Type:</label>
                    <select id="payPeriodType">
                        <option value="weekly">Weekly</option>
                        <option value="bi-weekly">Bi-Weekly</option>
                    </select>
                </div>
                <div class="form-group hidden" id="weeklyStartDayGroup">
                    <label for="weeklyStartDay">Pay Period Start Day:</label>
                    <select id="weeklyStartDay">
                        <option value="0">Sunday</option>
                        <option value="1">Monday</option>
                        <option value="2">Tuesday</option>
                        <option value="3">Wednesday</option>
                        <option value="4">Thursday</option>
                        <option value="5">Friday</option>
                        <option value="6">Saturday</option>
                    </select>
                </div>
                <div class="form-group hidden" id="biWeeklyStartDayGroup">
                    <label for="biWeeklyStartDay">Pay Period Start Date:</label>
                    <input type="date" id="biWeeklyStartDay">
                </div>
                <button onclick="createEmployee()">Create Employee</button>
                <div id="createEmployeeMessage"></div>
            </div>
        </div>
    </div>

    <div id="editEmployeeModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <h3>Edit Employee</h3>
            <div id="editEmployeeForm">
                <input type="hidden" id="editUserId">
                <div class="form-group">
                    <label for="editName">Full Name:</label>
                    <input type="text" id="editName" placeholder="Full Name">
                </div>
                <div class="form-group">
                    <label for="editUsername">Username:</label>
                    <input type="text" id="editUsername" placeholder="Username" disabled>
                </div>
                <div class="form-group">
                    <label for="editPassword">New Password (leave blank to keep current):</label>
                    <input type="password" id="editPassword" placeholder="New Password">
                </div>
                <div class="form-group">
                    <label for="editHourlyWage">Hourly Wage ($):</label>
                    <input type="number" id="editHourlyWage" placeholder="0.00" step="0.01" min="0">
                </div>
                <div class="form-group">
                    <label for="editPayPeriodType">Pay Period Type:</label>
                    <select id="editPayPeriodType">
                        <option value="weekly">Weekly</option>
                        <option value="bi-weekly">Bi-Weekly</option>
                    </select>
                </div>
                <div class="form-group" id="editWeeklyStartDayGroup">
                    <label for="editWeeklyStartDay">Pay Period Start Day:</label>
                    <select id="editWeeklyStartDay">
                        <option value="0">Sunday</option>
                        <option value="1">Monday</option>
                        <option value="2">Tuesday</option>
                        <option value="3">Wednesday</option>
                        <option value="4">Thursday</option>
                        <option value="5">Friday</option>
                        <option value="6">Saturday</option>
                    </select>
                </div>
                <div class="form-group hidden" id="editBiWeeklyStartDayGroup">
                    <label for="editBiWeeklyStartDay">Pay Period Start Date:</label>
                    <input type="date" id="editBiWeeklyStartDay">
                </div>
                <button onclick="updateEmployee()">Update Employee</button>
                <div id="editEmployeeMessage"></div>
            </div>
        </div>
    </div>

    <!-- Add Time Entry Modal -->
    <div id="timeEntryModal" class="modal">
        <div class="modal-content">
            <span class="close-modal">&times;</span>
            <h3>Add Manual Time Entry</h3>
            <div id="manualTimeEntryForm">
                <div class="form-group">
                    <label for="manualEntryDate">Date:</label>
                    <input type="date" id="manualEntryDate" required>
                </div>
                <div class="form-group">
                    <label for="manualEntryType">Entry Type:</label>
                    <select id="manualEntryType" required>
                        <option value="regular">Regular</option>
                        <option value="sick">Sick Time</option>
                        <option value="vacation">Vacation</option>
                    </select>
                </div>
                
                <div class="entry-method-toggle">
                    <label>
                        <input type="radio" name="entryMethod" value="timeRange" checked> 
                        Enter Time Range
                    </label>
                    <label>
                        <input type="radio" name="entryMethod" value="totalHours"> 
                        Enter Total Hours
                    </label>
                </div>
                
                <div id="timeRangeInputs" class="form-row">
                    <div class="form-group">
                        <label for="manualEntryStartTime">Start Time:</label>
                        <input type="time" id="manualEntryStartTime">
                    </div>
                    <div class="form-group">
                        <label for="manualEntryEndTime">End Time:</label>
                        <input type="time" id="manualEntryEndTime">
                    </div>
                </div>
                
                <div id="totalHoursInput" class="form-group" style="display:none;">
                    <label for="manualEntryTotalHours">Total Hours:</label>
                    <input type="number" id="manualEntryTotalHours" step="0.01" min="0" max="24">
                </div>
                
                <div class="form-group">
                    <label for="entryPayStatus">Paid:</label>
                    <select id="entryPayStatus" required>
                        <option value="yes">Yes</option>
                        <option value="no">No</option>
                    </select>
                </div>
                
                <button id="addManualEntryBtn" onclick="addManualTimeEntry()">Add Entry</button>
                <div id="addTimeEntryMessage"></div>
            </div>
        </div>
    </div>

    <script>
        // Make sure all panels are hidden on page load
        $(document).ready(function() {
            console.log('Document ready - initializing app');
            $('#adminPanel').addClass('hidden');
            $('#timeclockPanel').addClass('hidden');
            
            // Initialize and update the current time
            updateCurrentTime();
            setInterval(updateCurrentTime, 1000);
            
            // Set default date for bi-weekly date picker
            const today = new Date();
            const formattedDate = today.toISOString().split('T')[0];
            $('#biWeeklyStartDay').val(formattedDate);
            $('#editBiWeeklyStartDay').val(formattedDate);
            
            // Pay period type change handler
            $('#payPeriodType').change(function() {
                const periodType = $(this).val();
                if (periodType === 'weekly') {
                    $('#weeklyStartDayGroup').removeClass('hidden');
                    $('#biWeeklyStartDayGroup').addClass('hidden');
                } else {
                    $('#weeklyStartDayGroup').addClass('hidden');
                    $('#biWeeklyStartDayGroup').removeClass('hidden');
                }
            });
            
            // Set up employee pay period navigation buttons
            $('#employeePrevPeriod').on('click', function() {
                console.log('Employee Previous Period button clicked');
                navigateEmployeePayPeriod('prev');
            });
            
            $('#employeeCurrentPeriod').on('click', function() {
                console.log('Employee Current Period button clicked');
                navigateEmployeePayPeriod('current');
            });
            
            $('#employeeNextPeriod').on('click', function() {
                console.log('Employee Next Period button clicked');
                navigateEmployeePayPeriod('next');
            });
            
            // Check if user is already logged in (session exists)
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'check_session' }),
                success: function(response) {
                    if (response && response.logged_in) {
                        $('#loginForm').hide();
                        if (response.is_admin) {
                            console.log('Admin login successful');
                            $('#adminPanel').removeClass('hidden');
                            showAdminSection('dashboard');
                            loadAdminEntries();
                        } else {
                            console.log('Employee login successful');
                            // Initialize employee timeclock panel
                            $('#timeclockPanel').removeClass('hidden');
                            
                            // Initialize the clock display
                            updateCurrentTime();
                            setInterval(updateCurrentTime, 1000);
                            
                            // Check if currently clocked in
                            $.ajax({
                                url: 'index.php',
                                method: 'POST',
                                contentType: 'application/json',
                                dataType: 'json',
                                data: JSON.stringify({ action: 'get_entries' }),
                                success: function(response) {
                                    console.log('Clock status check:', response);
                                    if (response && response.entries) {
                                        const hasActiveEntry = response.entries.some(entry => !entry.clock_out);
                                        updateClockStatus(hasActiveEntry);
                                    }
                                    
                                    // Set employee name in header
                                    $.ajax({
                                        url: 'index.php',
                                        method: 'POST',
                                        contentType: 'application/json',
                                        dataType: 'json',
                                        data: JSON.stringify({ action: 'get_user' }),
                                        success: function(response) {
                                            if (response && response.user) {
                                                $('#employeeTimeclockHeader').text(response.user.name + "'s Time Clock");
                                            }
                                            
                                            // Load company info
                                            loadCompanyInfo();
                                            
                                            $('#timeclockPanel').removeClass('hidden');
                                            loadEntries();
                                        }
                                    });
                                }
                            });
                        }
                    }
                }
            });
        });
        
        function login() {
            const username = $('#username').val();
            const password = $('#password').val();
            
            if (!username || !password) {
                alert('Please enter both username and password');
                return;
            }
            
            console.log('Attempting login with:', username);
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({
                    action: 'login',
                    username: username,
                    password: password
                }),
                success: function(response) {
                    console.log('Login response:', response);
                    if (response && response.success) {
                        $('#loginForm').hide();
                        if (response.is_admin) {
                            console.log('Admin login successful');
                            $('#adminPanel').removeClass('hidden');
                            showAdminSection('dashboard');
                            loadAdminEntries();
                        } else {
                            console.log('Employee login successful');
                            // Initialize employee timeclock panel
                            $('#timeclockPanel').removeClass('hidden');
                            
                            // Initialize the clock display
                            updateCurrentTime();
                            setInterval(updateCurrentTime, 1000);
                            
                            // Check if currently clocked in
                            $.ajax({
                                url: 'index.php',
                                method: 'POST',
                                contentType: 'application/json',
                                dataType: 'json',
                                data: JSON.stringify({ action: 'get_entries' }),
                                success: function(response) {
                                    console.log('Clock status check:', response);
                                    if (response && response.entries) {
                                        const hasActiveEntry = response.entries.some(entry => !entry.clock_out);
                                        updateClockStatus(hasActiveEntry);
                                    }
                                    
                                    // Set employee name in header
                                    $.ajax({
                                        url: 'index.php',
                                        method: 'POST',
                                        contentType: 'application/json',
                                        dataType: 'json',
                                        data: JSON.stringify({ action: 'get_user' }),
                                        success: function(response) {
                                            if (response && response.user) {
                                                $('#employeeTimeclockHeader').text(response.user.name + "'s Time Clock");
                                            }
                                            
                                            // Load company info
                                            loadCompanyInfo();
                                            
                                            $('#timeclockPanel').removeClass('hidden');
                                            loadEntries();
                                        }
                                    });
                                }
                            });
                        }
                    } else {
                        console.error('Login failed response:', response);
                        alert('Login failed: ' + (response ? response.error : 'Unknown error'));
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Login AJAX error:', xhr, status, error);
                    try {
                        const response = xhr.responseJSON || JSON.parse(xhr.responseText);
                        alert('Error during login: ' + (response.error || error));
                    } catch (e) {
                        alert('Error during login: ' + error);
                    }
                }
            });
        }

        function clockIn() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'clock_in' }),
                success: function(response) {
                    if (response.success) {
                        updateClockStatus(true);
                        loadEntries();
                    } else {
                        alert('Clock in failed: ' + response.error);
                    }
                }
            });
        }

        function clockOut() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'clock_out' }),
                success: function(response) {
                    if (response.success) {
                        updateClockStatus(false);
                        loadEntries();
                    } else {
                        alert('Clock out failed: ' + response.error);
                    }
                }
            });
        }

        function updateClockStatus(isClockedIn) {
            const statusElement = $('#clockStatus');
            const statusText = $('#currentStatus');
            const clockInBtn = $('#clockInBtn');
            const clockOutBtn = $('#clockOutBtn');
            
            if (isClockedIn) {
                statusElement.removeClass('not-clocked-in').addClass('clocked-in');
                statusText.text('CLOCKED IN - Don\'t forget to clock out!');
                clockInBtn.addClass('disabled').prop('disabled', true);
                clockOutBtn.removeClass('disabled').prop('disabled', false);
            } else {
                statusElement.removeClass('clocked-in').addClass('not-clocked-in');
                statusText.text('Not Clocked In');
                clockInBtn.removeClass('disabled').prop('disabled', false);
                clockOutBtn.addClass('disabled').prop('disabled', true);
            }
        }

        // Store employee's own pay period settings
        let employeePayPeriod = {
            id: null,
            payPeriodType: null,
            payPeriodStartDay: null,
            hourlyWage: 0,
            currentPeriodOffset: 0  // 0 = current period, -1 = previous period, 1 = next period
        };
        
        function loadEntries() {
            console.log('Loading time entries for employee');
            
            // Get employee's full name and pay period settings
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ 
                    action: 'get_user'
                    // No user_id - will default to current user
                }),
                success: function(response) {
                    console.log('Got employee data:', response);
                    if (response && response.user) {
                        // Initialize pay period navigation
                        initializeEmployeePayPeriod();
                    } else {
                        console.error('Failed to get employee data or data is invalid:', response);
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Error fetching employee name:', error);
                }
            });
            
            // Get time entries
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'get_entries' }),
                success: function(response) {
                    console.log('Entries response:', response);
                    if (response && response.entries) {
                        // Check if user is currently clocked in
                        const hasActiveEntry = response.entries.some(entry => !entry.clock_out);
                        updateClockStatus(hasActiveEntry);
                        
                        displayEntries(response.entries, '#entriesList');
                        
                        // Calculate total hours and payment if employee settings are loaded
                        if (employeePayPeriod.id) {
                            calculateEmployeePaymentSummary(response.entries);
                        }
                    } else {
                        console.error('Failed to load entries:', response);
                        $('#entriesList').html('<p>No entries found or error loading entries.</p>');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Error loading entries:', error);
                    $('#entriesList').html('<p>Error loading entries: ' + error + '</p>');
                }
            });
        }
        
        // Navigate employee pay periods
        function navigateEmployeePayPeriod(direction) {
            console.log('navigateEmployeePayPeriod called with direction:', direction);
            console.log('Current employeePayPeriod:', employeePayPeriod);
            
            // Initialize employeePayPeriod if not already set
            if (!employeePayPeriod.id) {
                console.log('employeePayPeriod not initialized, fetching user data');
                initializeEmployeePayPeriod();
                return;
            }
            
            // Set defaults for missing values
            if (!employeePayPeriod.payPeriodType) {
                employeePayPeriod.payPeriodType = 'weekly';
            }
            
            if (employeePayPeriod.payPeriodStartDay === null || employeePayPeriod.payPeriodStartDay === undefined) {
                employeePayPeriod.payPeriodStartDay = employeePayPeriod.payPeriodType === 'weekly' ? 0 : 1;
            }
            
            // Update the offset based on direction
            if (direction === 'prev') {
                employeePayPeriod.currentPeriodOffset--;
            } else if (direction === 'next') {
                employeePayPeriod.currentPeriodOffset++;
            } else if (direction === 'current') {
                employeePayPeriod.currentPeriodOffset = 0;
            }
            
            console.log('Updated offset to:', employeePayPeriod.currentPeriodOffset);
            
            // Calculate the date range for the pay period
            const dateRange = calculatePayPeriodDates(
                employeePayPeriod.payPeriodType, 
                employeePayPeriod.payPeriodStartDay, 
                employeePayPeriod.currentPeriodOffset
            );
            
            console.log('Calculated date range:', dateRange);
            
            // Store date range for filtering entries
            window.employeeDateRange = {
                start: dateRange.start,
                end: dateRange.end
            };
            
            // Format dates for display
            const formatDisplayDate = (dateStr) => {
                const parts = dateStr.split('-');
                const year = parts[0];
                const month = parseInt(parts[1]) - 1; // JavaScript months are 0-based
                const day = parseInt(parts[2]);
                
                const date = new Date(year, month, day);
                return date.toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric'
                });
            };
            
            // Update period info display
            const periodType = employeePayPeriod.payPeriodType === 'weekly' ? 'Weekly' : 'Bi-Weekly';
            let periodLabel = `${periodType} Pay Period: ${formatDisplayDate(dateRange.start)} - ${formatDisplayDate(dateRange.end)}`;
            
            if (employeePayPeriod.currentPeriodOffset === 0) {
                periodLabel += ' (Current)';
            } else if (employeePayPeriod.currentPeriodOffset < 0) {
                periodLabel += ` (${Math.abs(employeePayPeriod.currentPeriodOffset)} period${Math.abs(employeePayPeriod.currentPeriodOffset) > 1 ? 's' : ''} ago)`;
            } else {
                periodLabel += ` (${employeePayPeriod.currentPeriodOffset} period${employeePayPeriod.currentPeriodOffset > 1 ? 's' : ''} ahead)`;
            }
            
            console.log('Setting period info to:', periodLabel);
            $('#employeePeriodInfo').text(periodLabel);
            
            // Load filtered entries
            loadFilteredEmployeeEntries(dateRange.start, dateRange.end);
        }
        
        // Initialize employee pay period data
        function initializeEmployeePayPeriod() {
            console.log('Initializing employee pay period data');
            
            // Set default values even before the AJAX call, in case it fails
            employeePayPeriod = {
                id: <?php echo isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'null' ?>,
                payPeriodType: 'weekly',
                payPeriodStartDay: 0,
                hourlyWage: 0,
                currentPeriodOffset: 0
            };
            
            // Update the hourly rate display with default value
            $('#employeeHourlyRate').text(employeePayPeriod.hourlyWage.toFixed(2));
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ 
                    action: 'get_user'
                    // No user_id, which will use the current user's ID on the server
                }),
                success: function(response) {
                    console.log('Got employee data for pay period:', response);
                    
                    if (response && response.success && response.user) {
                        // Store employee pay period settings
                        employeePayPeriod = {
                            id: response.user.id,
                            payPeriodType: response.user.pay_period_type || 'weekly',
                            payPeriodStartDay: parseInt(response.user.pay_period_start_day || 0),
                            hourlyWage: parseFloat(response.user.hourly_wage) || 0,
                            currentPeriodOffset: 0
                        };
                        
                        console.log('Initialized employeePayPeriod:', employeePayPeriod);
                        
                        // Update hourly rate display
                        $('#employeeHourlyRate').text(employeePayPeriod.hourlyWage.toFixed(2));
                        
                        // Now navigate to current period
                        navigateEmployeePayPeriod('current');
                    } else {
                        console.error('Failed to get employee data:', response);
                        $('#employeePeriodInfo').text('Error loading pay period data. Using defaults.');
                        // Use default values and proceed anyway
                        navigateEmployeePayPeriod('current');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('AJAX error getting employee data:', error);
                    $('#employeePeriodInfo').text('Error loading pay period data. Using defaults.');
                    // Use default values and proceed anyway
                    navigateEmployeePayPeriod('current');
                },
                // Add a timeout to ensure we don't hang indefinitely
                timeout: 5000
            });
        }
        
        // Load entries for the employee within a specific date range
        function loadFilteredEmployeeEntries(startDate, endDate) {
            console.log('Loading filtered employee entries for date range:', startDate, 'to', endDate);
            
            if (!startDate || !endDate) {
                console.error('Invalid date range for filtering:', startDate, endDate);
                $('#entriesList').html('<p>Error: Invalid date range for filtering entries.</p>');
                return;
            }
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ 
                    action: 'get_entries',
                    start_date: startDate,
                    end_date: endDate
                }),
                success: function(response) {
                    console.log('Filtered entries response:', response);
                    if (response && response.entries) {
                        // Ensure we have an array of entries
                        const entries = Array.isArray(response.entries) ? response.entries : [];
                        console.log('Got', entries.length, 'filtered entries');
                        
                        if (entries.length > 0) {
                            displayEntries(entries, '#entriesList');
                            calculateEmployeePaymentSummary(entries);
                        } else {
                            console.log('No entries found for this period');
                            $('#entriesList').html('<p>No time entries found for this period.</p>');
                            // Reset payment summary
                            $('#employeeTotalHours').text('0.00');
                            $('#employeeAmountDue').text('0.00');
                        }
                    } else {
                        console.log('No entries found for this period');
                        $('#entriesList').html('<p>No entries found for this period.</p>');
                        // Reset payment summary
                        $('#employeeTotalHours').text('0.00');
                        $('#employeeAmountDue').text('0.00');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Error loading filtered entries:', error);
                    $('#entriesList').html('<p>Error loading entries: ' + error + '</p>');
                    // Reset payment summary
                    $('#employeeTotalHours').text('0.00');
                    $('#employeeAmountDue').text('0.00');
                }
            });
        }
        
        // Calculate employee payment summary
        function calculateEmployeePaymentSummary(entries) {
            console.log('Calculating payment summary for', entries.length, 'entries');
            
            if (!employeePayPeriod.id || !employeePayPeriod.hourlyWage) {
                console.error('Cannot calculate payment - employeePayPeriod not properly initialized');
                return;
            }
            
            let totalHours = 0;
            let paidHours = 0;
            
            // Sum up all hours worked
            entries.forEach(entry => {
                if (entry.hours_worked) {
                    let hours = parseFloat(entry.hours_worked);
                    if (!isNaN(hours)) {
                        totalHours += hours;
                        
                        // Only add to paid hours if non_payable is not set to 1
                        if (entry.non_payable != 1) {
                            paidHours += hours;
                            console.log('Added', hours, 'PAID hours from entry, paid total now:', paidHours);
                        } else {
                            console.log('Skipped', hours, 'UNPAID hours from entry');
                        }
                    }
                }
            });
            
            // Calculate amount due based on hourly wage and paid hours only
            const hourlyWage = parseFloat(employeePayPeriod.hourlyWage);
            const amountDue = paidHours * hourlyWage;
            
            console.log('Total hours:', totalHours, '(Paid:', paidHours, ') at rate:', hourlyWage, '= amount due:', amountDue);
            
            // Update the display
            $('#employeeTotalHours').text(totalHours.toFixed(2));
            $('#employeeHourlyRate').text('$' + hourlyWage.toFixed(2));
            $('#employeeAmountDue').text('$' + amountDue.toFixed(2));
        }

        function loadAdminEntries() {
            console.log('Loading admin time entries');
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'get_entries' }),
                success: function(response) {
                    console.log('Admin entries response:', response);
                    if (response && response.entries) {
                        displayEntries(response.entries, '#adminEntriesList');
                    } else {
                        console.error('Failed to load admin entries:', response);
                        $('#adminEntriesList').html('<p>No entries found or error loading entries.</p>');
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Error loading admin entries:', error);
                    $('#adminEntriesList').html('<p>Error loading entries: ' + error + '</p>');
                }
            });
        }

        function displayEntries(entries, target) {
            console.log('Displaying', entries.length, 'entries on target:', target);
            
            if (!entries || entries.length === 0) {
                $(target).html('<p>No time entries found.</p>');
                return;
            }
            
            let html;
            
            // If this is the employee list view, use a nicer format
            if (target === '#entriesList') {
                html = `
                    <h3>My Time Entries</h3>
                    <div class="employee-entries">
                        ${entries.map(entry => {
                            // Format date more nicely
                            const clockInDate = entry.clock_in ? new Date(entry.clock_in.replace(' ', 'T')) : null;
                            const clockOutDate = entry.clock_out ? new Date(entry.clock_out.replace(' ', 'T')) : null;
                            
                            // Format for display date
                            const displayDate = clockInDate ? clockInDate.toLocaleDateString('en-US', {
                                weekday: 'short',
                                month: 'short',
                                day: 'numeric',
                                year: 'numeric'
                            }) : 'Unknown';
                            
                            // Format for display time
                            const formatTime = (date) => {
                                if (!date) return 'Active';
                                return date.toLocaleTimeString('en-US', {
                                    hour: 'numeric',
                                    minute: '2-digit',
                                    hour12: true
                                });
                            };
                            
                            const clockInTime = clockInDate ? formatTime(clockInDate) : 'Unknown';
                            const clockOutTime = clockOutDate ? formatTime(clockOutDate) : 'Active';
                            
                            // Get entry type and format it nicely
                            const entryType = entry.entry_type || 'regular';
                            const entryTypeLabel = entryType.charAt(0).toUpperCase() + entryType.slice(1);
                            const entryTypeClass = `entry-type-${entryType}`;
                            
                            // Check if entry is paid or unpaid
                            const isPaid = entry.non_payable != 1;
                            const paidStatus = isPaid ? 
                                '<span class="paid-badge">Paid</span>' : 
                                '<span class="unpaid-badge">Unpaid</span>';
                            
                            return `
                                <div class="employee-entry ${entryTypeClass}">
                                    <div class="entry-date">
                                        <div>${displayDate}</div>
                                        <span class="entry-type">${entryTypeLabel}</span>
                                        ${paidStatus}
                                    </div>
                                    <div class="entry-details">
                                        <p><strong>Clock In:</strong> ${clockInTime}</p>
                                        <p><strong>Clock Out:</strong> ${clockOutTime}</p>
                                        <p><strong>Hours:</strong> ${entry.hours_worked || 'N/A'}</p>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                    </div>
                `;
            } else {
                // Compact format for admin view
                html = entries.map(entry => {
                    // Format date more nicely
                    const clockInDate = entry.clock_in ? new Date(entry.clock_in.replace(' ', 'T')) : null;
                    const clockOutDate = entry.clock_out ? new Date(entry.clock_out.replace(' ', 'T')) : null;
                    
                    // Format for display time
                    const formatTime = (date) => {
                        if (!date) return 'Active';
                        return date.toLocaleTimeString('en-US', {
                            hour: 'numeric',
                            minute: '2-digit',
                            hour12: true
                        });
                    };
                    
                    const displayDate = clockInDate ? clockInDate.toLocaleDateString('en-US', {
                        month: 'short',
                        day: 'numeric'
                    }) : 'Unknown';
                    
                    const clockInTime = clockInDate ? formatTime(clockInDate) : 'Unknown';
                    const clockOutTime = clockOutDate ? formatTime(clockOutDate) : 'Active';
                    
                    return `
                        <div class="entry">
                            <p>User: ${entry.username}</p>
                            <p>${displayDate}: ${clockInTime} - ${clockOutTime}</p>
                            <p>Hours: ${entry.hours_worked || 'N/A'}</p>
                            <p>${entry.entry_type || 'Regular'}</p>
                        </div>
                    `;
                }).join('');
            }
            
            $(target).html(html);
        }
        
        // Helper function to format date for display
        function formatDisplayDate(dateStr) {
            const parts = dateStr.split('-');
            const year = parts[0];
            const month = parseInt(parts[1]) - 1; // JavaScript months are 0-based
            const day = parseInt(parts[2]);
            
            const date = new Date(year, month, day);
            return date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                year: 'numeric'
            });
        }

        function createEmployee() {
            const name = $('#newName').val();
            const username = $('#newUsername').val();
            const password = $('#newPassword').val();
            const hourly_wage = $('#newHourlyWage').val();
            const payPeriodType = $('#payPeriodType').val();
            let payPeriodStartDay;
            
            if (payPeriodType === 'weekly') {
                payPeriodStartDay = $('#weeklyStartDay').val();
            } else {
                // For bi-weekly, extract the day of month from the date picker
                const selectedDate = new Date($('#biWeeklyStartDay').val());
                payPeriodStartDay = selectedDate.getDate();
            }
            
            if (!name || !username || !password) {
                $('#createEmployeeMessage').removeClass('success').addClass('error').text('Name, username and password are required');
                return;
            }
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'create_employee',
                    name: name,
                    username: username,
                    password: password,
                    hourly_wage: hourly_wage,
                    pay_period_type: payPeriodType,
                    pay_period_start_day: payPeriodStartDay
                }),
                success: function(response) {
                    if (response.success) {
                        $('#createEmployeeMessage').removeClass('error').addClass('success').text(response.message);
                        $('#newName').val('');
                        $('#newUsername').val('');
                        $('#newPassword').val('');
                        $('#newHourlyWage').val('0.00');
                        $('#payPeriodType').val('weekly');
                        $('#weeklyStartDay').val('0');
                        $('#biWeeklyStartDay').val('1');
                        // Reset pay period display
                        $('#weeklyStartDayGroup').removeClass('hidden');
                        $('#biWeeklyStartDayGroup').addClass('hidden');
                        loadUsers();
                        
                        // Close the modal after successful creation
                        setTimeout(function() {
                            $('#employeeModal').css('display', 'none');
                            $('#createEmployeeMessage').text('');
                        }, 1500);
                    } else {
                        $('#createEmployeeMessage').removeClass('success').addClass('error').text(response.error);
                    }
                }
            });
        }

        function loadUsers() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'get_users',
                    include_admins: false  // Don't include admin users in the employee list
                }),
                success: function(response) {
                    if (response.users) {
                        displayUsers(response.users);
                    }
                }
            });
        }

        function displayUsers(users) {
            const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
            
            const html = users.map(user => {
                // Format pay period info
                let payPeriodInfo = '';
                if (user.pay_period_type === 'weekly') {
                    payPeriodInfo = `Weekly (starts on ${dayNames[user.pay_period_start_day]})`;
                } else {
                    payPeriodInfo = `Bi-Weekly (starts on date ${user.pay_period_start_day} of month)`;
                }
                
                return `
                    <div class="user-item">
                        <p><strong>${user.name}</strong> (${user.username})</p>
                        <p>Role: ${user.is_admin ? 'Admin' : 'Employee'}</p>
                        <p>Pay Period: ${payPeriodInfo}</p>
                        <p>Created: ${user.created_at}</p>
                        <div class="user-actions">
                            <button onclick="editUser(${user.id})" class="edit-btn">Edit</button>
                            ${!user.is_admin ? `<button onclick="deleteUser(${user.id})" class="delete-btn">Delete</button>` : ''}
                        </div>
                    </div>
                `;
            }).join('');
            
            $('#userList').html(html);
        }

        function deleteUser(userId) {
            if (confirm('Are you sure you want to delete this user? This will also delete all their time entries.')) {
                $.ajax({
                    url: 'index.php',
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({
                        action: 'delete_user',
                        user_id: userId
                    }),
                    success: function(response) {
                        if (response.success) {
                            loadUsers();
                            loadAdminEntries();
                        } else {
                            alert('Error: ' + response.error);
                        }
                    }
                });
            }
        }

        function showAdminSection(section) {
            // Update active button
            $('.side-menu button').removeClass('active');
            $(`.side-menu button:contains('${section.charAt(0).toUpperCase() + section.slice(1)}')`).addClass('active');
            
            // Show selected section
            $('.admin-section').removeClass('active');
            $(`#${section}Section`).addClass('active');

            // Load section data
            if (section === 'employees') {
                loadUsers();
            } else if (section === 'timecards') {
                loadEmployeesList();
                // loadTimeEntries() will be called after employee is loaded and selected
            } else if (section === 'dashboard') {
                loadAdminEntries();
            } else if (section === 'settings') {
                loadCompanySettings();
            }
        }

        function loadEmployeesList() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'get_users',
                    include_admins: false  // Only show employees in the dropdown
                }),
                success: function(response) {
                    if (response.users && response.users.length > 0) {
                        const options = response.users.map(user => 
                            `<option value="${user.id}">${user.name} (${user.username})</option>`
                        ).join('');
                        
                        // No "All Employees" option, just the list of employees
                        $('#employeeFilter').html(options);
                        
                        // Get the ID of the first employee to select by default
                        const firstEmployeeId = response.users[0].id;
                        
                        // Set the selected employee
                        $('#employeeFilter').val(firstEmployeeId);
                        
                        // Fetch employee settings for pay period for the first employee
                        fetchEmployeePayPeriodSettings(firstEmployeeId);
                        
                        // Add change event to employee filter
                        $('#employeeFilter').off('change').on('change', function() {
                            const selectedEmployeeId = $(this).val();
                            fetchEmployeePayPeriodSettings(selectedEmployeeId);
                        });
                    }
                }
            });
        }
        
        function loadCompanySettings() {
            // Clear any previous messages
            $('#settingsMessage').removeClass('success error').text('');
            $('#adminSettingsMessage').removeClass('success error').text('');
            
            // Load company settings from the server
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'get_company_settings'
                }),
                success: function(response) {
                    if (response.success && response.settings) {
                        // Populate the form with company settings
                        $('#companyName').val(response.settings.company_name);
                        $('#companyShortName').val(response.settings.company_short_name);
                        $('#companyEmail').val(response.settings.company_email);
                        $('#companyAddress').val(response.settings.company_address);
                    }
                }
            });
            
            // Load current admin email
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'get_user'
                }),
                success: function(response) {
                    if (response.user) {
                        // Populate the admin email field
                        $('#adminEmail').val(response.user.username);
                    }
                }
            });
            
            // Set up the save buttons event handlers
            $('#saveSettingsBtn').off('click').on('click', function() {
                saveCompanySettings();
            });
            
            $('#saveAdminSettingsBtn').off('click').on('click', function() {
                updateAdminSettings();
            });
        }
        
        function saveCompanySettings() {
            // Get the form values
            const companyName = $('#companyName').val();
            const companyShortName = $('#companyShortName').val();
            const companyEmail = $('#companyEmail').val();
            const companyAddress = $('#companyAddress').val();
            
            // Validate inputs
            if (!companyName) {
                $('#settingsMessage').removeClass('success').addClass('error').text('Company name is required');
                return;
            }
            
            // Save company settings to the server
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'update_company_settings',
                    company_name: companyName,
                    company_short_name: companyShortName,
                    company_email: companyEmail,
                    company_address: companyAddress
                }),
                success: function(response) {
                    if (response.success) {
                        $('#settingsMessage').removeClass('error').addClass('success').text(response.message);
                    } else {
                        $('#settingsMessage').removeClass('success').addClass('error').text(response.error || 'Error saving settings');
                    }
                },
                error: function(xhr, status, error) {
                    $('#settingsMessage').removeClass('success').addClass('error').text('Error saving settings: ' + error);
                }
            });
        }

        function filterTimeEntries() {
            const employeeId = $('#employeeFilter').val();
            const startDate = $('#startDate').val();
            const endDate = $('#endDate').val();
            
            // Store the current filter parameters to use when reloading after edits
            window.currentTimecardsFilter = {
                employeeId: employeeId,
                startDate: startDate,
                endDate: endDate
            };
            
            loadTimeEntries(employeeId, startDate, endDate);
        }

        function loadTimeEntries(employeeId = '', startDate = '', endDate = '') {
            // If we have stored filter parameters and no arguments were provided, use the stored parameters
            if (window.currentTimecardsFilter && (!employeeId && !startDate && !endDate)) {
                employeeId = window.currentTimecardsFilter.employeeId;
                startDate = window.currentTimecardsFilter.startDate;
                endDate = window.currentTimecardsFilter.endDate;
            }
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({ 
                    action: 'get_entries',
                    employee_id: employeeId,
                    start_date: startDate,
                    end_date: endDate
                }),
                success: function(response) {
                    if (response.entries) {
                        displayTimeEntries(response.entries);
                        
                        // Calculate and display total hours and payment if a specific employee is selected
                        if (employeeId && currentEmployee.id === parseInt(employeeId)) {
                            calculatePaymentSummary(response.entries);
                        }
                    }
                }
            });
        }

        function displayTimeEntries(entries) {
            const html = entries.map(entry => {
                const entryType = entry.entry_type ? entry.entry_type : 'regular';
                const isPaid = entry.non_payable != 1;
                const paidStatus = isPaid ? '<span class="paid-badge">Paid</span>' : '<span class="unpaid-badge">Unpaid</span>';
                const entryTypeLabel = entryType.charAt(0).toUpperCase() + entryType.slice(1);
                const entryTypeClass = `entry-type-${entryType}`;
                
                return `
                <div class="timecard-entry ${entryTypeClass}" data-id="${entry.id}">
                    <div class="timecard-date">
                        ${new Date(entry.clock_in).toLocaleDateString('en-US', {month: 'short', day: 'numeric'})}
                        <span class="entry-type">${entryTypeLabel}</span>
                        ${paidStatus}
                    </div>
                    <div class="timecard-details">
                        <p><strong>Employee:</strong> ${entry.username}</p>
                        <p><strong>Clock In:</strong> ${entry.clock_in}</p>
                        <p><strong>Clock Out:</strong> ${entry.clock_out || 'Active'}</p>
                        <p><strong>Hours:</strong> ${entry.hours_worked || 'N/A'}</p>
                        
                        <div class="entry-fields hidden">
                            <div class="form-group">
                                <label>Clock In:</label>
                                <input type="datetime-local" class="clock-in" 
                                       value="${entry.clock_in.replace(' ', 'T')}">
                            </div>
                            <div class="form-group">
                                <label>Clock Out:</label>
                                <input type="datetime-local" class="clock-out" 
                                       value="${entry.clock_out ? entry.clock_out.replace(' ', 'T') : ''}">
                            </div>
                            <div class="form-group">
                                <label>Entry Type:</label>
                                <select class="entry-type-select">
                                    <option value="regular" ${entryType === 'regular' ? 'selected' : ''}>Regular</option>
                                    <option value="sick" ${entryType === 'sick' ? 'selected' : ''}>Sick Time</option>
                                    <option value="vacation" ${entryType === 'vacation' ? 'selected' : ''}>Vacation</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Paid:</label>
                                <select class="entry-pay-status">
                                    <option value="yes" ${isPaid ? 'selected' : ''}>Yes</option>
                                    <option value="no" ${!isPaid ? 'selected' : ''}>No</option>
                                </select>
                            </div>
                            <div class="timecard-actions">
                                <button class="timecard-edit" onclick="updateTimeEntry(${entry.id})">Save Changes</button>
                                <button class="timecard-delete" onclick="cancelEdit(${entry.id})">Cancel</button>
                            </div>
                        </div>
                        
                        <div class="entry-display">
                            <div class="timecard-actions">
                                <button class="timecard-edit" onclick="editTimeEntry(${entry.id})">Edit</button>
                                <button class="timecard-delete" onclick="deleteTimeEntry(${entry.id})">Delete</button>
                            </div>
                        </div>
                    </div>
                </div>
            `}).join('');
            
            if (entries.length === 0) {
                $('#timecardsEntries').html('<div class="no-entries">No time entries found for the selected period.</div>');
            } else {
                $('#timecardsEntries').html(html);
            }
        }

        function editTimeEntry(entryId) {
            const entry = $(`div[data-id="${entryId}"]`);
            entry.find('.entry-display').addClass('hidden');
            entry.find('.entry-fields').removeClass('hidden');
        }
        
        function cancelEdit(entryId) {
            const entry = $(`div[data-id="${entryId}"]`);
            entry.find('.entry-fields').addClass('hidden');
            entry.find('.entry-display').removeClass('hidden');
            
            // No need to reload all entries, just hide the edit form
        }

        function updateTimeEntry(entryId) {
            const entry = $(`div[data-id="${entryId}"]`);
            const clockIn = entry.find('.clock-in').val().replace('T', ' ');
            const clockOut = entry.find('.clock-out').val().replace('T', ' ');
            const entryType = entry.find('.entry-type-select').val();
            const isPaid = entry.find('.entry-pay-status').val() === 'yes';
            const nonPayable = !isPaid; // Convert yes/no to the nonPayable flag (inverse of isPaid)
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'update_time_entry',
                    entry_id: entryId,
                    clock_in: clockIn,
                    clock_out: clockOut,
                    entry_type: entryType,
                    non_payable: nonPayable
                }),
                success: function(response) {
                    if (response.success) {
                        // After successful update, reload entries and reset the display
                        filterTimeEntries();
                    } else {
                        alert('Error updating time entry: ' + response.error);
                    }
                },
                error: function(xhr, status, error) {
                    alert('Error updating time entry: ' + error);
                }
            });
        }

        function deleteTimeEntry(entryId) {
            if (confirm('Are you sure you want to delete this time entry?')) {
                $.ajax({
                    url: 'index.php',
                    method: 'POST',
                    contentType: 'application/json',
                    data: JSON.stringify({
                        action: 'delete_time_entry',
                        entry_id: entryId
                    }),
                    success: function(response) {
                        if (response.success) {
                            loadTimeEntries();
                        } else {
                            alert('Error deleting time entry: ' + response.error);
                        }
                    }
                });
            }
        }

        // Function to update the current time display
        function updateCurrentTime() {
            const now = new Date();
            const formattedTime = now.toLocaleTimeString();
            $('#currentTime').text(formattedTime);
        }

        function logout() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'logout' }),
                success: function(response) {
                    // Regardless of response, redirect to login
                    window.location.reload();
                },
                error: function() {
                    // Even on error, attempt to reload the page
                    window.location.reload();
                }
            });
        }

        // Add this to your existing jQuery document ready function
        $(document).ready(function() {
            // Modal functionality
            $('#addEmployeeBtn').click(function() {
                $('#employeeModal').css('display', 'block');
                // Make sure weekly start day is visible by default
                $('#weeklyStartDayGroup').removeClass('hidden');
                $('#biWeeklyStartDayGroup').addClass('hidden');
                $('#payPeriodType').val('weekly');
            });
            
            $('.close-modal').click(function() {
                $(this).closest('.modal').css('display', 'none');
            });
            
            // Close modal when clicking outside the content
            $(window).click(function(event) {
                if ($(event.target).hasClass('modal')) {
                    $('.modal').css('display', 'none');
                }
            });
            
            // Pay period type change handler for edit form
            $('#editPayPeriodType').change(function() {
                const periodType = $(this).val();
                if (periodType === 'weekly') {
                    $('#editWeeklyStartDayGroup').removeClass('hidden');
                    $('#editBiWeeklyStartDayGroup').addClass('hidden');
                } else {
                    $('#editWeeklyStartDayGroup').addClass('hidden');
                    $('#editBiWeeklyStartDayGroup').removeClass('hidden');
                }
            });
            
            // Ensure date pickers always use yyyy-mm-dd format
            $('#biWeeklyStartDay, #editBiWeeklyStartDay').on('change', function() {
                const selectedDate = $(this).val();
                console.log('Date picker changed to:', selectedDate);
                
                // Force the date format to be preserved exactly as entered
                if (selectedDate) {
                    $(this).attr('data-raw-date', selectedDate);
                }
            });
        });
        
        function editUser(userId) {
            // Clear previous messages
            $('#editEmployeeMessage').text('').removeClass('error success');
            
            // Fetch user data
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'get_user',
                    user_id: userId
                }),
                success: function(response) {
                    if (response.user) {
                        const user = response.user;
                        
                        // Populate form fields
                        $('#editUserId').val(user.id);
                        $('#editName').val(user.name);
                        $('#editUsername').val(user.username);
                        $('#editPassword').val(''); // Clear password field
                        $('#editHourlyWage').val(user.hourly_wage);
                        $('#editPayPeriodType').val(user.pay_period_type);
                        
                        // Set the appropriate pay period start day
                        if (user.pay_period_type === 'weekly') {
                            $('#editWeeklyStartDay').val(user.pay_period_start_day);
                            $('#editWeeklyStartDayGroup').removeClass('hidden');
                            $('#editBiWeeklyStartDayGroup').addClass('hidden');
                        } else {
                            // For bi-weekly, create a date object using the current month/year and the stored day
                            console.log('Setting up bi-weekly date with start day:', user.pay_period_start_day);
                            
                            // Make sure we have a valid day (1-31)
                            let day = parseInt(user.pay_period_start_day);
                            if (isNaN(day) || day < 1 || day > 31) {
                                console.warn('Invalid pay period start day:', user.pay_period_start_day, 'defaulting to 1');
                                day = 1;
                            }
                            
                            // Use a future year to avoid any date boundary issues
                            const futureYear = 2025; // Use a consistent future year for easier debugging
                            
                            // Determine month (use March which has 31 days to handle all possible days)
                            const month = 2; // March (0-based)
                            
                            // Create date with the consistent year/month + stored day
                            const biWeeklyDate = new Date(futureYear, month, day);
                            
                            // Format as YYYY-MM-DD (ensuring we use the actual date)
                            const formattedYear = biWeeklyDate.getFullYear();
                            const formattedMonth = String(biWeeklyDate.getMonth() + 1).padStart(2, '0');
                            
                            // Use the original day value directly in the formatted string
                            // This prevents any date shifting from month boundary issues
                            const formattedDay = String(day).padStart(2, '0');
                            
                            // Build the date string manually to ensure the day isn't shifted
                            const formattedDate = `${formattedYear}-${formattedMonth}-${formattedDay}`;
                            
                            console.log('Setting bi-weekly date input to:', formattedDate, 'original day:', day);
                            $('#editBiWeeklyStartDay').val(formattedDate);
                            $('#editBiWeeklyStartDay').attr('data-raw-date', formattedDate);
                            $('#editWeeklyStartDayGroup').addClass('hidden');
                            $('#editBiWeeklyStartDayGroup').removeClass('hidden');
                        }
                        
                        // Show modal
                        $('#editEmployeeModal').css('display', 'block');
                    } else {
                        alert('Error: ' + (response.error || 'Could not fetch user data'));
                    }
                },
                error: function(xhr, status, error) {
                    alert('Error fetching user data: ' + error);
                }
            });
        }
        
        function updateEmployee() {
            const userId = $('#editUserId').val();
            const name = $('#editName').val();
            const password = $('#editPassword').val();
            const hourlyWage = $('#editHourlyWage').val();
            const payPeriodType = $('#editPayPeriodType').val();
            let payPeriodStartDay;
            
            if (payPeriodType === 'weekly') {
                payPeriodStartDay = parseInt($('#editWeeklyStartDay').val());
                console.log('Using weekly start day:', payPeriodStartDay);
            } else {
                // For bi-weekly, check first if we have the raw date attribute
                let dateString = $('#editBiWeeklyStartDay').attr('data-raw-date');
                
                // If no data attribute, fall back to the input value
                if (!dateString) {
                    dateString = $('#editBiWeeklyStartDay').val();
                }
                
                console.log('Using bi-weekly date string:', dateString);
                
                if (dateString) {
                    // Split the date string into components (YYYY-MM-DD)
                    const dateParts = dateString.split('-');
                    if (dateParts.length === 3) {
                        // Extract the day part directly from the string format
                        payPeriodStartDay = parseInt(dateParts[2], 10);
                        
                        // Log the extraction for debugging
                        console.log('Extracted date parts:', {
                            year: dateParts[0],
                            month: dateParts[1],
                            day: dateParts[2]
                        });
                        console.log('Extracted bi-weekly start day:', payPeriodStartDay);
                    } else {
                        // Fallback if the date format is unexpected
                        console.warn('Date string format unexpected:', dateString);
                        payPeriodStartDay = 1;
                    }
                } else {
                    // Default to 1st if no date is selected
                    payPeriodStartDay = 1;
                    console.log('No date selected, using default start day:', payPeriodStartDay);
                }
            }
            
            if (!name) {
                $('#editEmployeeMessage').removeClass('success').addClass('error').text('Name is required');
                return;
            }
            
            console.log('Updating employee with payPeriodStartDay:', payPeriodStartDay);
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'update_user',
                    user_id: userId,
                    name: name,
                    password: password, // Will be ignored if empty
                    hourly_wage: hourlyWage,
                    pay_period_type: payPeriodType,
                    pay_period_start_day: payPeriodStartDay
                }),
                success: function(response) {
                    if (response.success) {
                        $('#editEmployeeMessage').removeClass('error').addClass('success').text(response.message);
                        
                        // Reload users list after a delay
                        setTimeout(function() {
                            $('#editEmployeeModal').css('display', 'none');
                            loadUsers();
                        }, 1500);
                    } else {
                        $('#editEmployeeMessage').removeClass('success').addClass('error').text(response.error);
                    }
                },
                error: function(xhr, status, error) {
                    $('#editEmployeeMessage').removeClass('success').addClass('error').text('Error updating employee: ' + error);
                }
            });
        }

        // Store the current employee pay period settings and current period offset
        let currentEmployee = {
            id: null,
            payPeriodType: null,
            payPeriodStartDay: null,
            hourlyWage: 0,
            currentPeriodOffset: 0  // 0 = current period, -1 = previous period, 1 = next period
        };
        
        // Fetch employee pay period settings
        function fetchEmployeePayPeriodSettings(employeeId) {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'get_user',
                    user_id: employeeId
                }),
                success: function(response) {
                    if (response.user) {
                        const user = response.user;
                        
                        // Store employee settings
                        currentEmployee = {
                            id: user.id,
                            payPeriodType: user.pay_period_type,
                            payPeriodStartDay: parseInt(user.pay_period_start_day),
                            hourlyWage: parseFloat(user.hourly_wage) || 0,
                            currentPeriodOffset: 0
                        };
                        
                        // Set hourly rate in payment summary
                        $('#hourlyRate').text(currentEmployee.hourlyWage.toFixed(2));
                        
                        // Show pay period navigation
                        $('#payPeriodNav').removeClass('hidden');
                        
                        // Show payment summary
                        $('#paymentSummary').removeClass('hidden');
                        
                        // Load current pay period
                        navigatePayPeriod('current');
                    } else {
                        alert('Error: ' + (response.error || 'Could not fetch user data'));
                    }
                },
                error: function(xhr, status, error) {
                    alert('Error fetching user data: ' + error);
                }
            });
        }
        
        // Navigate pay periods
        function navigatePayPeriod(direction) {
            // Get the current employee and update pay period
            const employeeId = $('#employeeFilter').val();
            if (!employeeId) {
                alert('Please select an employee first');
                return;
            }
            
            // Get the current employee's pay period settings
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'get_user',
                    user_id: employeeId
                }),
                success: function(response) {
                    if (response.user) {
                        // Update currentEmployee object with user data
                        currentEmployee = {
                            id: response.user.id,
                            payPeriodType: response.user.pay_period_type,
                            payPeriodStartDay: parseInt(response.user.pay_period_start_day),
                            hourlyWage: parseFloat(response.user.hourly_wage) || 0,
                            currentPeriodOffset: currentPeriodOffset
                        };
                        
                        // Update the current period offset based on direction
                        if (direction === 'prev') {
                            currentPeriodOffset -= 1;
                        } else if (direction === 'next') {
                            currentPeriodOffset += 1;
                        } else if (direction === 'current') {
                            currentPeriodOffset = 0;
                        }
                        
                        // Store updated offset in currentEmployee
                        currentEmployee.currentPeriodOffset = currentPeriodOffset;
                        
                        // Calculate the dates for the selected pay period
                        const dates = calculatePayPeriodDates(
                            currentEmployee.payPeriodType, 
                            currentEmployee.payPeriodStartDay, 
                            currentEmployee.currentPeriodOffset
                        );
                        
                        // Format the dates for display
                        const formatDisplayDate = (dateStr) => {
                            const parts = dateStr.split('-');
                            const year = parts[0];
                            const month = parseInt(parts[1]) - 1; // JavaScript months are 0-based
                            const day = parseInt(parts[2]);
                            
                            const date = new Date(year, month, day);
                            return date.toLocaleDateString('en-US', {
                                month: 'short',
                                day: 'numeric',
                                year: 'numeric'
                            });
                        };
                        
                        // Update the UI to show the current pay period
                        const periodLabel = (currentPeriodOffset === 0) ? ' (Current)' : '';
                        $('#currentPeriodInfo').text(`Pay Period: ${formatDisplayDate(dates.start)} - ${formatDisplayDate(dates.end)}${periodLabel}`);
                        
                        // Set the date inputs to match the pay period
                        $('#startDate').val(dates.start);
                        $('#endDate').val(dates.end);
                        
                        // Show the payment summary section
                        $('#paymentSummary').show();
                        
                        // Filter time entries for this pay period
                        filterTimeEntries();
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Error fetching user data:', error);
                    alert('Error fetching user data. Please try again.');
                }
            });
        }
        
        // Calculate pay period date range
        function calculatePayPeriodDates(payPeriodType, startDay, offset = 0) {
            console.log('calculatePayPeriodDates called with:', { payPeriodType, startDay, offset });
            
            try {
                const today = new Date();
                let startDate, endDate;
                
                // Sanitize inputs
                payPeriodType = (payPeriodType === 'bi-weekly') ? 'bi-weekly' : 'weekly';
                
                // Ensure offset is a valid number
                offset = parseInt(offset) || 0;
                
                if (payPeriodType === 'weekly') {
                    // Weekly pay period (startDay is 0-6, where 0 is Sunday, 5 is Friday)
                    startDay = parseInt(startDay); // Ensure startDay is an integer
                    
                    // Validate that startDay is a valid day of week (0-6)
                    if (isNaN(startDay) || startDay < 0 || startDay > 6) {
                        console.warn('Invalid weekly startDay:', startDay, 'defaulting to 0 (Sunday)');
                        startDay = 0; // Default to Sunday
                    }
                    
                    const currentDayOfWeek = today.getDay(); // 0-6
                    
                    // First, find the most recent start day
                    let mostRecentStartDate = new Date(today);
                    
                    if (currentDayOfWeek >= startDay) {
                        // Start day occurred during this week, go back (currentDayOfWeek - startDay) days
                        mostRecentStartDate.setDate(today.getDate() - (currentDayOfWeek - startDay));
                    } else {
                        // Start day was in the previous week, go back (currentDayOfWeek + 7 - startDay) days
                        mostRecentStartDate.setDate(today.getDate() - (currentDayOfWeek + 7 - startDay));
                    }
                    
                    // Apply the offset in weeks
                    startDate = new Date(mostRecentStartDate);
                    startDate.setDate(mostRecentStartDate.getDate() + (offset * 7));
                    
                    // Set end date (6 days after start)
                    endDate = new Date(startDate);
                    endDate.setDate(startDate.getDate() + 6);
                } else {
                    // Bi-weekly pay period (startDay is day of month 1-31)
                    startDay = parseInt(startDay); // Ensure startDay is an integer
                    
                    // Validate that startDay is a valid day of month (1-31)
                    if (isNaN(startDay) || startDay < 1 || startDay > 31) {
                        console.warn('Invalid bi-weekly startDay:', startDay, 'defaulting to 1');
                        startDay = 1; // Default to 1st of month
                    }
                    
                    // Simplified bi-weekly calculation - start with a standard month
                    // Find either this month's or last month's period start date based on today
                    const currentYear = today.getFullYear();
                    const currentMonth = today.getMonth();
                    const currentDay = today.getDate();
                    
                    // Determine the base month/year to use for calculating the start date
                    let baseMonth = currentMonth;
                    let baseYear = currentYear;
                    
                    // If today is before startDay, use the previous month's period
                    if (currentDay < startDay) {
                        baseMonth = currentMonth === 0 ? 11 : currentMonth - 1;
                        baseYear = currentMonth === 0 ? currentYear - 1 : currentYear;
                    }
                    
                    // Create the period start date
                    let periodStart = new Date(baseYear, baseMonth, startDay);
                    
                    // Check if we need to adjust for month end (e.g., Feb 30 doesn't exist)
                    if (periodStart.getDate() !== startDay) {
                        // Find the next valid period start
                        // For simplicity, we'll use the 1st of the next month
                        baseMonth = baseMonth === 11 ? 0 : baseMonth + 1;
                        baseYear = baseMonth === 0 ? baseYear + 1 : baseYear;
                        periodStart = new Date(baseYear, baseMonth, 1);
                    }
                    
                    // If the current date is more than 14 days past the period start,
                    // move to the next period
                    const daysSincePeriodStart = Math.floor((today - periodStart) / (1000 * 60 * 60 * 24));
                    if (daysSincePeriodStart >= 14) {
                        baseMonth = baseMonth === 11 ? 0 : baseMonth + 1;
                        baseYear = baseMonth === 0 ? baseYear + 1 : baseYear;
                        periodStart = new Date(baseYear, baseMonth, startDay);
                        
                        // Check month end again
                        if (periodStart.getDate() !== startDay) {
                            baseMonth = baseMonth === 11 ? 0 : baseMonth + 1;
                            baseYear = baseMonth === 0 ? baseYear + 1 : baseYear;
                            periodStart = new Date(baseYear, baseMonth, 1);
                        }
                    }
                    
                    // Now we have the current period start. Apply offset in periods.
                    startDate = new Date(periodStart);
                    
                    // Handle bi-weekly offset (positive or negative number of periods)
                    if (offset !== 0) {
                        // Each bi-weekly period is 14 days
                        const offsetDays = offset * 14;
                        startDate.setDate(startDate.getDate() + offsetDays);
                    }
                    
                    // Ensure end date is exactly 13 days after start (14-day period)
                    endDate = new Date(startDate);
                    endDate.setDate(startDate.getDate() + 13);
                }
                
                // Format dates as YYYY-MM-DD for input fields
                const formatDate = (date) => {
                    const year = date.getFullYear();
                    const month = String(date.getMonth() + 1).padStart(2, '0');
                    const day = String(date.getDate()).padStart(2, '0');
                    return `${year}-${month}-${day}`;
                };
                
                const result = {
                    start: formatDate(startDate),
                    end: formatDate(endDate)
                };
                
                console.log('Calculated date range:', result);
                return result;
            } catch (error) {
                console.error('Error calculating pay period dates:', error);
                
                // Fallback to a simple 7-day range from today
                const today = new Date();
                const startDate = new Date(today);
                const endDate = new Date(today);
                endDate.setDate(today.getDate() + 6);
                
                // Format dates as YYYY-MM-DD
                const formatDate = (date) => {
                    const year = date.getFullYear();
                    const month = String(date.getMonth() + 1).padStart(2, '0');
                    const day = String(date.getDate()).padStart(2, '0');
                    return `${year}-${month}-${day}`;
                };
                
                const result = {
                    start: formatDate(startDate),
                    end: formatDate(endDate)
                };
                
                console.log('Using fallback date range due to error:', result);
                return result;
            }
        }

        // New function to calculate total hours and payment
        function calculatePaymentSummary(entries) {
            // Ensure we have the current employee's hourly wage
            const employeeId = $('#employeeFilter').val();
            
            // Get total hours worked and paid hours
            let totalHours = 0;
            let paidHours = 0;
            
            entries.forEach(entry => {
                if (entry.hours_worked) {
                    const hours = parseFloat(entry.hours_worked);
                    totalHours += hours;
                    
                    // Only include in paid hours if non_payable is not set to 1
                    if (entry.non_payable != 1) {
                        paidHours += hours;
                    }
                }
            });
            
            // Get employee's hourly wage
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'get_user',
                    user_id: employeeId
                }),
                success: function(response) {
                    if (response.user) {
                        const hourlyWage = parseFloat(response.user.hourly_wage) || 0;
                        const amountDue = paidHours * hourlyWage;
                        
                        // Update the payment summary display
                        $('#totalHours').text(totalHours.toFixed(2));
                        $('#hourlyRate').text('$' + hourlyWage.toFixed(2));
                        $('#amountDue').text('$' + amountDue.toFixed(2));
                        
                        // Make sure the payment summary is visible
                        $('#paymentSummary').show();
                    }
                }
            });
        }

        // Store currentPeriodOffset for pay period navigation
        let currentPeriodOffset = 0; // 0 = current period, -1 = previous period, 1 = next period

        // Function to add a manual time entry
        function addManualTimeEntry() {
            const employeeId = $('#employeeFilter').val();
            if (!employeeId) {
                $('#addTimeEntryMessage').removeClass('success').addClass('error').text('Please select an employee first');
                return;
            }
            
            const entryDate = $('#manualEntryDate').val();
            const entryType = $('#manualEntryType').val();
            const entryMethod = $('input[name="entryMethod"]:checked').val();
            const isPaid = $('#entryPayStatus').val() === 'yes';
            const nonPayable = !isPaid; // Convert yes/no to the nonPayable flag (inverse of isPaid)
            
            if (!entryDate) {
                $('#addTimeEntryMessage').removeClass('success').addClass('error').text('Please select a date');
                return;
            }
            
            let clockIn, clockOut, hoursWorked;
            
            // Handle different entry methods
            if (entryMethod === 'timeRange') {
                // Time range method
                const startTime = $('#manualEntryStartTime').val();
                const endTime = $('#manualEntryEndTime').val();
                
                if (!startTime || !endTime) {
                    $('#addTimeEntryMessage').removeClass('success').addClass('error').text('Please fill in both start and end times');
                    return;
                }
                
                // Create clock-in and clock-out datetime strings
                clockIn = `${entryDate} ${startTime}:00`;
                clockOut = `${entryDate} ${endTime}:00`;
                
                // Validate that end time is after start time
                const startDateTime = new Date(clockIn);
                const endDateTime = new Date(clockOut);
                
                if (endDateTime <= startDateTime) {
                    $('#addTimeEntryMessage').removeClass('success').addClass('error').text('End time must be after start time');
                    return;
                }
                
                // Calculate hours worked
                hoursWorked = (endDateTime - startDateTime) / (1000 * 60 * 60);
            } else {
                // Total hours method
                const totalHours = parseFloat($('#manualEntryTotalHours').val());
                
                if (isNaN(totalHours) || totalHours <= 0) {
                    $('#addTimeEntryMessage').removeClass('success').addClass('error').text('Please enter a valid number of hours');
                    return;
                }
                
                if (totalHours > 24) {
                    $('#addTimeEntryMessage').removeClass('success').addClass('error').text('Hours cannot exceed 24 for a single day');
                    return;
                }
                
                // Set a default start time (8 AM)
                const defaultStartTime = '08:00:00';
                clockIn = `${entryDate} ${defaultStartTime}`;
                
                // Calculate end time based on total hours
                const startDateTime = new Date(clockIn);
                const endDateTime = new Date(startDateTime.getTime() + (totalHours * 60 * 60 * 1000));
                
                // Format end time
                const endHours = endDateTime.getHours().toString().padStart(2, '0');
                const endMinutes = endDateTime.getMinutes().toString().padStart(2, '0');
                const endSeconds = endDateTime.getSeconds().toString().padStart(2, '0');
                clockOut = `${entryDate} ${endHours}:${endMinutes}:${endSeconds}`;
                
                // Use the provided total hours directly
                hoursWorked = totalHours;
            }
            
            // Send the manual entry to the server
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'add_manual_time_entry',
                    employee_id: employeeId,
                    clock_in: clockIn,
                    clock_out: clockOut,
                    hours_worked: hoursWorked,
                    entry_type: entryType,
                    non_payable: nonPayable
                }),
                success: function(response) {
                    if (response.success) {
                        // Show success message
                        $('#addTimeEntryMessage').removeClass('error').addClass('success').text('Time entry added successfully');
                        
                        // Reload the time entries after a short delay
                        setTimeout(function() {
                            // Close the modal
                            $('#timeEntryModal').css('display', 'none');
                            
                            // Reload time entries
                            filterTimeEntries();
                        }, 1500);
                    } else {
                        $('#addTimeEntryMessage').removeClass('success').addClass('error')
                            .text('Error adding time entry: ' + (response.error || 'Unknown error'));
                    }
                },
                error: function(xhr, status, error) {
                    $('#addTimeEntryMessage').removeClass('success').addClass('error')
                        .text('Error adding time entry: ' + error);
                }
            });
        }

        // Set up time entry modal handlers
        $(document).ready(function() {
            // Open modal when the Add Time Entry button is clicked
            $('#addTimeEntryBtn').click(function() {
                // Set today's date as default
                const today = new Date().toISOString().split('T')[0];
                $('#manualEntryDate').val(today);
                
                // Clear other fields
                $('#manualEntryType').val('regular');
                $('#manualEntryStartTime').val('');
                $('#manualEntryEndTime').val('');
                $('#manualEntryTotalHours').val('');
                $('#entryPayStatus').val('yes'); // Default to paid
                $('#addTimeEntryMessage').removeClass('success error').text('');
                
                // Reset to time range input by default
                $('input[name="entryMethod"][value="timeRange"]').prop('checked', true);
                $('#timeRangeInputs').show();
                $('#totalHoursInput').hide();
                
                // Show the modal
                $('#timeEntryModal').css('display', 'block');
            });
            
            // Toggle between time range and total hours inputs
            $('input[name="entryMethod"]').change(function() {
                if ($(this).val() === 'timeRange') {
                    $('#timeRangeInputs').show();
                    $('#totalHoursInput').hide();
                } else {
                    $('#timeRangeInputs').hide();
                    $('#totalHoursInput').show();
                }
            });
            
            // Close modal when the X is clicked
            $('.close-modal').click(function() {
                $(this).closest('.modal').css('display', 'none');
            });
            
            // Close modal when clicking outside the content
            $(window).click(function(event) {
                if ($(event.target).hasClass('modal')) {
                    $('.modal').css('display', 'none');
                }
            });
        });

        // Update admin settings
        function updateAdminSettings() {
            const adminEmail = $('#adminEmail').val();
            const adminCurrentPassword = $('#adminCurrentPassword').val();
            const adminNewPassword = $('#adminNewPassword').val();
            const adminConfirmPassword = $('#adminConfirmPassword').val();

            // Validate form inputs
            if (!adminEmail) {
                $('#adminSettingsMessage').removeClass('success').addClass('error').text('Admin email is required');
                return;
            }

            if (!adminCurrentPassword && !adminNewPassword) {
                $('#adminSettingsMessage').removeClass('success').addClass('error').text('Please provide either the current password or a new password');
                return;
            }

            if (adminNewPassword && adminNewPassword !== adminConfirmPassword) {
                $('#adminSettingsMessage').removeClass('success').addClass('error').text('New password and confirm password do not match');
                return;
            }

            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                data: JSON.stringify({
                    action: 'update_admin_settings',
                    admin_email: adminEmail,
                    admin_current_password: adminCurrentPassword,
                    admin_new_password: adminNewPassword
                }),
                success: function(response) {
                    if (response.success) {
                        $('#adminSettingsMessage').removeClass('error').addClass('success').text(response.message);
                        // Optionally, you might want to refresh the admin panel or clear form fields
                        $('#adminEmail').val('');
                        $('#adminCurrentPassword').val('');
                        $('#adminNewPassword').val('');
                        $('#adminConfirmPassword').val('');
                    } else {
                        $('#adminSettingsMessage').removeClass('success').addClass('error').text(response.error || 'Error updating admin settings');
                    }
                },
                error: function(xhr, status, error) {
                    $('#adminSettingsMessage').removeClass('success').addClass('error').text('Error updating admin settings: ' + error);
                }
            });
        }

        // Add event listener for save button
        $('#saveAdminSettingsBtn').click(function(e) {
            e.preventDefault();
            updateAdminSettings();
        });

        // Function to load company info for the employee view
        function loadCompanyInfo() {
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({ action: 'get_company_settings' }),
                success: function(response) {
                    if (response && response.success && response.settings) {
                        // Display company name
                        if (response.settings.company_name) {
                            $('#companyNameDisplay').text(response.settings.company_name);
                        }
                        
                        // Display support email with label
                        if (response.settings.company_email) {
                            $('#supportEmailDisplay').text('Support: ' + response.settings.company_email);
                        } else {
                            $('#supportEmailDisplay').hide();
                        }
                        
                        // Show the company info section
                        $('#companyInfo').show();
                    } else {
                        // Hide the company info section if no data
                        $('#companyInfo').hide();
                    }
                },
                error: function() {
                    // Hide the company info section on error
                    $('#companyInfo').hide();
                }
            });
        }
    </script>
</body>
</html>
