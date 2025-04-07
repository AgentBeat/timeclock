<?php
// Database configuration
$db_file = 'timeclock.sqlite';
$dsn = "sqlite:$db_file";

try {
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Get the employee ID
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute(['employee1']);
    $employee = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$employee) {
        die("Employee not found!");
    }
    
    $employee_id = $employee['id'];
    echo "Creating test entries for employee ID: $employee_id<br>";
    
    // Create some sample time entries for the past week
    $entries = [
        // Yesterday - completed shift
        [
            'clock_in' => date('Y-m-d H:i:s', strtotime('yesterday 9:00')),
            'clock_out' => date('Y-m-d H:i:s', strtotime('yesterday 17:00'))
        ],
        // Two days ago - completed shift
        [
            'clock_in' => date('Y-m-d H:i:s', strtotime('-2 days 8:30')),
            'clock_out' => date('Y-m-d H:i:s', strtotime('-2 days 16:45'))
        ],
        // Three days ago - completed shift
        [
            'clock_in' => date('Y-m-d H:i:s', strtotime('-3 days 9:15')),
            'clock_out' => date('Y-m-d H:i:s', strtotime('-3 days 17:30'))
        ],
        // Active shift (not clocked out)
        [
            'clock_in' => date('Y-m-d H:i:s', strtotime('now')),
            'clock_out' => null
        ]
    ];
    
    // Insert the entries
    $stmt = $pdo->prepare("
        INSERT INTO time_entries (user_id, clock_in, clock_out)
        VALUES (?, ?, ?)
    ");
    
    foreach ($entries as $entry) {
        $stmt->execute([$employee_id, $entry['clock_in'], $entry['clock_out']]);
        echo "Created entry: " . $entry['clock_in'] . " to " . ($entry['clock_out'] ?? 'Active') . "<br>";
    }
    
    echo "<br>All entries added successfully!";
    
    // Show all time entries
    echo "<br><br>All time entries in database:<br>";
    $entries = $pdo->query("
        SELECT t.id, u.username, t.clock_in, t.clock_out,
               CASE WHEN t.clock_out IS NOT NULL 
                    THEN round((julianday(t.clock_out) - julianday(t.clock_in)) * 24, 2)
                    ELSE NULL END as hours_worked
        FROM time_entries t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.clock_in DESC
    ")->fetchAll(PDO::FETCH_ASSOC);
    
    foreach ($entries as $entry) {
        echo "ID: " . $entry['id'] . 
             ", User: " . $entry['username'] . 
             ", Clock In: " . $entry['clock_in'] . 
             ", Clock Out: " . ($entry['clock_out'] ?? 'Active') . 
             ", Hours: " . ($entry['hours_worked'] ?? 'N/A') . 
             "<br>";
    }
    
} catch (PDOException $e) {
    echo "Database error: " . $e->getMessage();
}
?> 