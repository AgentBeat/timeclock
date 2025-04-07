<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    // If admin, redirect to admin page
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
        header('Location: index.php');
        exit;
    }
    // If employee, show the timeclock panel
    include('index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Employee TimeClock Login</title>
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
        
        /* Login Form */
        #employeeLoginForm {
            max-width: 400px;
            margin: 80px auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
        }
        
        #employeeLoginForm h2 {
            text-align: center;
            margin-bottom: 25px;
            color: #2c3e50;
        }
        
        #employeeLoginForm input {
            width: 100%;
            padding: 12px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border 0.3s ease;
        }
        
        #employeeLoginForm input:focus {
            border-color: #3498db;
            outline: none;
            box-shadow: 0 0 0 2px rgba(52, 152, 219, 0.2);
        }
        
        #employeeLoginForm button {
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
        
        #employeeLoginForm button:hover {
            background-color: #2980b9;
        }
        
        .admin-link {
            text-align: center;
            margin-top: 20px;
            font-size: 14px;
        }
        
        .admin-link a {
            color: #7f8c8d;
            text-decoration: none;
        }
        
        .admin-link a:hover {
            text-decoration: underline;
            color: #34495e;
        }
        
        .company-field {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db !important;
            font-weight: 500;
            margin-bottom: 30px !important;
        }
        
        .company-field:focus {
            background-color: #fff;
        }
        
        .field-help {
            color: #7f8c8d;
            font-size: 13px;
            margin-top: -18px;
            margin-bottom: 18px;
            text-align: left;
            padding-left: 2px;
        }
    </style>
</head>
<body>
    <div id="employeeLoginForm">
        <h2>Employee Clock In</h2>
        <input type="text" id="companyName" placeholder="Company Name or Short Name" class="company-field">
        <div class="field-help">Enter your company name or the short name provided by your administrator</div>
        <input type="text" id="username" placeholder="Username">
        <input type="password" id="password" placeholder="Password">
        <button onclick="employeeLogin()">Login</button>
    </div>

    <script>
        // On page load, check for saved company name
        $(document).ready(function() {
            const savedCompany = localStorage.getItem('lastCompany');
            if (savedCompany) {
                $('#companyName').val(savedCompany);
            }
        });
        
        function employeeLogin() {
            const companyName = $('#companyName').val();
            const username = $('#username').val();
            const password = $('#password').val();
            
            if (!companyName) {
                alert('Please enter your company name');
                return;
            }
            
            if (!username || !password) {
                alert('Please enter both username and password');
                return;
            }
            
            // Save company name to localStorage
            localStorage.setItem('lastCompany', companyName);
            
            $.ajax({
                url: 'index.php',
                method: 'POST',
                contentType: 'application/json',
                dataType: 'json',
                data: JSON.stringify({
                    action: 'login',
                    company_name: companyName,
                    username: username,
                    password: password,
                    employee_only: true
                }),
                success: function(response) {
                    if (response && response.success) {
                        if (response.is_admin) {
                            // Redirect admins to the admin login
                            window.location.href = 'index.php';
                        } else {
                            // Load the employee timeclock interface
                            window.location.href = 'index.php';
                        }
                    } else {
                        alert('Login failed: ' + (response ? response.error : 'Unknown error'));
                    }
                },
                error: function(xhr, status, error) {
                    try {
                        const response = xhr.responseJSON || JSON.parse(xhr.responseText);
                        alert('Error during login: ' + (response.error || error));
                    } catch (e) {
                        alert('Error during login: ' + error);
                    }
                }
            });
        }
    </script>
</body>
</html> 