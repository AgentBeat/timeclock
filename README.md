# Simple TimeClock System

A lightweight employee time tracking system built with PHP, SQLite, and jQuery.

## Features

- Employee clock in/out functionality
- Admin panel for managing time entries
- Secure login system
- Time entry management
- Hours calculation
- SQLite database (no complex database setup required)

## Requirements

- PHP 7.4+ with PDO SQLite extension
- Apache web server with mod_rewrite enabled
- Write permissions for the web server user in the application directory

## Installation

1. Upload all files to your web server
2. Ensure the directory has proper write permissions for the SQLite database
3. Access the application through your web browser


## Security Notes

1. The SQLite database file is protected from direct web access
2. All passwords are securely hashed
3. Session security measures are in place
4. XSS and CSRF protections are implemented

## Directory Structure

```
/
├── index.php         # Main application file
├── .htaccess        # Apache configuration and security
├── timeclock.sqlite # Database file (created automatically)
└── README.md        # This file
```

## Adding New Users

Currently, new users can only be added directly in the database. Use SQLite command line tool or a SQLite database manager to add new users:

```sql
INSERT INTO users (username, password, is_admin) 
VALUES ('employee1', 'HASHED_PASSWORD', 0);
```

To generate a hashed password, you can use PHP's password_hash() function.

## Deployment Notes

1. Ensure your web server has the required PHP extensions:
   - PDO
   - PDO_SQLite
   - JSON

2. Set proper file permissions:
   ```bash
   chmod 644 index.php
   chmod 644 .htaccess
   chmod 644 README.md
   chmod 777 /path/to/directory  # For SQLite database creation
   ```

3. After database creation, you can restrict directory permissions:
   ```bash
   chmod 755 /path/to/directory
   chmod 640 timeclock.sqlite
   ```

## Customization

The system is intentionally minimal. You can customize it by:
1. Adding CSS to style the interface
2. Extending the admin panel functionality
3. Adding more features to the time entry system
4. Implementing user management in the admin panel

## Support

This is a minimal implementation. For production use, consider adding:
1. Backup system for the SQLite database
2. User management interface
3. More detailed reporting features
4. Additional security measures 
