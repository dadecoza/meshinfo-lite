# MeshInfo-Lite Setup Guide

This guide will help you set up MeshInfo-Lite with proper database privileges for optimal performance.

## Setup Options

- **[Docker Compose Setup](SETUP_DOCKER.md)** - Recommended for most users
- **Manual Setup** - For traditional installations (see below)

## Prerequisites

- Python 3.7 or higher
- MariaDB/MySQL server
- Root access to the database server

## Quick Setup

### 1. Configure Database Settings

Edit your `config.ini` file and add the database section:

```ini
[database]
host = localhost
username = meshdata
password = your_secure_password
database = meshdata
root_password = your_root_password
```

### 2. Run Database Setup

Execute the database setup script:

```bash
python setup_database.py
```

This script will:
- ✅ Create the database with proper character encoding
- ✅ Create the application user
- ✅ Grant all necessary privileges
- ✅ Test the connection and privileges
- ✅ Provide detailed feedback

### 3. Start the Application

Once setup is complete, start the application:

```bash
python main.py
```

## Manual Setup (Alternative)

If you prefer to set up the database manually:

### 1. Connect to MariaDB as Root

```bash
mysql -u root -p
```

### 2. Create Database and User

```sql
-- Create database
CREATE DATABASE meshdata CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER 'meshdata'@'%' IDENTIFIED BY 'your_secure_password';

-- Grant privileges
GRANT ALL PRIVILEGES ON meshdata.* TO 'meshdata'@'%';
GRANT RELOAD ON *.* TO 'meshdata'@'%';
GRANT PROCESS ON *.* TO 'meshdata'@'%';

-- Apply changes
FLUSH PRIVILEGES;
```

## Privileges Explained

### Required Privileges

- **ALL PRIVILEGES ON meshdata.\*** - Full access to the application database
- **RELOAD ON \*.\*** - Required for query cache operations
- **PROCESS ON \*.\*** - Required for monitoring and debugging

### Why These Privileges?

- **RELOAD**: Allows the application to clear the MariaDB query cache for optimal performance
- **PROCESS**: Enables monitoring of database connections and processes
- **ALL PRIVILEGES**: Standard database operations (SELECT, INSERT, UPDATE, DELETE, etc.)

## Verification

After setup, you can verify everything is working:

### 1. Test Database Connection

```bash
mysql -u meshdata -p meshdata
```

### 2. Test Privileges

```sql
-- Test RELOAD privilege
FLUSH QUERY CACHE;

-- Test PROCESS privilege
SHOW PROCESSLIST;
```

### 3. Check Application

Visit the debug endpoint to verify privileges:
```
http://your-server:port/api/debug/database-cache
```

## Troubleshooting

### Common Issues

1. **"Access denied for user"**
   - Check username and password in config.ini
   - Verify user exists and has correct privileges

2. **"Access denied; you need RELOAD privilege"**
   - Run the setup script again
   - Or manually grant RELOAD privilege

3. **"Cannot connect to database"**
   - Check if MariaDB/MySQL is running
   - Verify host and port settings
   - Check firewall settings

### Getting Help

- Check the logs for detailed error messages
- Use the debug endpoints to diagnose issues
- Review the CACHING.md document for advanced configuration

## Security Notes

- Use strong passwords for both root and application users
- Consider using a dedicated database user for the application
- Restrict network access to the database server when possible
- Regularly update MariaDB/MySQL for security patches 