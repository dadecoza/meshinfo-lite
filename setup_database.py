#!/usr/bin/env python3
"""
Database Setup Script for MeshInfo-Lite

This script creates the database and user with proper privileges for new installations.
It should be run once during initial setup.

Usage:
    python setup_database.py

Requirements:
    - MariaDB/MySQL server running
    - Root access to the database server
    - config.ini file with database configuration
"""

import configparser
import mysql.connector
import logging
import sys
import os

def setup_logging():
    """Setup basic logging for the setup script."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def check_config():
    """Check if config.ini exists and has required database settings."""
    if not os.path.exists('config.ini'):
        logging.error("config.ini not found! Please create it first.")
        return False
    
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    required_sections = ['database']
    required_keys = ['host', 'username', 'password', 'database']
    
    for section in required_sections:
        if section not in config:
            logging.error(f"Missing [{section}] section in config.ini")
            return False
        
        for key in required_keys:
            if key not in config[section]:
                logging.error(f"Missing {key} in [{section}] section of config.ini")
                return False
    
    return True

def test_root_connection(config):
    """Test connection to database as root."""
    try:
        root_password = config.get("database", "root_password", fallback="passw0rd")
        db = mysql.connector.connect(
            host=config["database"]["host"],
            user="root",
            password=root_password,
        )
        db.close()
        logging.info("Successfully connected to database as root")
        return True
    except mysql.connector.Error as e:
        logging.error(f"Failed to connect as root: {e}")
        logging.error("Please ensure:")
        logging.error("1. MariaDB/MySQL server is running")
        logging.error("2. Root password is correct in config.ini [database] root_password")
        logging.error("3. Root user can connect from this host")
        return False

def create_database_and_user(config):
    """Create database and user with proper privileges."""
    root_password = config.get("database", "root_password", fallback="passw0rd")
    
    try:
        # Connect as root
        db = mysql.connector.connect(
            host=config["database"]["host"],
            user="root",
            password=root_password,
        )
        
        logging.info("Creating database and user...")
        
        # Create database
        cur = db.cursor()
        cur.execute(f"""CREATE DATABASE IF NOT EXISTS {config["database"]["database"]}
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci""")
        cur.close()
        logging.info(f"✓ Database '{config['database']['database']}' created/verified")
        
        # Create user if it doesn't exist
        cur = db.cursor()
        cur.execute(f"""CREATE USER IF NOT EXISTS '{config["database"]["username"]}'@'%'
IDENTIFIED BY '{config["database"]["password"]}'""")
        cur.close()
        logging.info(f"✓ User '{config['database']['username']}' created/verified")
        
        # Grant all privileges on the specific database
        cur = db.cursor()
        cur.execute(f"""GRANT ALL PRIVILEGES ON {config["database"]["database"]}.*
TO '{config["database"]["username"]}'@'%'""")
        cur.close()
        logging.info(f"✓ Granted ALL PRIVILEGES on {config['database']['database']}.*")
        
        # Grant RELOAD privilege for query cache operations
        cur = db.cursor()
        cur.execute(f"""GRANT RELOAD ON *.* TO '{config["database"]["username"]}'@'%'""")
        cur.close()
        logging.info("✓ Granted RELOAD privilege for query cache operations")
        
        # Grant PROCESS privilege for monitoring
        cur = db.cursor()
        cur.execute(f"""GRANT PROCESS ON *.* TO '{config["database"]["username"]}'@'%'""")
        cur.close()
        logging.info("✓ Granted PROCESS privilege for monitoring")
        
        # Flush privileges to apply changes
        cur = db.cursor()
        cur.execute("FLUSH PRIVILEGES")
        cur.close()
        logging.info("✓ Privileges flushed")
        
        db.commit()
        db.close()
        
        logging.info("✓ Database setup completed successfully!")
        return True
        
    except mysql.connector.Error as e:
        logging.error(f"Error creating database: {e}")
        return False

def test_user_connection(config):
    """Test connection with the newly created user."""
    try:
        db = mysql.connector.connect(
            host=config["database"]["host"],
            user=config["database"]["username"],
            password=config["database"]["password"],
            database=config["database"]["database"],
        )
        db.close()
        logging.info("✓ Successfully connected with application user")
        return True
    except mysql.connector.Error as e:
        logging.error(f"Failed to connect with application user: {e}")
        return False

def test_privileges(config):
    """Test if the user has the required privileges."""
    try:
        db = mysql.connector.connect(
            host=config["database"]["host"],
            user=config["database"]["username"],
            password=config["database"]["password"],
            database=config["database"]["database"],
        )
        cur = db.cursor()
        
        # Test RELOAD privilege
        try:
            cur.execute("FLUSH QUERY CACHE")
            logging.info("✓ RELOAD privilege verified")
        except mysql.connector.Error as e:
            logging.warning(f"RELOAD privilege test failed: {e}")
        
        # Test PROCESS privilege
        try:
            cur.execute("SHOW PROCESSLIST")
            logging.info("✓ PROCESS privilege verified")
        except mysql.connector.Error as e:
            logging.warning(f"PROCESS privilege test failed: {e}")
        
        cur.close()
        db.close()
        return True
        
    except mysql.connector.Error as e:
        logging.error(f"Error testing privileges: {e}")
        return False

def main():
    """Main setup function."""
    setup_logging()
    
    logging.info("=== MeshInfo-Lite Database Setup ===")
    
    # Check configuration
    if not check_config():
        sys.exit(1)
    
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    # Test root connection
    if not test_root_connection(config):
        sys.exit(1)
    
    # Create database and user
    if not create_database_and_user(config):
        sys.exit(1)
    
    # Test user connection
    if not test_user_connection(config):
        logging.error("Setup completed but user connection test failed")
        sys.exit(1)
    
    # Test privileges
    test_privileges(config)
    
    logging.info("=== Setup Complete ===")
    logging.info("You can now start the MeshInfo-Lite application")
    logging.info("Run: python main.py")

if __name__ == "__main__":
    main() 