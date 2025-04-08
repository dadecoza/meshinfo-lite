import logging

def migrate(db):
    """
    Improve SNR storage in traceroute table
    """
    try:
        cursor = db.cursor()
        
        # First check if the table exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.TABLES 
            WHERE TABLE_NAME = 'traceroute'
        """)
        table_exists = cursor.fetchone()[0] > 0

        if not table_exists:
            logging.info("Creating traceroute table...")
            cursor.execute("""
                CREATE TABLE traceroute (
                    from_id INT UNSIGNED NOT NULL,
                    to_id INT UNSIGNED NOT NULL,
                    route VARCHAR(255),
                    snr TEXT COMMENT 'Semicolon-separated SNR values, stored as integers (actual_value * 4)',
                    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_traceroute_nodes (from_id, to_id)
                )
            """)
            db.commit()
            logging.info("Created traceroute table successfully")
            return

        # Check if SNR column exists
        cursor.execute("""
            SELECT COLUMN_TYPE 
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'traceroute'
            AND COLUMN_NAME = 'snr'
        """)
        result = cursor.fetchone()
        
        if not result:
            # SNR column doesn't exist, add it
            logging.info("Adding SNR column to traceroute table...")
            cursor.execute("""
                ALTER TABLE traceroute
                ADD COLUMN snr TEXT COMMENT 'Semicolon-separated SNR values, stored as integers (actual_value * 4)'
            """)
            db.commit()
            logging.info("Added SNR column successfully")
            return
            
        current_type = result[0]
        
        if current_type.upper() == 'VARCHAR(255)':
            logging.info("Converting traceroute SNR column to more efficient format...")
            
            # Create temporary column with same type to preserve data
            cursor.execute("""
                ALTER TABLE traceroute
                ADD COLUMN snr_temp VARCHAR(255)
            """)
            
            # Copy existing data
            cursor.execute("""
                UPDATE traceroute 
                SET snr_temp = snr
                WHERE snr IS NOT NULL
            """)
            
            # Drop old column and create new one with better type
            cursor.execute("""
                ALTER TABLE traceroute
                DROP COLUMN snr,
                ADD COLUMN snr TEXT COMMENT 'Semicolon-separated SNR values, stored as integers (actual_value * 4)'
            """)
            
            # Copy data back
            cursor.execute("""
                UPDATE traceroute 
                SET snr = snr_temp
                WHERE snr_temp IS NOT NULL
            """)
            
            # Drop temporary column
            cursor.execute("""
                ALTER TABLE traceroute
                DROP COLUMN snr_temp
            """)
            
            db.commit()
            logging.info("Converted SNR column successfully")

        # Add index if it doesn't exist
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.STATISTICS
            WHERE TABLE_NAME = 'traceroute'
            AND INDEX_NAME = 'idx_traceroute_nodes'
        """)
        has_index = cursor.fetchone()[0] > 0
        
        if not has_index:
            logging.info("Adding index on from_id, to_id...")
            cursor.execute("""
                ALTER TABLE traceroute
                ADD INDEX idx_traceroute_nodes (from_id, to_id)
            """)
            db.commit()
            logging.info("Added index successfully")

    except Exception as e:
        logging.error(f"Error performing traceroute SNR migration: {e}")
        raise
    finally:
        cursor.close()