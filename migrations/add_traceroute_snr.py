import logging

def clear_unread_results(cursor):
    """Clear any unread results from the cursor"""
    try:
        while cursor.nextset():
            pass
    except:
        pass

def migrate(db):
    """
    Update traceroute table to store separate SNR values for forward and return paths
    """
    cursor = None
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        
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
                    traceroute_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    from_id INT UNSIGNED NOT NULL,
                    to_id INT UNSIGNED NOT NULL,
                    route TEXT,
                    route_back TEXT,
                    snr_towards TEXT COMMENT 'Semicolon-separated SNR values for forward path',
                    snr_back TEXT COMMENT 'Semicolon-separated SNR values for return path',
                    success BOOLEAN DEFAULT FALSE,
                    channel TINYINT UNSIGNED,
                    hop_limit TINYINT UNSIGNED,
                    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_traceroute_nodes (from_id, to_id),
                    INDEX idx_traceroute_time (ts_created)
                )
            """)
            db.commit()
            logging.info("Created traceroute table successfully")
            return

        # Check if old SNR column exists
        cursor.execute("""
            SELECT COLUMN_TYPE 
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'traceroute'
            AND COLUMN_NAME = 'snr'
        """)
        result = cursor.fetchone()
        
        if result:
            # Old SNR column exists, need to migrate to new format
            logging.info("Migrating from single SNR column to separate forward/return SNR columns...")
            
            # Add new columns if they don't exist
            cursor.execute("""
                ALTER TABLE traceroute
                ADD COLUMN IF NOT EXISTS snr_towards TEXT COMMENT 'Semicolon-separated SNR values for forward path',
                ADD COLUMN IF NOT EXISTS snr_back TEXT COMMENT 'Semicolon-separated SNR values for return path'
            """)
            
            # Copy existing SNR data to snr_towards (since historically it was forward path only)
            cursor.execute("""
                UPDATE traceroute 
                SET snr_towards = snr
                WHERE snr IS NOT NULL
            """)
            
            # Drop old column
            cursor.execute("""
                ALTER TABLE traceroute
                DROP COLUMN snr
            """)
            
            db.commit()
            logging.info("Migrated SNR columns successfully")

        # Add other necessary columns if they don't exist
        cursor.execute("""
            ALTER TABLE traceroute
            ADD COLUMN IF NOT EXISTS traceroute_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST,
            ADD COLUMN IF NOT EXISTS route_back TEXT AFTER route,
            ADD COLUMN IF NOT EXISTS success BOOLEAN DEFAULT FALSE AFTER snr_back,
            ADD COLUMN IF NOT EXISTS channel TINYINT UNSIGNED AFTER success,
            ADD COLUMN IF NOT EXISTS hop_limit TINYINT UNSIGNED AFTER channel
        """)

        # Add indices if they don't exist
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.STATISTICS
            WHERE TABLE_NAME = 'traceroute'
            AND INDEX_NAME = 'idx_traceroute_nodes'
        """)
        has_node_index = cursor.fetchone()[0] > 0
        
        if not has_node_index:
            logging.info("Adding index on from_id, to_id...")
            cursor.execute("""
                ALTER TABLE traceroute
                ADD INDEX idx_traceroute_nodes (from_id, to_id)
            """)

        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.STATISTICS
            WHERE TABLE_NAME = 'traceroute'
            AND INDEX_NAME = 'idx_traceroute_time'
        """)
        has_time_index = cursor.fetchone()[0] > 0
        
        if not has_time_index:
            logging.info("Adding index on ts_created...")
            cursor.execute("""
                ALTER TABLE traceroute
                ADD INDEX idx_traceroute_time (ts_created)
            """)

        db.commit()
        logging.info("Migration completed successfully")

    except Exception as e:
        logging.error(f"Error performing traceroute SNR migration: {e}")
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass