import logging

def clear_unread_results(cursor):
    """Clear any unread results from the cursor"""
    try:
        while cursor.nextset():
            pass
    except:
        pass

def migrate(db):
    cursor = None
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        # Start transaction
        cursor.execute("START TRANSACTION")
        
        # Check existing columns to determine what needs to be added
        needed_columns = {
            'traceroute_id': 'BIGINT AUTO_INCREMENT PRIMARY KEY',
            'request_id': 'BIGINT NULL',
            'channel': 'INT UNSIGNED NULL',
            'hop_limit': 'INT UNSIGNED NULL',
            'success': 'TINYINT(1) NULL',
            'time': 'TIMESTAMP NULL',
            'snr_towards': 'TEXT NULL',
            'snr_back': 'TEXT NULL',
            'route_back': 'VARCHAR(255) NULL'
        }
        
        # Get existing columns
        cursor.execute("""
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_NAME = 'traceroute'
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        logging.info(f"Existing columns in traceroute: {existing_columns}")
        
        # Build ALTER TABLE statement
        alter_statements = []
        
        # Handle special case for SNR rename if needed
        if 'snr' in existing_columns and 'snr_towards' not in existing_columns:
            alter_statements.append("CHANGE COLUMN snr snr_towards TEXT NULL")
            existing_columns.remove('snr')
            existing_columns.append('snr_towards')
        
        # Add missing columns (always add at the end for robustness)
        for col, type_def in needed_columns.items():
            if col not in existing_columns:
                alter_statements.append(f"ADD COLUMN {col} {type_def}")
        
        # Execute ALTER TABLE if there are changes needed
        if alter_statements:
            alter_sql = "ALTER TABLE traceroute " + ", ".join(alter_statements)
            logging.info(f"Executing ALTER TABLE: {alter_sql}")
            cursor.execute(alter_sql)
        else:
            logging.info("No ALTER TABLE needed for traceroute.")
        
        # Commit transaction
        db.commit()
        logging.info("Migration completed successfully")
        
    except Exception as e:
        logging.error(f"Error during traceroute id migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass