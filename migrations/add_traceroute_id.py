def migrate(db):
    cursor = db.cursor()
    try:
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
        
        # Build ALTER TABLE statement
        alter_statements = []
        
        # Handle special case for SNR rename if needed
        if 'snr' in existing_columns and 'snr_towards' not in existing_columns:
            alter_statements.append("CHANGE COLUMN snr snr_towards TEXT NULL")
            existing_columns.remove('snr')
            existing_columns.append('snr_towards')
        
        # Add missing columns
        for col, type_def in needed_columns.items():
            if col not in existing_columns:
                if col == 'traceroute_id':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} FIRST")
                elif col == 'request_id':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER traceroute_id")
                elif col == 'channel':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER to_id")
                elif col == 'hop_limit':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER channel")
                elif col == 'success':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER hop_limit")
                elif col == 'time':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER success")
                elif col == 'snr_back':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER snr_towards")
                elif col == 'route_back':
                    alter_statements.append(f"ADD COLUMN {col} {type_def} AFTER route")
                else:
                    alter_statements.append(f"ADD COLUMN {col} {type_def}")
        
        # Execute ALTER TABLE if there are changes needed
        if alter_statements:
            alter_sql = "ALTER TABLE traceroute " + ", ".join(alter_statements)
            print(f"Executing: {alter_sql}")
            cursor.execute(alter_sql)
        
        # Commit transaction
        db.commit()
        print("Migration completed successfully")
        
    except Exception as e:
        print(f"Migration error: {str(e)}")
        db.rollback()
        raise
    finally:
        cursor.close()