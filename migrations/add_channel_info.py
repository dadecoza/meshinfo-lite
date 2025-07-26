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
        
        # List of tables that should have channel information
        tables_to_update = [
            'telemetry',
            'position',
            'neighborinfo',
            'meshlog',
            'traceroute'
        ]
        
        for table_name in tables_to_update:
            logging.info(f"Processing table: {table_name}")
            
            # Check if table exists
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.TABLES 
                WHERE TABLE_NAME = %s
            """, (table_name,))
            table_exists = cursor.fetchone()[0] > 0
            
            if not table_exists:
                logging.info(f"Table {table_name} does not exist, skipping...")
                continue
                
            # Check if channel column exists
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.COLUMNS 
                WHERE TABLE_NAME = %s
                AND COLUMN_NAME = 'channel'
            """, (table_name,))
            has_channel = cursor.fetchone()[0] > 0
            
            if not has_channel:
                logging.info(f"Adding channel column to {table_name} table...")
                try:
                    cursor.execute(f"""
                        ALTER TABLE {table_name}
                        ADD COLUMN channel INT UNSIGNED NULL,
                        ADD INDEX idx_{table_name}_channel (channel)
                    """)
                    db.commit()
                    logging.info(f"Added channel column to {table_name} successfully")
                except Exception as e:
                    logging.error(f"Error adding channel column to {table_name}: {e}")
                    raise
            else:
                logging.info(f"Channel column already exists in {table_name} table")
                # Check if index exists
                index_name = f"idx_{table_name}_channel"
                cursor.execute("""
                    SELECT COUNT(*) 
                    FROM information_schema.STATISTICS
                    WHERE TABLE_NAME = %s
                    AND INDEX_NAME = %s
                """, (table_name, index_name))
                has_index = cursor.fetchone()[0] > 0
                
                if not has_index:
                    logging.info(f"Adding index on channel column for {table_name}...")
                    try:
                        cursor.execute(f"""
                            ALTER TABLE {table_name}
                            ADD INDEX {index_name} (channel)
                        """)
                        db.commit()
                        logging.info(f"Added channel index to {table_name} successfully")
                    except Exception as e:
                        logging.error(f"Error adding channel index to {table_name}: {e}")
                        raise
                else:
                    logging.info(f"Channel index already exists in {table_name} table")
        
        # Special handling for meshlog table - extract channel from JSON if possible
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.TABLES 
            WHERE TABLE_NAME = 'meshlog'
        """)
        meshlog_exists = cursor.fetchone()[0] > 0
        
        if meshlog_exists:
            # Ensure meshlog table has channel column (in case it wasn't added in the loop)
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.COLUMNS 
                WHERE TABLE_NAME = 'meshlog'
                AND COLUMN_NAME = 'channel'
            """, ())
            has_channel_column = cursor.fetchone()[0] > 0
            
            if not has_channel_column:
                logging.info("Adding channel column to meshlog table...")
                cursor.execute("""
                    ALTER TABLE meshlog
                    ADD COLUMN channel INT UNSIGNED NULL,
                    ADD INDEX idx_meshlog_channel (channel)
                """)
                db.commit()
                logging.info("Added channel column to meshlog table successfully")
                has_channel_column = True
            
            if has_channel_column:
                # Double-check that channel column actually exists before using it
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM information_schema.COLUMNS 
                    WHERE TABLE_NAME = 'meshlog'
                    AND COLUMN_NAME = 'channel'
                """)
                channel_exists = cursor.fetchone()[0] > 0
                
                # Additional check: try to actually query the channel column
                if channel_exists:
                    try:
                        cursor.execute("SELECT COUNT(*) FROM meshlog WHERE channel IS NULL")
                        result = cursor.fetchone()
                        logging.info("Channel column is queryable in meshlog table")
                    except Exception as query_error:
                        logging.warning(f"Channel column exists in schema but not queryable: {query_error}")
                        channel_exists = False
                
                if channel_exists:
                    logging.info("Channel column confirmed to exist in meshlog table")
                    
                    # Clear any unread results before proceeding
                    clear_unread_results(cursor)
                    
                    # Check if we have any messages with channel information
                    try:
                        logging.info("Checking for messages with channel information...")
                        cursor.execute("""
                            SELECT COUNT(*)
                            FROM meshlog
                            WHERE JSON_EXTRACT(message, '$.channel') IS NOT NULL
                            AND channel IS NULL
                        """)
                        result = cursor.fetchone()
                        has_channel_data = result[0] > 0
                        logging.info(f"Found {has_channel_data} messages with channel information to extract")
                        
                        if has_channel_data:
                            logging.info("Extracting channel information from meshlog messages...")
                            cursor.execute("""
                                UPDATE meshlog
                                SET channel = CAST(JSON_EXTRACT(message, '$.channel') AS UNSIGNED)
                                WHERE JSON_EXTRACT(message, '$.channel') IS NOT NULL
                                AND channel IS NULL
                            """)
                            db.commit()
                            logging.info("Extracted channel information successfully")
                    except Exception as e:
                        logging.error(f"Error during channel extraction from meshlog: {e}")
                        # Try to get more information about the table structure
                        try:
                            cursor.execute("DESCRIBE meshlog")
                            columns = cursor.fetchall()
                            logging.info(f"Meshlog table structure: {columns}")
                        except Exception as desc_error:
                            logging.error(f"Error describing meshlog table: {desc_error}")
                        raise
                else:
                    logging.warning("Channel column was not found in meshlog table, skipping channel extraction")
        
        logging.info("Channel information migration completed successfully")
        
    except Exception as e:
        logging.error(f"Error performing channel information migration: {e}")
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 