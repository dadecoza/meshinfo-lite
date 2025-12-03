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
        
        # Check if positionlog index already exists (might have been added by add_positionlog_log_id)
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.statistics
            WHERE table_schema = DATABASE()
            AND table_name = 'positionlog'
            AND index_name = 'idx_positionlog_id_ts'
        """)
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                CREATE INDEX idx_positionlog_id_ts 
                ON positionlog(id, ts_created)
            """)
            logging.info("Added index idx_positionlog_id_ts to positionlog table")
        else:
            logging.info("Index idx_positionlog_id_ts already exists on positionlog table")
        
        # Check if message_reception table exists before adding indexes
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.TABLES 
            WHERE TABLE_NAME = 'message_reception'
        """)
        message_reception_exists = cursor.fetchone()[0] > 0
        logging.info(f"message_reception table exists (info_schema): {message_reception_exists}")
        
        if message_reception_exists:
            # Double-check that we can actually access the table
            try:
                cursor.execute("SELECT COUNT(*) FROM message_reception LIMIT 1")
                result = cursor.fetchone()
                logging.info("message_reception table is accessible")
            except Exception as table_error:
                logging.warning(f"message_reception table exists in schema but not accessible: {table_error}")
                message_reception_exists = False
            
            if message_reception_exists:
                # Clear any unread results before proceeding
                clear_unread_results(cursor)
                
                # Add index for reception lookups if it doesn't exist
                cursor.execute("""
                    SELECT COUNT(*)
                    FROM information_schema.statistics
                    WHERE table_schema = DATABASE()
                    AND table_name = 'message_reception'
                    AND index_name = 'idx_messagereception_message_receiver'
                """)
                if cursor.fetchone()[0] == 0:
                    cursor.execute("""
                        CREATE INDEX idx_messagereception_message_receiver 
                        ON message_reception(message_id, received_by_id)
                    """)
                    logging.info("Added index idx_messagereception_message_receiver to message_reception table")
                else:
                    logging.info("Index idx_messagereception_message_receiver already exists on message_reception table")
            else:
                logging.info("message_reception table not accessible, skipping index creation")
        else:
            logging.info("message_reception table does not exist, skipping index creation")
        
        db.commit()
        logging.info("Successfully added message map performance indexes")
        
    except Exception as e:
        db.rollback()
        logging.error(f"Failed to add message map indexes: {str(e)}")
        raise 
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 