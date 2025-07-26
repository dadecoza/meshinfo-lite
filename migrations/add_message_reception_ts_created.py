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
    Add ts_created column to message_reception table for compatibility
    """
    cursor = None
    try:
        cursor = db.cursor()
        
        # Clear any unread results before proceeding
        clear_unread_results(cursor)
        
        # Check if ts_created column exists in message_reception table
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'message_reception'
            AND COLUMN_NAME = 'ts_created'
        """)
        has_ts_created = cursor.fetchone()[0] > 0

        if not has_ts_created:
            logging.info("Adding ts_created column to message_reception table...")
            cursor.execute("""
                ALTER TABLE message_reception
                ADD COLUMN ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                COMMENT 'Timestamp when the reception was recorded'
            """)
            
            # Update existing records to use rx_time converted to timestamp
            logging.info("Updating existing records with rx_time converted to ts_created...")
            cursor.execute("""
                UPDATE message_reception 
                SET ts_created = FROM_UNIXTIME(rx_time) 
                WHERE rx_time IS NOT NULL AND ts_created IS NULL
            """)
            
            db.commit()
            logging.info("Added ts_created column successfully")
        else:
            logging.info("ts_created column already exists in message_reception table")
            
    except Exception as e:
        logging.error(f"Error during ts_created migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 