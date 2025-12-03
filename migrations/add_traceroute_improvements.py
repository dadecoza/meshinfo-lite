import logging
import mysql.connector
from mysql.connector import Error

def clear_unread_results(cursor):
    """Clear any unread results from the cursor"""
    try:
        while cursor.nextset():
            pass
    except:
        pass

def migrate(db):
    """
    Add improvements to traceroute table:
    - request_id to group related attempts
    - is_reply to distinguish requests from replies
    - error_reason to track failure reasons
    - attempt_number to track attempt sequence
    """
    cursor = None
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        
        # Check which columns already exist
        cursor.execute("SHOW COLUMNS FROM traceroute")
        existing_columns = [column[0] for column in cursor.fetchall()]
        
        # Build ALTER TABLE statement only for missing columns
        alter_statements = []
        if 'request_id' not in existing_columns:
            alter_statements.append("ADD COLUMN request_id BIGINT")
        if 'is_reply' not in existing_columns:
            alter_statements.append("ADD COLUMN is_reply BOOLEAN DEFAULT FALSE")
        if 'error_reason' not in existing_columns:
            alter_statements.append("ADD COLUMN error_reason INT")
        if 'attempt_number' not in existing_columns:
            alter_statements.append("ADD COLUMN attempt_number INT")
            
        # Only execute ALTER TABLE if we have columns to add
        if alter_statements:
            alter_sql = f"ALTER TABLE traceroute {', '.join(alter_statements)}"
            cursor.execute(alter_sql)
        
        # Check if index exists before creating it
        cursor.execute("SHOW INDEX FROM traceroute WHERE Key_name = 'idx_traceroute_request_id'")
        if not cursor.fetchone():
            cursor.execute("""
                CREATE INDEX idx_traceroute_request_id 
                ON traceroute(request_id)
            """)
        
        # Update existing records to use message_id as request_id if needed
        if 'request_id' not in existing_columns:
            cursor.execute("""
                UPDATE traceroute 
                SET request_id = message_id 
                WHERE request_id IS NULL
            """)
        
        # Calculate attempt numbers for existing records if needed
        if 'attempt_number' not in existing_columns:
            cursor.execute("""
                UPDATE traceroute t1
                JOIN (
                    SELECT request_id, COUNT(*) as attempt_count
                    FROM traceroute
                    GROUP BY request_id
                ) t2 ON t1.request_id = t2.request_id
                SET t1.attempt_number = t2.attempt_count
                WHERE t1.attempt_number IS NULL
            """)
        
        db.commit()
        logging.info("Successfully added traceroute improvements")
        
    except Exception as e:
        logging.error(f"Error during traceroute improvements migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 