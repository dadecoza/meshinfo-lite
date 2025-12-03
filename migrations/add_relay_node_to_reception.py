import logging
import configparser

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
        
        # Clear any unread results before proceeding
        clear_unread_results(cursor)
        
        # Ensure we're in the correct database
        cursor.execute("SELECT DATABASE()")
        current_db = cursor.fetchone()[0]
        if not current_db:
            raise Exception("No database selected")
        
        # Check if message_reception table exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.TABLES 
            WHERE TABLE_NAME = 'message_reception'
        """)
        has_reception_table = cursor.fetchone()[0] > 0
        logging.info(f"message_reception table exists: {has_reception_table}")
        
        if not has_reception_table:
            logging.info("message_reception table does not exist, skipping relay_node column addition")
            return
            
        # Double-check that we can actually access the table
        try:
            cursor.execute("SELECT COUNT(*) FROM message_reception LIMIT 1")
            result = cursor.fetchone()
            logging.info("message_reception table is accessible")
        except Exception as table_error:
            logging.warning(f"message_reception table exists in schema but not accessible: {table_error}")
            return
            
        # Check if relay_node column exists in message_reception table
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'message_reception'
            AND COLUMN_NAME = 'relay_node'
        """)
        has_relay_node = cursor.fetchone()[0] > 0
        logging.info(f"relay_node column exists: {has_relay_node}")

        if not has_relay_node:
            logging.info("Adding relay_node column to message_reception table...")
            try:
                cursor.execute("""
                    ALTER TABLE message_reception
                    ADD COLUMN relay_node VARCHAR(4) DEFAULT NULL,
                    ADD INDEX idx_message_reception_relay_node (relay_node)
                """)
                db.commit()
                logging.info("Added relay_node column successfully")
            except Exception as alter_error:
                logging.error(f"Error adding relay_node column: {alter_error}")
                # Try adding just the column first, then the index
                try:
                    cursor.execute("""
                        ALTER TABLE message_reception
                        ADD COLUMN relay_node VARCHAR(4) DEFAULT NULL
                    """)
                    db.commit()
                    logging.info("Added relay_node column (without index)")
                    
                    # Now try to add the index
                    try:
                        cursor.execute("""
                            ALTER TABLE message_reception
                            ADD INDEX idx_message_reception_relay_node (relay_node)
                        """)
                        db.commit()
                        logging.info("Added relay_node index successfully")
                    except Exception as index_error:
                        logging.warning(f"Could not add relay_node index: {index_error}")
                        
                except Exception as column_error:
                    logging.error(f"Could not add relay_node column: {column_error}")
                    raise
        else:
            logging.info("relay_node column already exists in message_reception table")
            
        # Verify the column exists by trying to query it
        try:
            cursor.execute("SELECT relay_node FROM message_reception LIMIT 1")
            logging.info("relay_node column is queryable - migration successful")
        except Exception as verify_error:
            logging.error(f"relay_node column is not queryable: {verify_error}")
            # Try to add the column again as a last resort
            try:
                cursor.execute("""
                    ALTER TABLE message_reception
                    ADD COLUMN relay_node VARCHAR(4) DEFAULT NULL
                """)
                db.commit()
                logging.info("Added relay_node column as fallback")
            except Exception as fallback_error:
                logging.error(f"Failed to add relay_node column as fallback: {fallback_error}")
                raise
            
    except Exception as e:
        logging.error(f"Error during relay_node migration: {e}")
        db.rollback()
        raise 
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 