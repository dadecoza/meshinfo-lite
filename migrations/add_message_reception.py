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
        clear_unread_results(cursor)
        
        # Ensure we're in the correct database
        cursor.execute("SELECT DATABASE()")
        current_db = cursor.fetchone()[0]
        if not current_db:
            raise Exception("No database selected")
        
        # Check if message_id column exists in text table
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'text'
            AND COLUMN_NAME = 'message_id'
        """)
        has_message_id = cursor.fetchone()[0] > 0

        if not has_message_id:
            logging.info("Adding message_id column to text table...")
            cursor.execute("""
                ALTER TABLE text
                ADD COLUMN message_id BIGINT,
                ADD INDEX idx_text_message_id (message_id)
            """)
            db.commit()
            logging.info("Added message_id column successfully")

        # Check if message_reception table exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.TABLES 
            WHERE TABLE_NAME = 'message_reception'
        """)
        has_reception_table = cursor.fetchone()[0] > 0
        logging.info(f"message_reception table exists: {has_reception_table}")

        # Double-check that we can actually access the table
        if has_reception_table:
            # Clear any unread results before checking table accessibility
            clear_unread_results(cursor)
            try:
                cursor.execute("SELECT COUNT(*) FROM message_reception LIMIT 1")
                result = cursor.fetchone()
                logging.info("message_reception table is accessible")
            except Exception as table_error:
                logging.warning(f"message_reception table exists in schema but not accessible: {table_error}")
                has_reception_table = False

        if not has_reception_table:
            logging.info("Creating message_reception table...")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS message_reception (
                    id INTEGER PRIMARY KEY AUTO_INCREMENT,
                    message_id BIGINT NOT NULL,
                    from_id INTEGER UNSIGNED NOT NULL,
                    received_by_id INTEGER UNSIGNED NOT NULL,
                    rx_time INTEGER,
                    rx_snr REAL,
                    rx_rssi INTEGER,
                    hop_limit INTEGER DEFAULT NULL,
                    hop_start INTEGER DEFAULT NULL,
                    relay_node VARCHAR(4) DEFAULT NULL,
                    UNIQUE KEY unique_reception (message_id, received_by_id),
                    INDEX idx_messagereception_message_receiver (message_id, received_by_id),
                    INDEX idx_message_reception_relay_node (relay_node)
                )
            """)
            db.commit()
            logging.info("Created message_reception table successfully")
        else:
            # Check if hop_limit column exists
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.COLUMNS 
                WHERE TABLE_NAME = 'message_reception'
                AND COLUMN_NAME = 'hop_limit'
            """)
            has_hop_limit = cursor.fetchone()[0] > 0
            
            if not has_hop_limit:
                logging.info("Adding hop_limit column to message_reception table...")
                cursor.execute("""
                    ALTER TABLE message_reception
                    ADD COLUMN hop_limit INTEGER DEFAULT NULL
                """)
                db.commit()
                logging.info("Added hop_limit column successfully")
                
            # Check if hop_start column exists
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.COLUMNS 
                WHERE TABLE_NAME = 'message_reception'
                AND COLUMN_NAME = 'hop_start'
            """)
            has_hop_start = cursor.fetchone()[0] > 0
            
            if not has_hop_start:
                logging.info("Adding hop_start column to message_reception table...")
                cursor.execute("""
                    ALTER TABLE message_reception
                    ADD COLUMN hop_start INTEGER DEFAULT NULL
                """)
                db.commit()
                logging.info("Added hop_start column successfully")
                
            # Check if hop_count column exists (handle legacy migration)
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.COLUMNS 
                WHERE TABLE_NAME = 'message_reception'
                AND COLUMN_NAME = 'hop_count'
            """)
            has_hop_count = cursor.fetchone()[0] > 0
            
            if has_hop_count:
                logging.info("Migrating from hop_count to hop_limit/hop_start...")
                # No need to remove the hop_count column, just leave it for backward compatibility
                logging.info("Migration complete")
                
            # Check if the performance index exists
            cursor.execute("""
                SELECT COUNT(*)
                FROM information_schema.statistics
                WHERE table_schema = DATABASE()
                AND table_name = 'message_reception'
                AND index_name = 'idx_messagereception_message_receiver'
            """)
            has_performance_index = cursor.fetchone()[0] > 0
            
            if not has_performance_index:
                logging.info("Adding performance index to message_reception table...")
                try:
                    cursor.execute("""
                        CREATE INDEX idx_messagereception_message_receiver 
                        ON message_reception(message_id, received_by_id)
                    """)
                    db.commit()
                    logging.info("Added performance index to message_reception table successfully")
                except Exception as index_error:
                    logging.warning(f"Could not add performance index to message_reception table: {index_error}")
                    # Don't raise the error, just log it and continue
            else:
                logging.info("Performance index already exists on message_reception table")

    except Exception as e:
        logging.error(f"Error performing migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass