import logging
import configparser

def migrate(db):
    """
    Migrate database to add message_id and message_reception tracking
    """
    try:
        cursor = db.cursor()
        
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
                    UNIQUE KEY unique_reception (message_id, received_by_id)
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

    except Exception as e:
        logging.error(f"Error performing migration: {e}")
        raise
    finally:
        cursor.close()