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
    Add routing_messages table to store routing packet information.
    This table captures routing errors, hop counts, relay nodes, and other routing metadata.
    """
    cursor = None
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        
        # Check if table already exists
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.tables 
            WHERE table_schema = DATABASE() 
            AND table_name = 'routing_messages'
        """)
        
        if cursor.fetchone()[0] > 0:
            logging.info("routing_messages table already exists, skipping creation")
            return
        
        # Create the routing_messages table
        cursor.execute("""
            CREATE TABLE routing_messages (
                routing_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                from_id INT UNSIGNED NOT NULL,
                to_id INT UNSIGNED,
                message_id BIGINT,
                request_id BIGINT,
                relay_node VARCHAR(10),
                hop_limit TINYINT UNSIGNED,
                hop_start TINYINT UNSIGNED,
                hops_taken TINYINT UNSIGNED,
                error_reason INT,
                error_description VARCHAR(50),
                is_error BOOLEAN DEFAULT FALSE,
                success BOOLEAN DEFAULT FALSE,
                channel TINYINT UNSIGNED,
                rx_snr FLOAT,
                rx_rssi FLOAT,
                rx_time BIGINT,
                routing_data JSON,
                uplink_node INT UNSIGNED,
                ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_routing_from (from_id),
                INDEX idx_routing_to (to_id),
                INDEX idx_routing_time (ts_created),
                INDEX idx_routing_error (is_error),
                INDEX idx_routing_relay (relay_node),
                INDEX idx_routing_request (request_id),
                INDEX idx_routing_uplink (uplink_node)
            )
        """)
        
        db.commit()
        logging.info("Successfully created routing_messages table")
        
    except Error as e:
        logging.error(f"Error during routing_messages table creation: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 