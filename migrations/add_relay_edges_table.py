import logging

def clear_unread_results(cursor):
    """Clear any unread results from the cursor"""
    try:
        while cursor.nextset():
            pass
    except:
        pass

def migrate(db):
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS relay_edges (
                from_node VARCHAR(8) NOT NULL,
                relay_suffix VARCHAR(2) NOT NULL,
                to_node VARCHAR(8) NOT NULL,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                count INT DEFAULT 1,
                PRIMARY KEY (from_node, relay_suffix, to_node)
            )
        """)
        db.commit()
        logging.info("relay_edges table created successfully.")
        cursor.close()
    except Exception as e:
        logging.error(f"Error creating relay_edges table: {e}")
        logging.info("Continuing despite relay_edges table creation error") 