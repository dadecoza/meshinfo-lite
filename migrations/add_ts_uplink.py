import logging

def migrate(db):
    """
    Add ts_uplink column to nodeinfo table to track MQTT uplink status
    """
    try:
        cursor = db.cursor()
        
        # Check if column exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS 
            WHERE TABLE_NAME = 'nodeinfo'
            AND COLUMN_NAME = 'ts_uplink'
        """)
        column_exists = cursor.fetchone()[0] > 0

        if not column_exists:
            logging.info("Adding ts_uplink column to nodeinfo table...")
            cursor.execute("""
                ALTER TABLE nodeinfo
                ADD COLUMN ts_uplink TIMESTAMP NULL DEFAULT NULL
                COMMENT 'Last time node connected via MQTT'
            """)
            db.commit()
            logging.info("Added ts_uplink column successfully")
        else:
            logging.info("ts_uplink column already exists")

    except Exception as e:
        logging.error(f"Error adding ts_uplink column: {e}")
        raise
    finally:
        cursor.close() 