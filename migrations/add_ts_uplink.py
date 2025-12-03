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
    Add ts_uplink column to nodeinfo table to track MQTT uplink status
    """
    cursor = None
    try:
        cursor = db.cursor()
        clear_unread_results(cursor)
        
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
        logging.error(f"Error during ts_uplink migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 