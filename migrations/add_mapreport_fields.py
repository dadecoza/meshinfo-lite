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
        
        # Check if columns already exist
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            AND table_name = 'nodeinfo'
            AND column_name = 'has_default_channel'
        """)
        has_default_channel_exists = cursor.fetchone()[0] > 0
        
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            AND table_name = 'nodeinfo'
            AND column_name = 'num_online_local_nodes'
        """)
        num_online_local_nodes_exists = cursor.fetchone()[0] > 0
        
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            AND table_name = 'nodeinfo'
            AND column_name = 'region'
        """)
        region_exists = cursor.fetchone()[0] > 0
        
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.columns
            WHERE table_schema = DATABASE()
            AND table_name = 'nodeinfo'
            AND column_name = 'modem_preset'
        """)
        modem_preset_exists = cursor.fetchone()[0] > 0
        
        # Add has_default_channel column if it doesn't exist
        if not has_default_channel_exists:
            cursor.execute("""
                ALTER TABLE nodeinfo 
                ADD COLUMN has_default_channel BOOLEAN NULL
            """)
            logging.info("Added has_default_channel column to nodeinfo table")
        else:
            logging.info("has_default_channel column already exists in nodeinfo table")
        
        # Add num_online_local_nodes column if it doesn't exist
        if not num_online_local_nodes_exists:
            cursor.execute("""
                ALTER TABLE nodeinfo 
                ADD COLUMN num_online_local_nodes INT UNSIGNED NULL
            """)
            logging.info("Added num_online_local_nodes column to nodeinfo table")
        else:
            logging.info("num_online_local_nodes column already exists in nodeinfo table")
        
        # Add region column if it doesn't exist
        if not region_exists:
            cursor.execute("""
                ALTER TABLE nodeinfo 
                ADD COLUMN region INT UNSIGNED NULL
            """)
            logging.info("Added region column to nodeinfo table")
        else:
            logging.info("region column already exists in nodeinfo table")
        
        # Add modem_preset column if it doesn't exist
        if not modem_preset_exists:
            cursor.execute("""
                ALTER TABLE nodeinfo 
                ADD COLUMN modem_preset INT UNSIGNED NULL
            """)
            logging.info("Added modem_preset column to nodeinfo table")
        else:
            logging.info("modem_preset column already exists in nodeinfo table")
        
        db.commit()
        logging.info("Successfully added mapreport fields to nodeinfo table")
        
    except Exception as e:
        logging.error(f"Failed to add mapreport fields to nodeinfo table: {e}")
        db.rollback()
        raise 
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 