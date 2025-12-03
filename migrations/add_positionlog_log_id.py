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
        # Check if log_id column already exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.COLUMNS
            WHERE TABLE_NAME = 'positionlog'
            AND COLUMN_NAME = 'log_id'
        """)
        column_exists = cursor.fetchone()[0] > 0

        if not column_exists:
            logging.info("Adding log_id column to positionlog table...")
            # Drop old primary key
            cursor.execute("ALTER TABLE positionlog DROP PRIMARY KEY")
            # Add log_id as auto-increment primary key
            cursor.execute("""
                ALTER TABLE positionlog
                ADD COLUMN log_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST
            """)
            logging.info("Added log_id column as primary key to positionlog table.")
        else:
            logging.info("log_id column already exists in positionlog table.")

        # Add secondary index for (id, ts_created) if not exists
        cursor.execute("""
            SELECT COUNT(*)
            FROM information_schema.STATISTICS
            WHERE TABLE_NAME = 'positionlog'
            AND INDEX_NAME = 'idx_positionlog_id_ts'
        """)
        index_exists = cursor.fetchone()[0] > 0
        if not index_exists:
            cursor.execute("CREATE INDEX idx_positionlog_id_ts ON positionlog(id, ts_created)")
            logging.info("Added index idx_positionlog_id_ts on (id, ts_created) to positionlog table.")
        else:
            logging.info("Index idx_positionlog_id_ts already exists on positionlog table.")

        db.commit()
    except Exception as e:
        logging.error(f"Error during positionlog log_id migration: {e}")
        db.rollback()
        raise
    finally:
        if cursor:
            try:
                cursor.close()
            except:
                pass 