"""
Database Cache Module

This module provides database connection pooling and query caching functionality
for the MeshInfo-Lite application. It manages database connections per thread
and provides methods for clearing the MariaDB query cache.

Key Features:
- Thread-safe connection pooling
- Automatic connection validation and cleanup
- Query cache statistics tracking
- Flask app context independent cache clearing
"""

import mysql.connector
import logging
import threading
import time
from datetime import datetime


class DatabaseCache:
    """Database connection pooling and query caching."""
    
    def __init__(self, config):
        self.config = config
        self._connection_pool = {}
        self._cache_lock = threading.Lock()
        self._query_cache_stats = {
            'hits': 0,
            'misses': 0,
            'last_reset': time.time()
        }
    
    def get_connection(self):
        """Get a database connection from the pool or create a new one."""
        thread_id = threading.get_ident()
        
        with self._cache_lock:
            if thread_id in self._connection_pool:
                conn = self._connection_pool[thread_id]
                try:
                    # Test if connection is still valid
                    if conn.is_connected():
                        return conn
                    else:
                        # Remove stale connection
                        del self._connection_pool[thread_id]
                except Exception:
                    # Remove invalid connection
                    del self._connection_pool[thread_id]
        
        # Create new connection
        try:
            conn = mysql.connector.connect(
                host=self.config["database"]["host"],
                user=self.config["database"]["username"],
                password=self.config["database"]["password"],
                database=self.config["database"]["database"],
                charset="utf8mb4",
                connection_timeout=10
            )
            
            with self._cache_lock:
                self._connection_pool[thread_id] = conn
            
            logging.debug(f"Created new database connection for thread {thread_id}")
            return conn
            
        except Exception as e:
            logging.error(f"Failed to create database connection: {e}")
            raise
    
    def close_connection(self):
        """Close the database connection for the current thread."""
        thread_id = threading.get_ident()
        
        with self._cache_lock:
            if thread_id in self._connection_pool:
                conn = self._connection_pool[thread_id]
                try:
                    if conn.is_connected():
                        conn.close()
                        logging.debug(f"Closed database connection for thread {thread_id}")
                except Exception as e:
                    logging.warning(f"Error closing database connection: {e}")
                finally:
                    del self._connection_pool[thread_id]
    
    def execute_cached_query(self, sql, params=None, cache_key=None, timeout=None):
        """Execute a query with database-level caching."""
        conn = self.get_connection()
        cursor = conn.cursor(dictionary=True)
        
        try:
            # Execute query - global query cache will handle caching automatically
            cursor.execute(sql, params or ())
            results = cursor.fetchall()
            
            with self._cache_lock:
                self._query_cache_stats['hits'] += 1
            
            return results
            
        except Exception as e:
            with self._cache_lock:
                self._query_cache_stats['misses'] += 1
            logging.error(f"Database query error: {e}")
            raise
        finally:
            cursor.close()
    
    def get_cache_stats(self):
        """Get query cache statistics."""
        with self._cache_lock:
            return self._query_cache_stats.copy()
    
    def clear_query_cache(self):
        """Clear the database query cache."""
        try:
            # Create a direct connection to avoid Flask app context issues
            import mysql.connector
            conn = mysql.connector.connect(
                host=self.config["database"]["host"],
                user=self.config["database"]["username"],
                password=self.config["database"]["password"],
                database=self.config["database"]["database"],
                charset="utf8mb4",
                connection_timeout=10
            )
            cursor = conn.cursor()
            try:
                # Try to clear query cache, but handle permission errors gracefully
                try:
                    cursor.execute("FLUSH QUERY CACHE")
                    logging.info("FLUSH QUERY CACHE executed successfully")
                except mysql.connector.Error as e:
                    if e.errno == 1227:  # Access denied for RELOAD privilege
                        logging.warning("Cannot FLUSH QUERY CACHE - insufficient privileges (RELOAD required)")
                    else:
                        logging.error(f"Error executing FLUSH QUERY CACHE: {e}")
                
                try:
                    cursor.execute("RESET QUERY CACHE")
                    logging.info("RESET QUERY CACHE executed successfully")
                except mysql.connector.Error as e:
                    if e.errno == 1227:  # Access denied for RELOAD privilege
                        logging.warning("Cannot RESET QUERY CACHE - insufficient privileges (RELOAD required)")
                    else:
                        logging.error(f"Error executing RESET QUERY CACHE: {e}")
                
                # If we get here, at least one command succeeded or we handled the errors gracefully
                logging.info("Database query cache clear operation completed")
                
            except Exception as e:
                logging.error(f"Error during query cache clear operations: {e}")
            finally:
                cursor.close()
                conn.close()
        except Exception as e:
            logging.error(f"Error creating connection for cache clear: {e}")
    
    def close_all_connections(self):
        """Close all database connections in the pool."""
        with self._cache_lock:
            for thread_id, conn in list(self._connection_pool.items()):
                try:
                    if conn.is_connected():
                        conn.close()
                        logging.debug(f"Closed database connection for thread {thread_id}")
                except Exception as e:
                    logging.warning(f"Error closing database connection: {e}")
            self._connection_pool.clear()
    
    def check_privileges(self):
        """Check if the database user has required privileges for cache operations."""
        try:
            import mysql.connector
            conn = mysql.connector.connect(
                host=self.config["database"]["host"],
                user=self.config["database"]["username"],
                password=self.config["database"]["password"],
                database=self.config["database"]["database"],
                charset="utf8mb4",
                connection_timeout=10
            )
            cursor = conn.cursor()
            
            privileges = {
                'reload': False,
                'query_cache': False
            }
            
            try:
                # Check RELOAD privilege by attempting a simple FLUSH command
                cursor.execute("FLUSH QUERY CACHE")
                privileges['reload'] = True
                privileges['query_cache'] = True
                logging.info("Database user has RELOAD privilege")
            except mysql.connector.Error as e:
                if e.errno == 1227:  # Access denied for RELOAD privilege
                    logging.warning("Database user lacks RELOAD privilege - query cache operations will be limited")
                    privileges['reload'] = False
                    privileges['query_cache'] = False
                else:
                    logging.error(f"Error checking RELOAD privilege: {e}")
            
            cursor.close()
            conn.close()
            return privileges
            
        except Exception as e:
            logging.error(f"Error checking database privileges: {e}")
            return {'reload': False, 'query_cache': False}
    
    def __del__(self):
        """Cleanup when the object is destroyed."""
        self.close_all_connections() 