#!/usr/bin/env python3
"""
Cache monitoring script for meshinfo-lite
Monitors database query cache and application cache performance
"""

import requests
import json
import time
import psutil
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def get_cache_stats(base_url="http://localhost:8001"):
    """Get cache statistics from the application."""
    try:
        # Get application cache stats
        response = requests.get(f"{base_url}/api/debug/cache", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logging.error(f"Error getting cache stats: {e}")
    return None

def get_database_cache_stats(base_url="http://localhost:8001"):
    """Get database cache statistics."""
    try:
        response = requests.get(f"{base_url}/api/debug/database-cache", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logging.error(f"Error getting database cache stats: {e}")
    return None

def get_memory_usage():
    """Get current memory usage."""
    process = psutil.Process()
    memory_info = process.memory_info()
    return {
        'rss_mb': memory_info.rss / 1024 / 1024,
        'vms_mb': memory_info.vms / 1024 / 1024,
        'percent': process.memory_percent()
    }

def monitor_cache_performance(duration_minutes=10, interval_seconds=30):
    """Monitor cache performance for a specified duration."""
    logging.info(f"Starting cache monitoring for {duration_minutes} minutes")
    
    start_time = time.time()
    end_time = start_time + (duration_minutes * 60)
    
    while time.time() < end_time:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Get memory usage
        memory = get_memory_usage()
        
        # Get cache stats
        cache_stats = get_cache_stats()
        db_cache_stats = get_database_cache_stats()
        
        # Log results
        logging.info(f"[{timestamp}] Memory: {memory['rss_mb']:.1f}MB RSS, {memory['percent']:.1f}%")
        
        if db_cache_stats and 'database_cache_stats' in db_cache_stats:
            db_stats = db_cache_stats['database_cache_stats']
            logging.info(f"[{timestamp}] DB Cache: {db_stats.get('hits', 0)} hits, {db_stats.get('misses', 0)} misses")
        
        if cache_stats:
            logging.info(f"[{timestamp}] App Cache: {cache_stats.get('message', 'No stats available')}")
        
        time.sleep(interval_seconds)
    
    logging.info("Cache monitoring completed")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Monitor cache performance")
    parser.add_argument("--duration", type=int, default=10, help="Monitoring duration in minutes")
    parser.add_argument("--interval", type=int, default=30, help="Check interval in seconds")
    parser.add_argument("--url", default="http://localhost:8001", help="Application base URL")
    
    args = parser.parse_args()
    
    monitor_cache_performance(args.duration, args.interval) 