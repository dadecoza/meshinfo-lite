from flask import (
    Flask,
    send_from_directory,
    render_template,
    request,
    make_response,
    redirect,
    url_for,
    abort,
    g,
    jsonify,
    current_app
)
from flask_caching import Cache
from waitress import serve
from paste.translogger import TransLogger
import configparser
import logging
import os
import psutil
import gc
import weakref
import threading
import time
import re
import sys
import math
from shapely.geometry import MultiPoint

import utils
import meshtastic_support
from meshdata import MeshData
from database_cache import DatabaseCache
from meshinfo_register import Register
from meshtastic_monday import MeshtasticMonday
from meshinfo_telemetry_graph import draw_graph
from meshinfo_los_profile import LOSProfile
from timezone_utils import convert_to_local, format_timestamp, time_ago
import json
import datetime
from meshinfo_api import api

app = Flask(__name__)

cache_dir = os.path.join(os.path.dirname(__file__), 'runtime_cache')

# Ensure the cache directory exists
if not os.path.exists(cache_dir):
    try:
        os.makedirs(cache_dir)
        logging.info(f"Created cache directory: {cache_dir}")
    except OSError as e:
        logging.error(f"Could not create cache directory {cache_dir}: {e}")
        cache_dir = None # Indicate failure

# Initialize cache after config is loaded
cache = None

def initialize_cache():
    """Initialize the Flask cache with configuration."""
    global cache
    
    # Load config first
    config = configparser.ConfigParser()
    config.read("config.ini")
    
    # Configure Flask-Caching
    cache_config = {
        'CACHE_TYPE': 'FileSystemCache',
        'CACHE_DIR': cache_dir,
        'CACHE_THRESHOLD': int(config.get('server', 'app_cache_max_entries', fallback=100)),
        'CACHE_DEFAULT_TIMEOUT': int(config.get('server', 'app_cache_timeout_seconds', fallback=60)),
        'CACHE_OPTIONS': {
            'mode': 0o600,
            'max_size': 50 * 1024 * 1024  # 50MB max size per item
        }
    }
    
    if cache_dir:
        logging.info(f"Using FileSystemCache with directory: {cache_dir}")
    else:
        logging.warning("Falling back to SimpleCache due to directory creation issues.")

    # Initialize Cache with the chosen config
    try:
        cache = Cache(app, config=cache_config)
    except Exception as e:
        logging.error(f"Failed to initialize cache: {e}")
        # Fallback to SimpleCache if FileSystemCache fails
        cache_config = {
            'CACHE_TYPE': 'SimpleCache',
            'CACHE_DEFAULT_TIMEOUT': int(config.get('server', 'app_cache_timeout_seconds', fallback=300)),
            'CACHE_THRESHOLD': int(config.get('server', 'app_cache_max_entries', fallback=100))
        }
        cache = Cache(app, config=cache_config)

# Cache monitoring functions
def get_cache_size():
    """Get total size of cache directory in bytes."""
    if cache_dir:
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(cache_dir):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    total_size += os.path.getsize(fp)
            return total_size
        except Exception as e:
            logging.error(f"Error getting cache size: {e}")
    return 0

def get_cache_entry_count():
    """Get number of entries in cache directory."""
    if cache_dir:
        try:
            return len([f for f in os.listdir(cache_dir) if not f.endswith('.lock')])
        except Exception as e:
            logging.error(f"Error getting cache entry count: {e}")
    return 0

def get_largest_cache_entries(limit=5):
    """Get the largest cache entries with their sizes."""
    if cache_dir:
        try:
            entries = []
            for f in os.listdir(cache_dir):
                if not f.endswith('.lock'):
                    path = os.path.join(cache_dir, f)
                    size = os.path.getsize(path)
                    entries.append((f, size))
            return sorted(entries, key=lambda x: x[1], reverse=True)[:limit]
        except Exception as e:
            logging.error(f"Error getting largest cache entries: {e}")
    return []

def log_cache_stats():
    """Log detailed cache statistics."""
    try:
        total_size = get_cache_size()
        entry_count = get_cache_entry_count()
        largest_entries = get_largest_cache_entries()
        
        logging.info(f"Cache Statistics:")
        logging.info(f"  Total Size: {total_size / 1024 / 1024:.2f} MB")
        logging.info(f"  Entry Count: {entry_count}")
        logging.info("  Largest Entries:")
        for entry, size in largest_entries:
            logging.info(f"    {entry}: {size / 1024 / 1024:.2f} MB")
    except Exception as e:
        logging.error(f"Error logging cache stats: {e}")

# Modify cleanup_cache to include cache stats
def cleanup_cache():
    try:
        logging.info("Starting cache cleanup")
        logging.info("Memory usage before cache cleanup:")
        log_memory_usage(force=True)
        logging.info("Cache stats before cleanup:")
        log_cache_stats()
        
        # Clear nodes-related cache entries
        clear_nodes_cache()
        
        # Clear database query cache
        clear_database_cache()
        
        # Clear the cache
        with app.app_context():
            cache.clear()
        
        # Force garbage collection
        gc.collect()
        
        logging.info("Memory usage after cache cleanup:")
        log_memory_usage(force=True)
        logging.info("Cache stats after cleanup:")
        log_cache_stats()
        
    except Exception as e:
        logging.error(f"Error during cache cleanup: {e}")

# Make globals available to templates
app.jinja_env.globals.update(convert_to_local=convert_to_local)
app.jinja_env.globals.update(format_timestamp=format_timestamp)
app.jinja_env.globals.update(time_ago=time_ago)
app.jinja_env.globals.update(min=min)
app.jinja_env.globals.update(max=max)
app.jinja_env.globals.update(datetime=datetime.datetime)

# Add template filters
@app.template_filter('safe_hw_model')
def safe_hw_model(value):
    try:
        return meshtastic_support.get_hardware_model_name(value)
    except (ValueError, AttributeError):
        return f"Unknown ({value})"

config = configparser.ConfigParser()
config.read("config.ini")

# Initialize cache with config
initialize_cache()

# Register API blueprint
app.register_blueprint(api)

# Add request context tracking
active_requests = set()
request_lock = threading.Lock()

# Add memory usage tracking
last_memory_log = 0
last_memory_usage = 0
MEMORY_LOG_INTERVAL = 60  # Log every minute instead of 5 minutes
MEMORY_CHANGE_THRESHOLD = 10 * 1024 * 1024  # 10MB change threshold (reduced from 50MB)

@app.before_request
def before_request():
    """Track request start."""
    with request_lock:
        active_requests.add(id(request))
    # Enhanced memory logging for high-activity periods
    if len(active_requests) > 5:  # If more than 5 concurrent requests
        log_memory_usage(force=True)

@app.after_request
def after_request(response):
    """Clean up request context."""
    with request_lock:
        active_requests.discard(id(request))
    # Enhanced memory logging for high-activity periods
    if len(active_requests) > 5:  # If more than 5 concurrent requests
        log_memory_usage(force=True)
    return response

# Modify get_meshdata to use connection pooling
def get_meshdata():
    """Opens a new MeshData connection if there is none yet for the
    current application context.
    """
    if 'meshdata' not in g:
        try:
            # Create new MeshData instance without connection pooling
            g.meshdata = MeshData()
            logging.debug("MeshData instance created for request context.")
        except Exception as e:
            logging.error(f"Failed to create MeshData for request context: {e}")
            g.meshdata = None
    return g.meshdata

@app.teardown_appcontext
def teardown_meshdata(exception):
    """Closes the MeshData connection at the end of the request."""
    md = g.pop('meshdata', None)
    if md is not None:
        try:
            if hasattr(md, 'db') and md.db:
                if md.db.is_connected():
                    md.db.close()
                    logging.debug("Database connection closed in teardown.")
                else:
                    logging.debug("Database connection was already closed.")
            else:
                logging.debug("No database connection to close.")
        except Exception as e:
            logging.error(f"Error handling database connection in teardown: {e}")
        finally:
            # Ensure the MeshData instance is properly cleaned up
            try:
                del md
            except:
                pass
        logging.debug("MeshData instance removed from request context.")

def log_memory_usage(force=False):
    """Log current memory usage with detailed information."""
    global last_memory_log, last_memory_usage
    current_time = time.time()
    current_usage = psutil.Process().memory_info().rss
    
    # Only log if:
    # 1. It's been more than MEMORY_LOG_INTERVAL seconds since last log
    # 2. Memory usage has changed by more than threshold
    # 3. Force flag is set
    if not force and (current_time - last_memory_log < MEMORY_LOG_INTERVAL and 
                     abs(current_usage - last_memory_usage) < MEMORY_CHANGE_THRESHOLD):
        return
        
    try:
        import gc
        gc.collect()  # Force garbage collection before measuring
        
        process = psutil.Process()
        mem_info = process.memory_info()
        
        # Get memory usage by object type with more detail
        objects_by_type = {}
        large_objects = []  # Track objects larger than 1MB
        object_counts = {}
        
        for obj in gc.get_objects():
            obj_type = type(obj).__name__
            try:
                obj_size = sys.getsizeof(obj)
                
                # Track object counts
                if obj_type not in object_counts:
                    object_counts[obj_type] = 0
                object_counts[obj_type] += 1
                
                # Track memory by type
                if obj_type not in objects_by_type:
                    objects_by_type[obj_type] = 0
                objects_by_type[obj_type] += obj_size
                
                # Track large objects (> 1MB)
                if obj_size > 1024 * 1024:  # 1MB
                    large_objects.append({
                        'type': obj_type,
                        'size': obj_size,
                        'repr': str(obj)[:100] + '...' if len(str(obj)) > 100 else str(obj)
                    })
                    
            except (TypeError, ValueError, RecursionError):
                pass
        
        # Sort object types by memory usage
        sorted_objects = sorted(objects_by_type.items(), key=lambda x: x[1], reverse=True)
        
        # Sort large objects by size
        large_objects.sort(key=lambda x: x['size'], reverse=True)
        
        # Sort object counts
        sorted_counts = sorted(object_counts.items(), key=lambda x: x[1], reverse=True)
        
        logging.info(f"=== MEMORY USAGE REPORT ===")
        logging.info(f"Memory Usage: {mem_info.rss / 1024 / 1024:.1f} MB")
        logging.info(f"Active Requests: {len(active_requests)}")
        logging.info(f"Memory Change: {(current_usage - last_memory_usage) / 1024 / 1024:+.1f} MB")
        
        logging.info("Top 10 memory-consuming object types:")
        for obj_type, size in sorted_objects[:10]:
            count = object_counts.get(obj_type, 0)
            logging.info(f"  {obj_type}: {size / 1024 / 1024:.1f} MB ({count:,} objects)")
            
        logging.info("Top 10 object counts:")
        for obj_type, count in sorted_counts[:10]:
            size = objects_by_type.get(obj_type, 0)
            logging.info(f"  {obj_type}: {count:,} objects ({size / 1024 / 1024:.1f} MB)")
            
        if large_objects:
            logging.info("Large objects (>1MB):")
            for obj in large_objects[:10]:  # Show top 10 largest objects
                logging.info(f"  {obj['type']}: {obj['size'] / 1024 / 1024:.1f} MB - {obj['repr']}")
        
        # Check for potential memory leaks
        if current_usage > last_memory_usage + 50 * 1024 * 1024:  # 50MB increase
            logging.warning(f"POTENTIAL MEMORY LEAK: Memory increased by {(current_usage - last_memory_usage) / 1024 / 1024:.1f} MB")
            
        # Check for specific problematic object types
        problematic_types = ['dict', 'list', 'SimpleNamespace', 'function', 'type']
        for obj_type in problematic_types:
            if obj_type in objects_by_type:
                size = objects_by_type[obj_type]
                count = object_counts.get(obj_type, 0)
                if size > 100 * 1024 * 1024:  # 100MB
                    logging.warning(f"LARGE {obj_type.upper()} OBJECTS: {size / 1024 / 1024:.1f} MB ({count:,} objects)")
        
        logging.info("=== END MEMORY REPORT ===")
            
        last_memory_log = current_time
        last_memory_usage = current_usage
        
    except Exception as e:
        logging.error(f"Error in detailed memory logging: {e}")

# Add connection monitoring
def monitor_connections():
    """Monitor database connections."""
    while True:
        try:
            with app.app_context():
                if hasattr(g, 'meshdata') and g.meshdata and hasattr(g.meshdata, 'db'):
                    if g.meshdata.db.is_connected():
                        logging.info("Database connection is active")
                    else:
                        logging.warning("Database connection is not active")
        except Exception as e:
            logging.error(f"Error monitoring database connection: {e}")
        time.sleep(60)  # Check every minute

# Add cache lock monitoring
def monitor_cache_locks():
    """Monitor cache lock files."""
    while True:
        try:
            if cache_dir:
                lock_files = [f for f in os.listdir(cache_dir) if f.endswith('.lock')]
                if lock_files:
                    logging.warning(f"Found {len(lock_files)} stale cache locks")
                    # Clean up stale locks
                    for lock_file in lock_files:
                        try:
                            os.remove(os.path.join(cache_dir, lock_file))
                        except Exception as e:
                            logging.error(f"Error removing stale lock {lock_file}: {e}")
        except Exception as e:
            logging.error(f"Error monitoring cache locks: {e}")
        time.sleep(300)  # Check every 5 minutes

def log_detailed_memory_analysis():
    """Perform detailed memory analysis to identify potential leaks."""
    try:
        import gc
        gc.collect()
        
        logging.info("=== DETAILED MEMORY ANALYSIS ===")
        
        # Check database connections
        db_connections = 0
        for obj in gc.get_objects():
            if hasattr(obj, '__class__') and 'mysql' in str(obj.__class__).lower():
                db_connections += 1
        logging.info(f"Database connection objects: {db_connections}")
        
        # Check cache objects
        cache_objects = 0
        cache_size = 0
        for obj in gc.get_objects():
            if hasattr(obj, '__class__') and 'cache' in str(obj.__class__).lower():
                cache_objects += 1
                try:
                    cache_size += sys.getsizeof(obj)
                except:
                    pass
        logging.info(f"Cache objects: {cache_objects} ({cache_size / 1024 / 1024:.1f} MB)")
        
        # Check for Flask/WSGI objects
        flask_objects = 0
        for obj in gc.get_objects():
            if hasattr(obj, '__class__') and 'flask' in str(obj.__class__).lower():
                flask_objects += 1
        logging.info(f"Flask objects: {flask_objects}")
        
        # Check for template objects
        template_objects = 0
        for obj in gc.get_objects():
            if hasattr(obj, '__class__') and 'template' in str(obj.__class__).lower():
                template_objects += 1
        logging.info(f"Template objects: {template_objects}")
        
        # Check for large dictionaries and lists
        large_dicts = []
        large_lists = []
        for obj in gc.get_objects():
            try:
                if isinstance(obj, dict) and len(obj) > 1000:
                    large_dicts.append((len(obj), str(obj)[:50]))
                elif isinstance(obj, list) and len(obj) > 1000:
                    large_lists.append((len(obj), str(obj)[:50]))
            except:
                pass
        
        if large_dicts:
            logging.info("Large dictionaries:")
            for size, repr_str in sorted(large_dicts, reverse=True)[:5]:
                logging.info(f"  Dict with {size:,} items: {repr_str}")
                
        if large_lists:
            logging.info("Large lists:")
            for size, repr_str in sorted(large_lists, reverse=True)[:5]:
                logging.info(f"  List with {size:,} items: {repr_str}")
        
        # Check for circular references
        circular_refs = gc.collect()
        if circular_refs > 0:
            logging.warning(f"Found {circular_refs} circular references")
        
        logging.info("=== END DETAILED ANALYSIS ===")
        
    except Exception as e:
        logging.error(f"Error in detailed memory analysis: {e}")

# Modify the memory watchdog to include detailed analysis
def memory_watchdog():
    """Monitor memory usage and take action if it gets too high."""
    while True:
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            
            if memory_mb > 1000:  # If over 1GB (reduced from 2GB)
                logging.warning(f"Memory usage high ({memory_mb:.2f} MB), performing detailed analysis")
                log_detailed_memory_analysis()
                logging.info("Cache stats before high memory cleanup:")
                log_cache_stats()
                with app.app_context():
                    cache.clear()
                # Clear nodes-related cache entries
                clear_nodes_cache()
                # Clear database query cache
                clear_database_cache()
                gc.collect()
                logging.info("Cache stats after high memory cleanup:")
                log_cache_stats()
                
            if memory_mb > 2000:  # If over 2GB (reduced from 4GB)
                logging.error(f"Memory usage critical ({memory_mb:.2f} MB), logging detailed memory info")
                log_memory_usage(force=True)
                log_detailed_memory_analysis()
                logging.info("Cache stats at critical memory level:")
                log_cache_stats()
                # Force clear nodes cache at critical levels
                clear_nodes_cache()
                clear_database_cache()
                gc.collect()
                
        except Exception as e:
            logging.error(f"Error in memory watchdog: {e}")
            
        time.sleep(30)  # Check every 30 seconds instead of 60

# Start monitoring threads
connection_monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
connection_monitor_thread.start()

lock_monitor_thread = threading.Thread(target=monitor_cache_locks, daemon=True)
lock_monitor_thread.start()

watchdog_thread = threading.Thread(target=memory_watchdog, daemon=True)
watchdog_thread.start()

# Schedule cache cleanup
def schedule_cache_cleanup():
    while True:
        time.sleep(900)  # Run every 15 minutes instead of hourly
        cleanup_cache()

cleanup_thread = threading.Thread(target=schedule_cache_cleanup, daemon=True)
cleanup_thread.start()

def auth():
    jwt = request.cookies.get('jwt')
    if not jwt:
        return None
    reg = Register()
    decoded_jwt = reg.auth(jwt)
    return decoded_jwt


@app.errorhandler(404)
def not_found(e):
    return render_template(
        "404.html.j2",
        auth=auth,
        config=config
    ), 404


# Data caching functions
def cache_key_prefix():
    """Generate a cache key prefix based on current time bucket."""
    # Round to nearest minute for 60-second cache
    return datetime.datetime.now().replace(second=0, microsecond=0).timestamp()

def get_cache_timeout():
    """Get cache timeout from config."""
    return int(config.get('server', 'app_cache_timeout_seconds', fallback=60))

@cache.memoize(timeout=get_cache_timeout())
def get_cached_nodes():
    """Get nodes data with database-level caching."""
    md = get_meshdata()
    if not md:
        return None
    
    # Use the cached method to prevent duplicate dictionaries
    nodes_data = md.get_nodes_cached()
    logging.debug(f"Fetched {len(nodes_data)} nodes from application cache")
    return nodes_data

@cache.memoize(timeout=get_cache_timeout())
def get_cached_active_nodes():
    """Cache the active nodes calculation."""
    nodes = get_cached_nodes()
    if not nodes:
        return {}
    return utils.active_nodes(nodes)

@cache.memoize(timeout=get_cache_timeout())
def get_cached_latest_node():
    """Cache the latest node data."""
    md = get_meshdata()
    if not md:
        return None
    return md.get_latest_node()

@cache.memoize(timeout=get_cache_timeout())
def get_cached_message_map_data(message_id):
    """Cache the message map data for a specific message."""
    md = get_meshdata()
    if not md:
        return None
        
    # Get message and basic reception data
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.*, GROUP_CONCAT(r.received_by_id) as receiver_ids
        FROM text t
        LEFT JOIN message_reception r ON t.message_id = r.message_id
        WHERE t.message_id = %s
        GROUP BY t.message_id
    """, (message_id,))

    message_base = cursor.fetchone()
    cursor.close()

    if not message_base:
        return None

    # Get the precise message time
    message_time = message_base['ts_created'].timestamp()

    # Batch load all positions at once
    receiver_ids_list = [int(r_id) for r_id in message_base['receiver_ids'].split(',')] if message_base['receiver_ids'] else []
    node_ids = [message_base['from_id']] + receiver_ids_list
    positions = md.get_positions_at_time(node_ids, message_time)

    # Fallback: If sender position is missing, fetch it directly
    if message_base['from_id'] not in positions:
        sender_fallback = md.get_position_at_time(message_base['from_id'], message_time)
        if sender_fallback:
            positions[message_base['from_id']] = sender_fallback

    # Batch load all reception details
    reception_details = md.get_reception_details_batch(message_id, receiver_ids_list)
    
    # Ensure keys are int for lookups
    receiver_positions = {int(k): v for k, v in positions.items() if k in receiver_ids_list}
    receiver_details = {int(k): v for k, v in reception_details.items() if k in receiver_ids_list}
    sender_position = positions.get(message_base['from_id'])

    # Calculate convex hull area in square km
    points = []
    if sender_position and sender_position['latitude'] is not None and sender_position['longitude'] is not None:
        points.append((sender_position['longitude'], sender_position['latitude']))
    for pos in receiver_positions.values():
        if pos and pos['latitude'] is not None and pos['longitude'] is not None:
            points.append((pos['longitude'], pos['latitude']))
    convex_hull_area_km2 = None
    if len(points) >= 3:
        # Use shapely to calculate convex hull area
        hull = MultiPoint(points).convex_hull
        # Approximate area on Earth's surface (convert degrees to meters using haversine formula)
        # We'll use a simple equirectangular projection for small areas
        # Reference point for projection
        avg_lat = sum(lat for lon, lat in points) / len(points)
        earth_radius = 6371.0088  # km
        def latlon_to_xy(lon, lat):
            x = math.radians(lon) * earth_radius * math.cos(math.radians(avg_lat))
            y = math.radians(lat) * earth_radius
            return (x, y)
        # Handle both LineString and Polygon cases
        if hasattr(hull, 'exterior'):
            coords = hull.exterior.coords
        else:
            coords = hull.coords
        xy_points = [latlon_to_xy(lon, lat) for lon, lat in coords]
        hull_xy = MultiPoint(xy_points).convex_hull
        convex_hull_area_km2 = hull_xy.area
    
    # Prepare message object for template
    message = {
        'id': message_id,
        'from_id': message_base['from_id'],
        'to_id': message_base.get('to_id'),  # Ensure to_id is included
        'channel': message_base.get('channel'),  # Ensure channel is included
        'text': message_base['text'],
        'ts_created': message_time,
        'receiver_ids': receiver_ids_list
    }
    
    return {
        'message': message,
        'sender_position': sender_position,
        'receiver_positions': receiver_positions,
        'receiver_details': receiver_details,
        'convex_hull_area_km2': convex_hull_area_km2
    }

@app.route('/message_map.html')
def message_map():
    message_id = request.args.get('id')
    if not message_id:
        return redirect(url_for('chat'))
    
    # Get cached data
    data = get_cached_message_map_data(message_id)
    if not data:
        return redirect(url_for('chat'))
    
    # Get nodes once and create a simplified version with only needed nodes
    all_nodes = get_cached_nodes()
    
    # Create simplified nodes dict with only nodes used in this message
    used_node_ids = set()
    used_node_ids.add(utils.convert_node_id_from_int_to_hex(data['message']['from_id']))
    if data['message'].get('to_id') and data['message']['to_id'] != 4294967295:
        used_node_ids.add(utils.convert_node_id_from_int_to_hex(data['message']['to_id']))
    for receiver_id in data['message']['receiver_ids']:
        used_node_ids.add(utils.convert_node_id_from_int_to_hex(receiver_id))
    
    simplified_nodes = {}
    for node_id in used_node_ids:
        if node_id in all_nodes:
            node = all_nodes[node_id]
            simplified_nodes[node_id] = {
                'long_name': node.get('long_name', ''),
                'short_name': node.get('short_name', ''),
                'position': node.get('position')
            }
    
    # --- Provide zero_hop_links and position data for relay node inference ---
    md = get_meshdata()
    sender_id = data['message']['from_id']
    receiver_ids = data['message']['receiver_ids']
    # Get zero-hop links for the last 1 day (or configurable)
    zero_hop_timeout = 86400
    cutoff_time = int(time.time()) - zero_hop_timeout
    zero_hop_links, _ = md.get_zero_hop_links(cutoff_time)
    # Get sender and receiver positions at message time
    message_time = data['message']['ts_created']
    sender_pos = data['sender_position']
    receiver_positions = data['receiver_positions']
    # Pass the relay matcher and context to the template
    return render_template(
        "message_map.html.j2",
        auth=auth(),
        config=config,
        nodes=simplified_nodes,
        message=data['message'],
        sender_position=sender_pos,
        receiver_positions=receiver_positions,
        receiver_details=data['receiver_details'],
        convex_hull_area_km2=data['convex_hull_area_km2'],
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        find_relay_node_by_suffix=lambda relay_suffix, nodes, receiver_ids=None, sender_id=None: find_relay_node_by_suffix(
            relay_suffix, nodes, receiver_ids, sender_id, zero_hop_links=zero_hop_links, sender_pos=sender_pos, receiver_pos=None
        )
    )

@app.route('/traceroute_map.html')
def traceroute_map():
    traceroute_id = request.args.get('id')
    if not traceroute_id:
        abort(404)
        
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    # Get traceroute attempt by unique id first
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM traceroute WHERE traceroute_id = %s
    """, (traceroute_id,))
    traceroute_data = cursor.fetchone()
    if not traceroute_data:
        cursor.close()
        abort(404)
    
    # Format the forward route data
    route = []
    if traceroute_data['route']:
        route = [int(hop) for hop in traceroute_data['route'].split(';') if hop]
    
    # Format the return route data
    route_back = []
    if traceroute_data['route_back']:
        route_back = [int(hop) for hop in traceroute_data['route_back'].split(';') if hop]
    
    # Format the forward SNR values and scale by dividing by 4
    snr_towards = []
    if traceroute_data['snr_towards']:
        snr_towards = [float(s)/4.0 for s in traceroute_data['snr_towards'].split(';') if s]
    
    # Format the return SNR values and scale by dividing by 4
    snr_back = []
    if traceroute_data['snr_back']:
        snr_back = [float(s)/4.0 for s in traceroute_data['snr_back'].split(';') if s]
    
    # Create a clean traceroute object for the template
    traceroute = {
        'id': traceroute_data['traceroute_id'],
        'from_id': traceroute_data['from_id'],
        'from_id_hex': utils.convert_node_id_from_int_to_hex(traceroute_data['from_id']),
        'to_id': traceroute_data['to_id'],
        'to_id_hex': utils.convert_node_id_from_int_to_hex(traceroute_data['to_id']),
        'ts_created': traceroute_data['ts_created'],
        'route': route,
        'route_back': route_back,
        'snr_towards': snr_towards,
        'snr_back': snr_back,
        'success': traceroute_data['success']
    }
    
    cursor.close()
    
    # Get nodes and create simplified version with only needed nodes
    all_nodes = get_cached_nodes()
    used_node_ids = set([traceroute['from_id'], traceroute['to_id']] + traceroute['route'] + traceroute['route_back'])
    
    simplified_nodes = {}
    for node_id in used_node_ids:
        node_hex = utils.convert_node_id_from_int_to_hex(node_id)
        if node_hex in all_nodes:
            node = all_nodes[node_hex]
            simplified_nodes[node_hex] = {
                'long_name': node.get('long_name', ''),
                'short_name': node.get('short_name', ''),
                'position': node.get('position'),
                'ts_seen': node.get('ts_seen'),
                'role': node.get('role'),
                'owner_username': node.get('owner_username'),
                'hw_model': node.get('hw_model'),
                'firmware_version': node.get('firmware_version')
            }
    
    # --- Build traceroute_positions dict for historical accuracy ---
    node_ids = set([traceroute['from_id'], traceroute['to_id']] + traceroute['route'] + traceroute['route_back'])
    traceroute_positions = {}
    ts_created = traceroute['ts_created']
    # If ts_created is a datetime, convert to timestamp
    if hasattr(ts_created, 'timestamp'):
        ts_created = ts_created.timestamp()
    for node_id in node_ids:
        pos = md.get_position_at_time(node_id, ts_created)
        node_hex = utils.convert_node_id_from_int_to_hex(node_id)
        if not pos and node_hex in simplified_nodes and simplified_nodes[node_hex].get('position'):
            pos_obj = simplified_nodes[node_hex]['position']
            # Convert to dict if needed
            if hasattr(pos_obj, '__dict__'):
                pos = dict(pos_obj.__dict__)
            else:
                pos = dict(pos_obj)
            # Ensure position_time is present and properly formatted
            if 'position_time' not in pos or not pos['position_time']:
                if hasattr(pos_obj, 'position_time') and pos_obj.position_time:
                    pt = pos_obj.position_time
                    if isinstance(pt, datetime.datetime):
                        pos['position_time'] = pt.timestamp()
                    else:
                        pos['position_time'] = pt
                else:
                    pos['position_time'] = None
        if pos:
            traceroute_positions[node_id] = pos

    
    return render_template(
        "traceroute_map.html.j2",
        auth=auth(),
        config=config,
        nodes=simplified_nodes,
        traceroute=traceroute,
        traceroute_positions=traceroute_positions,  # <-- pass to template
        utils=utils,
        meshtastic_support=meshtastic_support,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@cache.memoize(timeout=get_cache_timeout())
def get_cached_graph_data(view_type='merged', days=1, zero_hop_timeout=43200):
    """Cache the graph data."""
    md = get_meshdata()
    if not md:
        return None
    return md.get_graph_data(view_type, days, zero_hop_timeout)

@cache.memoize(timeout=get_cache_timeout())
def get_cached_neighbors_data(view_type='neighbor_info', days=1, zero_hop_timeout=43200):
    """Cache the neighbors data."""
    md = get_meshdata()
    if not md:
        return None
    return md.get_neighbors_data(view_type, days, zero_hop_timeout)

@app.route('/graph.html')
def graph():
    view_type = request.args.get('view_type', 'merged')
    days = int(request.args.get('days', 1))
    zero_hop_timeout = int(request.args.get('zero_hop_timeout', 43200))
    
    # Get cached data
    data = get_cached_graph_data(view_type, days, zero_hop_timeout)
    if not data:
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "graph.html.j2",
        auth=auth(),
        config=config,
        graph=data,
        view_type=view_type,
        days=days,
        zero_hop_timeout=zero_hop_timeout,
        timestamp=datetime.datetime.now()
    )

@app.route('/graph2.html')
def graph2():
    view_type = request.args.get('view_type', 'merged')
    days = int(request.args.get('days', 1))
    zero_hop_timeout = int(request.args.get('zero_hop_timeout', 43200))
    
    # Get cached data
    data = get_cached_graph_data(view_type, days, zero_hop_timeout)
    if not data:
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "graph2.html.j2",
        auth=auth(),
        config=config,
        graph=data,
        view_type=view_type,
        days=days,
        zero_hop_timeout=zero_hop_timeout,
        timestamp=datetime.datetime.now()
    )

@app.route('/graph3.html')
def graph3():
    view_type = request.args.get('view_type', 'merged')
    days = int(request.args.get('days', 1))
    zero_hop_timeout = int(request.args.get('zero_hop_timeout', 43200))
    
    # Get cached data
    data = get_cached_graph_data(view_type, days, zero_hop_timeout)
    if not data:
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "graph3.html.j2",
        auth=auth(),
        config=config,
        graph=data,
        view_type=view_type,
        days=days,
        zero_hop_timeout=zero_hop_timeout,
        timestamp=datetime.datetime.now()
    )

@app.route('/graph4.html')
def graph4():
    view_type = request.args.get('view_type', 'merged')
    days = int(request.args.get('days', 1))
    zero_hop_timeout = int(request.args.get('zero_hop_timeout', 43200))
    
    # Get cached data
    data = get_cached_graph_data(view_type, days, zero_hop_timeout)
    if not data:
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "graph4.html.j2",
        auth=auth(),
        config=config,
        graph=data,
        view_type=view_type,
        days=days,
        zero_hop_timeout=zero_hop_timeout,
        timestamp=datetime.datetime.now()
    )

@app.route('/utilization-heatmap.html')
def utilization_heatmap():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "utilization-heatmap.html.j2",
        auth=auth(),
        config=config,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        Channel=meshtastic_support.Channel  # Add Channel enum to template context
    )

@app.route('/utilization-hexmap.html')
def utilization_hexmap():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "utilization-hexmap.html.j2",
        auth=auth(),
        config=config,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        Channel=meshtastic_support.Channel  # Add Channel enum to template context
    )

@app.route('/map.html')
def map():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    nodes = get_cached_nodes()
    
    # Get timeout from config
    zero_hop_timeout = int(config.get("server", "zero_hop_timeout", fallback=43200))
    cutoff_time = int(time.time()) - zero_hop_timeout
    
    # Get zero-hop data for all nodes
    cursor = md.db.cursor(dictionary=True)
    zero_hop_data = {}
    
    # Query for all zero-hop messages
    cursor.execute("""
        SELECT 
            r.from_id,
            r.received_by_id,
            COUNT(*) AS count,
            MAX(r.rx_snr) AS best_snr,
            AVG(r.rx_snr) AS avg_snr,
            MAX(r.rx_time) AS last_rx_time
        FROM 
            message_reception r
        WHERE
            (
                (r.hop_limit IS NULL AND r.hop_start IS NULL)
                OR
                (r.hop_start - r.hop_limit = 0)
            )
            AND r.rx_time > %s
        GROUP BY 
            r.from_id, r.received_by_id
        ORDER BY
            last_rx_time DESC
    """, (cutoff_time,))
    
    for row in cursor.fetchall():
        from_id = utils.convert_node_id_from_int_to_hex(row['from_id'])
        received_by_id = utils.convert_node_id_from_int_to_hex(row['received_by_id'])
        
        if from_id not in zero_hop_data:
            zero_hop_data[from_id] = {'heard': [], 'heard_by': []}
        if received_by_id not in zero_hop_data:
            zero_hop_data[received_by_id] = {'heard': [], 'heard_by': []}
            
        # Add to heard_by list of sender
        zero_hop_data[from_id]['heard_by'].append({
            'node_id': received_by_id,
            'count': row['count'],
            'best_snr': row['best_snr'],
            'avg_snr': row['avg_snr'],
            'last_rx_time': row['last_rx_time']
        })
        
        # Add to heard list of receiver
        zero_hop_data[received_by_id]['heard'].append({
            'node_id': from_id,
            'count': row['count'],
            'best_snr': row['best_snr'],
            'avg_snr': row['avg_snr'],
            'last_rx_time': row['last_rx_time']
        })
    
    cursor.close()
    
    return render_template(
        "map.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        zero_hop_data=zero_hop_data,
        zero_hop_timeout=zero_hop_timeout,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        Channel=meshtastic_support.Channel  # Add Channel enum to template context
    )

@app.route('/neighbors.html')
def neighbors():
    view_type = request.args.get('view', 'neighbor_info') # Default to neighbor_info
    md = get_meshdata()
    if not md:
        abort(503, description="Database connection unavailable")

    # Get base node data using singleton
    nodes = get_cached_nodes()
    if not nodes:
        # Handle case with no nodes gracefully
        return render_template(
            "neighbors.html.j2",
            auth=auth, config=config, nodes={},
            active_nodes_with_connections={}, view_type=view_type,
            utils=utils, datetime=datetime.datetime, timestamp=datetime.datetime.now()
        )

    # Get neighbors data using the new method
    active_nodes_data = md.get_neighbors_data(view_type=view_type)

    # Sort final results by last heard time
    active_nodes_data = dict(sorted(
        active_nodes_data.items(),
        key=lambda item: item[1].get('last_heard', datetime.datetime.min),
        reverse=True
    ))

    return render_template(
        "neighbors.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes, # Pass full nodes list for lookups in template
        active_nodes_with_connections=active_nodes_data, # Pass the processed data
        view_type=view_type,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )

@app.route('/telemetry.html')
def telemetry():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    nodes = get_cached_nodes()
    telemetry = md.get_telemetry_all()
    return render_template(
        "telemetry.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        telemetry=telemetry,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )


@app.route('/traceroutes.html')
def traceroutes():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    nodes = get_cached_nodes()
    traceroute_data = md.get_traceroutes(page=page, per_page=per_page)
    
    # Calculate pagination info
    total = traceroute_data['total']
    start_item = (page - 1) * per_page + 1 if total > 0 else 0
    end_item = min(page * per_page, total)
    
    # Create pagination info
    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'items': traceroute_data['items'],
        'pages': (total + per_page - 1) // per_page,
        'has_prev': page > 1,
        'has_next': page * per_page < total,
        'prev_num': page - 1,
        'next_num': page + 1,
        'start_item': start_item,
        'end_item': end_item
    }
    
    return render_template(
        "traceroutes.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        traceroutes=traceroute_data['items'],
        pagination=pagination,
        utils=utils,
        meshtastic_support=meshtastic_support,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        meshdata=md  # Add meshdata to template context
    )


@app.route('/logs.html')
def logs():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    # Get node filter from query parameter
    node_filter = request.args.get('node')
    
    logs = md.get_logs()
    return render_template(
        "logs.html.j2",
        auth=auth(),
        config=config,
        logs=logs,
        node_filter=node_filter,  # Pass the node filter to template
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        json=json
    )


@app.route('/monday.html')
def monday():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    nodes = get_cached_nodes()
    chat = md.get_chat()
    monday = MeshtasticMonday(chat["items"]).get_data()
    return render_template(
        "monday.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        monday=monday,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )


@app.route('/mynodes.html')
def mynodes():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    nodes = get_cached_nodes()
    owner = auth()
    if not owner:
        return redirect(url_for('login'))
    mynodes = utils.get_owner_nodes(nodes, owner["email"])
    return render_template(
        "mynodes.html.j2",
        auth=owner,
        config=config,
        nodes=mynodes,
        show_inactive=True,
        hardware=meshtastic_support.HardwareModel,
        meshtastic_support=meshtastic_support,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )


@app.route('/linknode.html')
def link_node():
    owner = auth()
    if not owner:
        return redirect(url_for('login'))
    reg = Register()
    otp = reg.get_otp(
        owner["email"]
    )
    return render_template(
        "link_node.html.j2",
        auth=owner,
        otp=otp,
        config=config
    )


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    error_message = None
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        reg = Register()
        res = reg.register(username, email, password)
        if "error" in res:
            error_message = res["error"]
        elif "success" in res:
            return serve_index(success_message=res["success"])

    return render_template(
        "register.html.j2",
        auth=auth(),
        config=config,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        error_message=error_message
    )


@app.route('/login.html', methods=['GET', 'POST'])
def login(success_message=None, error_message=None):
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        reg = Register()
        res = reg.authenticate(email, password)
        if "error" in res:
            error_message = res["error"]
        elif "success" in res:
            jwt = res["success"]
            resp = make_response(redirect(url_for('mynodes')))
            resp.set_cookie("jwt", jwt)
            return resp
    return render_template(
            "login.html.j2",
            auth=auth(),
            config=config,
            datetime=datetime.datetime,
            timestamp=datetime.datetime.now(),
            success_message=success_message,
            error_message=error_message
        )


@app.route('/logout.html')
def logout():
    resp = make_response(redirect(url_for('serve_index')))
    resp.set_cookie('jwt', '', expires=0)
    return resp


@app.route('/verify')
def verify():
    code = request.args.get('c')
    reg = Register()
    res = reg.verify_account(code)
    if "error" in res:
        return serve_index(error_message=res["error"])
    elif "success" in res:
        return login(success_message=res["success"])
    return serve_index()


@app.route('/<path:filename>')
def serve_static(filename):
    nodep = r"node\_(\w{8})\.html"
    userp = r"user\_(\w+)\.html"

    if re.match(nodep, filename):
        match = re.match(nodep, filename)
        node_hex = match.group(1)

        # Get nodes once and reuse them
        nodes = get_cached_nodes()
        if not nodes:
            abort(503, description="Database connection unavailable")
        
        # Check if node exists first
        if node_hex not in nodes:
            abort(404)

        # Get all node page data directly, bypassing the leaky application cache
        node_page_data = get_node_page_data(node_hex, nodes)

        # If data fetching fails, handle gracefully
        if not node_page_data:
            abort(503, description="Failed to retrieve node data. Please try again shortly.")

        # Render the template
        response = make_response(render_template(
            f"node.html.j2",
            auth=auth(),
            config=config,
            node=node_page_data['node'],
            linked_nodes_details=node_page_data['linked_nodes_details'],
            hardware=meshtastic_support.HardwareModel,
            meshtastic_support=meshtastic_support,
            los_profiles=node_page_data['los_profiles'],
            telemetry_graph=node_page_data['telemetry_graph'],
            node_route=node_page_data['node_route'],
            utils=utils,
            datetime=datetime.datetime,
            timestamp=datetime.datetime.now(),
            zero_hop_heard=node_page_data['zero_hop_heard'],
            zero_hop_heard_by=node_page_data['zero_hop_heard_by'],
            neighbor_heard_by=node_page_data['neighbor_heard_by'],
            zero_hop_timeout=node_page_data['zero_hop_timeout'],
            max_distance=node_page_data['max_distance_km'],
            elsewhere_links=node_page_data['elsewhere_links']
        ))
        
        # Clean up node_page_data to help with memory management
        del node_page_data
        
        # Force garbage collection to release memory immediately
        gc.collect()
        
        # Set Cache-Control header for client-side caching
        response.headers['Cache-Control'] = 'public, max-age=60'
        
        return response

    if re.match(userp, filename):
        match = re.match(userp, filename)
        username = match.group(1)
        md = get_meshdata()
        if not md: # Check if MeshData failed to initialize
            abort(503, description="Database connection unavailable")
        owner = md.get_user(username)
        if not owner:
            abort(404)
        all_nodes = get_cached_nodes()
        owner_nodes = utils.get_owner_nodes(all_nodes, owner["email"])
        return render_template(
            "user.html.j2",
            auth=auth(),
            username=username,
            config=config,
            nodes=owner_nodes,
            show_inactive=True,
            hardware=meshtastic_support.HardwareModel,
            meshtastic_support=meshtastic_support,
            utils=utils,
            datetime=datetime.datetime,
            timestamp=datetime.datetime.now(),
        )

    return send_from_directory("www", filename)


@app.route('/metrics.html')
@cache.cached(timeout=60)  # Cache for 60 seconds
def metrics():
    return render_template(
        "metrics.html.j2",
        auth=auth(),
        config=config,
        Channel=meshtastic_support.Channel,
        utils=utils
    )

@app.route('/api/metrics')
def get_metrics():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    try:
        # Get time range from request parameters
        time_range = request.args.get('time_range', 'day')  # day, week, month, year, all
        channel = request.args.get('channel', 'all')  # Get channel parameter
        
        # Set time range based on parameter
        end_time = datetime.datetime.now()
        if time_range == 'week':
            start_time = end_time - datetime.timedelta(days=7)
            bucket_size = 180  # 3 hours in minutes
        elif time_range == 'month':
            start_time = end_time - datetime.timedelta(days=30)
            bucket_size = 720  # 12 hours in minutes
        elif time_range == 'year':
            start_time = end_time - datetime.timedelta(days=365)
            bucket_size = 2880  # 2 days in minutes
        elif time_range == 'all':
            # For 'all', we'll first check the data range in the database
            cursor = md.db.cursor(dictionary=True)
            cursor.execute("SELECT MIN(ts_created) as min_time FROM telemetry")
            min_time = cursor.fetchone()['min_time']
            cursor.close()
            
            if min_time:
                start_time = min_time
            else:
                # Default to 1 year if no data
                start_time = end_time - datetime.timedelta(days=365)
            
            bucket_size = 10080  # 7 days in minutes
        else:  # Default to 'day'
            start_time = end_time - datetime.timedelta(hours=24)
            bucket_size = 30  # 30 minutes
        
        # Convert timestamps to the correct format for MySQL
        start_timestamp = start_time.strftime('%Y-%m-%d %H:%M:%S')
        end_timestamp = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Format string for time buckets based on bucket size
        if bucket_size >= 10080:  # 7 days or more
            time_format = '%Y-%m-%d'  # Daily format
        elif bucket_size >= 1440:  # 1 day or more
            time_format = '%Y-%m-%d %H:00'  # Hourly format
        else:
            time_format = '%Y-%m-%d %H:%i'  # Minute format
        
        cursor = md.db.cursor(dictionary=True)
        
        # First, generate a series of time slots
        time_slots_query = f"""
            WITH RECURSIVE time_slots AS (
                SELECT DATE_FORMAT(
                    DATE_ADD(%s, INTERVAL -MOD(MINUTE(%s), {bucket_size}) MINUTE),
                    '{time_format}'
                ) as time_slot
                UNION ALL
                SELECT DATE_FORMAT(
                    DATE_ADD(
                        STR_TO_DATE(time_slot, '{time_format}'),
                        INTERVAL {bucket_size} MINUTE
                    ),
                    '{time_format}'
                )
                FROM time_slots
                WHERE DATE_ADD(
                    STR_TO_DATE(time_slot, '{time_format}'),
                    INTERVAL {bucket_size} MINUTE
                ) <= %s
            )
            SELECT time_slot FROM time_slots
        """
        cursor.execute(time_slots_query, (start_timestamp, start_timestamp, end_timestamp))
        time_slots = [row['time_slot'] for row in cursor.fetchall()]
        
        # Add channel condition if specified
        channel_condition = ""
        if channel != 'all':
            # Only apply channel condition to tables that have a channel column
            channel_condition_text = f" AND channel = {channel}"
            channel_condition_telemetry = f" AND channel = {channel}"
            channel_condition_reception = f" AND EXISTS (SELECT 1 FROM text t WHERE t.message_id = message_reception.message_id AND t.channel = {channel})"
        else:
            channel_condition_text = ""
            channel_condition_telemetry = ""
            channel_condition_reception = ""
        
        # Nodes Online Query
        nodes_online_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                COUNT(DISTINCT id) as node_count
            FROM telemetry
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_telemetry}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(nodes_online_query, (start_timestamp, end_timestamp))
        nodes_online_data = {row['time_slot']: row['node_count'] for row in cursor.fetchall()}
        
        # Message Traffic Query
        message_traffic_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                COUNT(*) as message_count
            FROM text
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_text}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(message_traffic_query, (start_timestamp, end_timestamp))
        message_traffic_data = {row['time_slot']: row['message_count'] for row in cursor.fetchall()}
        
        # Channel Utilization Query
        channel_util_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                AVG(channel_utilization) as avg_util
            FROM telemetry
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_telemetry}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(channel_util_query, (start_timestamp, end_timestamp))
        channel_util_data = {row['time_slot']: float(row['avg_util']) if row['avg_util'] is not None else 0.0 for row in cursor.fetchall()}
        
        # Battery Levels Query
        battery_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                AVG(battery_level) as avg_battery
            FROM telemetry
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_telemetry}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(battery_query, (start_timestamp, end_timestamp))
        battery_data = {row['time_slot']: float(row['avg_battery']) if row['avg_battery'] is not None else 0.0 for row in cursor.fetchall()}
        
        # Temperature Query
        temperature_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                AVG(temperature) as avg_temp
            FROM telemetry
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_telemetry}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(temperature_query, (start_timestamp, end_timestamp))
        temperature_data = {row['time_slot']: float(row['avg_temp']) if row['avg_temp'] is not None else 0.0 for row in cursor.fetchall()}
        
        # SNR Query
        snr_query = f"""
            SELECT 
                DATE_FORMAT(
                    DATE_ADD(
                        ts_created,
                        INTERVAL -MOD(MINUTE(ts_created), {bucket_size}) MINUTE
                    ),
                    '{time_format}'
                ) as time_slot,
                AVG(rx_snr) as avg_snr
            FROM message_reception
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_reception}
            GROUP BY time_slot
            ORDER BY time_slot
        """
        cursor.execute(snr_query, (start_timestamp, end_timestamp))
        snr_data = {row['time_slot']: float(row['avg_snr']) if row['avg_snr'] is not None else 0.0 for row in cursor.fetchall()}
        
        cursor.close()
        
        # --- Moving Average Helper ---
        def moving_average_centered(data_list, window_minutes, bucket_size_minutes):
            # data_list: list of floats (same order as time_slots)
            # window_minutes: total window size (e.g., 120 for 2 hours)
            # bucket_size_minutes: size of each bucket (e.g., 30 for 30 min)
            n = len(data_list)
            result = []
            half_window = window_minutes // 2
            buckets_per_window = max(1, window_minutes // bucket_size_minutes)
            for i in range(n):
                # Centered window: find all indices within window centered at i
                center_time = i
                window_indices = []
                for j in range(n):
                    if abs(j - center_time) * bucket_size_minutes <= half_window:
                        window_indices.append(j)
                if window_indices:
                    avg = sum(data_list[j] for j in window_indices) / len(window_indices)
                else:
                    avg = data_list[i]
                result.append(avg)
            return result

        # --- Get metrics_average_interval from config ---
        metrics_avg_interval = int(config.get('server', 'metrics_average_interval', fallback=7200))  # seconds
        metrics_avg_minutes = metrics_avg_interval // 60

        # --- Calculate moving averages for relevant metrics ---
        # Determine bucket_size_minutes from bucket_size
        bucket_size_minutes = bucket_size

        # Prepare raw data lists
        nodes_online_raw = [nodes_online_data.get(slot, 0) for slot in time_slots]
        battery_levels_raw = [battery_data.get(slot, 0) for slot in time_slots]
        temperature_raw = [temperature_data.get(slot, 0) for slot in time_slots]
        snr_raw = [snr_data.get(slot, 0) for slot in time_slots]

        # --- Get node_activity_prune_threshold from config ---
        node_activity_prune_threshold = int(config.get('server', 'node_activity_prune_threshold', fallback=7200))  # seconds

        # --- For each time slot, count unique nodes heard in the preceding activity window ---
        # Fetch all telemetry records in the full time range
        cursor = md.db.cursor(dictionary=True)
        cursor.execute(f"""
            SELECT id, ts_created
            FROM telemetry
            WHERE ts_created >= %s AND ts_created <= %s {channel_condition_telemetry}
            ORDER BY ts_created
        """, (start_timestamp, end_timestamp))
        all_telemetry = list(cursor.fetchall())
        # Convert ts_created to datetime for easier comparison
        for row in all_telemetry:
            if isinstance(row['ts_created'], str):
                row['ts_created'] = datetime.datetime.strptime(row['ts_created'], '%Y-%m-%d %H:%M:%S')
        # Precompute for each time slot
        nodes_heard_per_slot = []
        for slot in time_slots:
            # slot is a string, convert to datetime
            if '%H:%M' in time_format or '%H:%i' in time_format:
                slot_time = datetime.datetime.strptime(slot, '%Y-%m-%d %H:%M')
            elif '%H:00' in time_format:
                slot_time = datetime.datetime.strptime(slot, '%Y-%m-%d %H:%M')
            else:
                slot_time = datetime.datetime.strptime(slot, '%Y-%m-%d')
            window_start = slot_time - datetime.timedelta(seconds=node_activity_prune_threshold)
            # Find all node ids with telemetry in [window_start, slot_time]
            active_nodes = set()
            for row in all_telemetry:
                if window_start < row['ts_created'] <= slot_time:
                    active_nodes.add(row['id'])
            nodes_heard_per_slot.append(len(active_nodes))
        # Now apply moving average and round to nearest integer
        nodes_online_smoothed = [round(x) for x in moving_average_centered(nodes_heard_per_slot, metrics_avg_minutes, bucket_size_minutes)]

        # Fill in missing time slots with zeros (for non-averaged metrics)
        result = {
            'nodes_online': {
                'labels': time_slots,
                'data': nodes_online_smoothed
            },
            'message_traffic': {
                'labels': time_slots,
                'data': [message_traffic_data.get(slot, 0) for slot in time_slots]
            },
            'channel_util': {
                'labels': time_slots,
                'data': [channel_util_data.get(slot, 0) for slot in time_slots]
            },
            'battery_levels': {
                'labels': time_slots,
                'data': moving_average_centered(battery_levels_raw, metrics_avg_minutes, bucket_size_minutes)
            },
            'temperature': {
                'labels': time_slots,
                'data': moving_average_centered(temperature_raw, metrics_avg_minutes, bucket_size_minutes)
            },
            'snr': {
                'labels': time_slots,
                'data': moving_average_centered(snr_raw, metrics_avg_minutes, bucket_size_minutes)
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error fetching metrics data: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'Error fetching metrics data: {str(e)}'
        }), 500

@app.route('/api/chattiest-nodes')
def get_chattiest_nodes():
    md = get_meshdata()
    if not md:  # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    # Get filter parameters from request
    time_frame = request.args.get('time_frame', 'day')  # day, week, month, year, all
    message_type = request.args.get('message_type', 'all')  # all, text, position, telemetry
    channel = request.args.get('channel', 'all')  # all or specific channel number
    
    try:
        cursor = md.db.cursor(dictionary=True)
        
        # Build the time frame condition
        time_condition = ""
        if time_frame == 'year':
            time_condition = "WHERE ts_created >= DATE_SUB(NOW(), INTERVAL 1 YEAR)"
        elif time_frame == 'month':
            time_condition = "WHERE ts_created >= DATE_SUB(NOW(), INTERVAL 1 MONTH)"
        elif time_frame == 'week':
            time_condition = "WHERE ts_created >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        elif time_frame == 'day':
            time_condition = "WHERE ts_created >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        
        # Add channel filter if specified - only for text and telemetry tables which have channel column
        channel_condition_text = ""
        channel_condition_telemetry = ""
        if channel != 'all':
            channel_condition_text = f" AND channel = {channel}"
            channel_condition_telemetry = f" AND channel = {channel}"
            if not time_condition:
                channel_condition_text = f"WHERE channel = {channel}"
                channel_condition_telemetry = f"WHERE channel = {channel}"
        
        # Build the message type query based on the selected type
        if message_type == 'all':
            # For text messages, we need to qualify the columns with table aliases
            time_condition_with_prefix = time_condition.replace("WHERE", "WHERE t.").replace(" AND", " AND t.")
            channel_condition_text_with_prefix = channel_condition_text.replace("WHERE", "WHERE t.").replace(" AND", " AND t.")
            
            message_query = (
                "SELECT t.from_id as node_id, t.ts_created, t.channel as channel "
                "FROM text t "
                + time_condition_with_prefix 
                + channel_condition_text_with_prefix + " "
                "UNION ALL "
                "SELECT id as node_id, ts_created, NULL as channel "
                "FROM positionlog "
                + time_condition + " "
                "UNION ALL "
                "SELECT id as node_id, ts_created, channel "
                "FROM telemetry "
                + time_condition 
                + channel_condition_telemetry
            )
        elif message_type == 'text':
            message_query = (
                "SELECT from_id as node_id, ts_created, channel "
                "FROM text "
                + time_condition
                + channel_condition_text
            )
        elif message_type == 'position':
            message_query = (
                "SELECT id as node_id, ts_created, NULL as channel "
                "FROM positionlog "
                + time_condition
            )
        elif message_type == 'telemetry':
            message_query = (
                "SELECT id as node_id, ts_created, channel "
                "FROM telemetry "
                + time_condition
                + channel_condition_telemetry
            )
        else:
            return jsonify({
                'error': f'Invalid message type: {message_type}'
            }), 400
        
        # Query to get the top 20 nodes by message count, including node names and role
        query = """
            WITH messages AS ({message_query})
            SELECT 
                m.node_id as from_id,
                n.long_name,
                n.short_name,
                n.role,
                COUNT(*) as message_count,
                COUNT(DISTINCT DATE_FORMAT(m.ts_created, '%Y-%m-%d')) as active_days,
                MIN(m.ts_created) as first_message,
                MAX(m.ts_created) as last_message,
                CASE 
                    WHEN '{channel}' != 'all' THEN '{channel}'
                    ELSE GROUP_CONCAT(DISTINCT NULLIF(CAST(m.channel AS CHAR), 'NULL'))
                END as channels,
                CASE 
                    WHEN '{channel}' != 'all' THEN 1
                    ELSE COUNT(DISTINCT NULLIF(m.channel, 'NULL'))
                END as channel_count
            FROM 
                messages m
            LEFT JOIN
                nodeinfo n ON m.node_id = n.id
            GROUP BY 
                m.node_id, n.long_name, n.short_name, n.role
            ORDER BY 
                message_count DESC
            LIMIT 20
        """.format(message_query=message_query, channel=channel)
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        # Process the results to format them for the frontend
        chattiest_nodes = []
        for row in results:
            # Convert node ID to hex format
            node_id_hex = utils.convert_node_id_from_int_to_hex(row['from_id'])
            
            # Parse channels string into a list of channel objects
            channels_str = row['channels']
            channels = []
            if channels_str:
                # If we're filtering by channel, just use that channel
                if channel != 'all':
                    channels.append({
                        'id': int(channel),
                        'name': utils.get_channel_name(int(channel)),
                        'color': utils.get_channel_color(int(channel))
                    })
                else:
                    # Otherwise process the concatenated list of channels
                    channel_ids = [ch_id for ch_id in channels_str.split(',') if ch_id and ch_id != 'NULL']
                    for ch_id in channel_ids:
                        try:
                            ch_id_int = int(ch_id)
                            channels.append({
                                'id': ch_id_int,
                                'name': utils.get_channel_name(ch_id_int),
                                'color': utils.get_channel_color(ch_id_int)
                            })
                        except (ValueError, TypeError):
                            continue
            
            # Create node object
            node = {
                'node_id': row['from_id'],
                'node_id_hex': node_id_hex,
                'long_name': row['long_name'] or f"Node {row['from_id']}",  # Fallback if no long name
                'short_name': row['short_name'] or f"Node {row['from_id']}",  # Fallback if no short name
                'role': utils.get_role_name(row['role']),  # Convert role number to name
                'message_count': row['message_count'],
                'active_days': row['active_days'],
                'first_message': row['first_message'].isoformat() if row['first_message'] else None,
                'last_message': row['last_message'].isoformat() if row['last_message'] else None,
                'channels': channels,
                'channel_count': row['channel_count']
            }
            chattiest_nodes.append(node)
        
        return jsonify({
            'chattiest_nodes': chattiest_nodes
        })
        
    except Exception as e:
        logging.error(f"Error fetching chattiest nodes: {str(e)}")
        return jsonify({
            'error': f'Error fetching chattiest nodes: {str(e)}'
        }), 500
    finally:
        if cursor:
            cursor.close()

@app.route('/api/telemetry/<int:node_id>')
def api_telemetry(node_id):
    md = get_meshdata()
    telemetry = md.get_telemetry_for_node(node_id)
    return jsonify(telemetry)

@app.route('/api/environmental-telemetry/<int:node_id>')
def api_environmental_telemetry(node_id):
    md = get_meshdata()
    days = request.args.get('days', 1, type=int)
    # Limit days to reasonable range (1-30 days)
    days = max(1, min(30, days))
    telemetry = md.get_environmental_telemetry_for_node(node_id, days)
    return jsonify(telemetry)

@cache.memoize(timeout=get_cache_timeout())
def get_cached_chat_data(page=1, per_page=50):
    """Cache the chat data with optimized query."""
    md = get_meshdata()
    if not md:
        return None
    
    # Get total count first (this is fast)
    cur = md.db.cursor()
    cur.execute("SELECT COUNT(DISTINCT t.message_id) FROM text t")
    total = cur.fetchone()[0]
    cur.close()
    
    # Get paginated chat messages (without reception data)
    offset = (page - 1) * per_page
    cur = md.db.cursor(dictionary=True)
    cur.execute("""
        SELECT t.* FROM text t
        ORDER BY t.ts_created DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    messages = cur.fetchall()
    cur.close()
    
    # Get reception data for these messages in a separate query
    if messages:
        message_ids = [msg['message_id'] for msg in messages]
        placeholders = ','.join(['%s'] * len(message_ids))
        cur = md.db.cursor(dictionary=True)
        cur.execute(f"""
            SELECT message_id, received_by_id, rx_snr, rx_rssi, hop_limit, hop_start, rx_time
            FROM message_reception
            WHERE message_id IN ({placeholders})
        """, message_ids)
        receptions = cur.fetchall()
        cur.close()
        
        # Group receptions by message_id
        receptions_by_message = {}
        for reception in receptions:
            msg_id = reception['message_id']
            if msg_id not in receptions_by_message:
                receptions_by_message[msg_id] = []
            receptions_by_message[msg_id].append({
                "node_id": reception['received_by_id'],
                "rx_snr": float(reception['rx_snr']) if reception['rx_snr'] is not None else 0,
                "rx_rssi": int(reception['rx_rssi']) if reception['rx_rssi'] is not None else 0,
                "hop_limit": int(reception['hop_limit']) if reception['hop_limit'] is not None else None,
                "hop_start": int(reception['hop_start']) if reception['hop_start'] is not None else None,
                "rx_time": reception['rx_time'].timestamp() if isinstance(reception['rx_time'], datetime.datetime) else reception['rx_time']
            })
    else:
        receptions_by_message = {}
    
    # Process messages
    chats = []
    prev_key = ""
    for row in messages:
        record = {}
        for key, value in row.items():
            if isinstance(value, datetime.datetime):
                record[key] = value.timestamp()
            else:
                record[key] = value
        
        # Add reception data
        record["receptions"] = receptions_by_message.get(record['message_id'], [])
        
        # Convert IDs to hex
        record["from"] = utils.convert_node_id_from_int_to_hex(record["from_id"])
        record["to"] = utils.convert_node_id_from_int_to_hex(record["to_id"])
        
        # Deduplicate messages
        msg_key = f"{record['from']}{record['to']}{record['text']}{record['message_id']}"
        if msg_key != prev_key:
            chats.append(record)
            prev_key = msg_key
    
    return {
        "items": chats,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
        "has_prev": page > 1,
        "has_next": page * per_page < total,
        "prev_num": page - 1,
        "next_num": page + 1
    }

def get_node_page_data(node_hex, all_nodes=None):
    """Fetch and process all data for the node page to prevent memory leaks."""
    md = get_meshdata()
    if not md: return None

    # Use provided nodes or fetch them if not provided
    if all_nodes is None:
        all_nodes = get_cached_nodes()
    if not all_nodes or node_hex not in all_nodes:
        return None

    current_node = all_nodes[node_hex]
    node_id = current_node['id']

    # Get LOS configuration early
    los_enabled = config.getboolean("los", "enabled", fallback=False)
    zero_hop_timeout = int(config.get("server", "zero_hop_timeout", fallback=43200))
    max_distance_km = int(config.get("los", "max_distance", fallback=5000)) / 1000
    cutoff_time = int(time.time()) - zero_hop_timeout

    # --- Fetch all raw data ---
    node_telemetry = md.get_node_telemetry(node_id)
    node_route = md.get_route_coordinates(node_id)
    telemetry_graph = draw_graph(node_telemetry)
    neighbor_heard_by = md.get_heard_by_from_neighbors(node_id)
    
    # Only process LOS if enabled
    los_profiles = {}
    if los_enabled:
        # Create a minimal nodes dict for LOSProfile with only the current node and its neighbors
        los_nodes = {}
        los_nodes[node_hex] = current_node
        
        # Add only the nodes that are within LOS distance and have positions
        max_distance = int(config.get("los", "max_distance", fallback=5000))
        for other_hex, other_node in all_nodes.items():
            if other_hex == node_hex:
                continue
            if not other_node.get('position'):
                continue
            # Calculate distance and only include if within range
            try:
                my_pos = current_node.get('position', {})
                other_pos = other_node.get('position', {})
                if my_pos.get('latitude') and my_pos.get('longitude') and other_pos.get('latitude') and other_pos.get('longitude'):
                    dist = utils.distance_between_two_points(
                        my_pos['latitude'], my_pos['longitude'],
                        other_pos['latitude'], other_pos['longitude']
                    ) * 1000  # Convert to meters
                    if dist < max_distance:
                        los_nodes[other_hex] = other_node
            except:
                continue
        
        lp = LOSProfile(los_nodes, node_id, config, cache)
        
        # Get LOS profiles and clean up the LOSProfile instance
        try:
            los_profiles = lp.get_profiles()
        finally:
            # Explicitly clean up the LOSProfile instance to release memory
            if hasattr(lp, 'close_datasets'):
                lp.close_datasets()
            del lp
            del los_nodes

    cursor = md.db.cursor(dictionary=True)
    # Query for zero-hop messages heard by this node
    cursor.execute("""
        SELECT r.from_id, COUNT(*) AS count, MAX(r.rx_snr) AS best_snr,
               AVG(r.rx_snr) AS avg_snr, MAX(r.rx_time) AS last_rx_time
        FROM message_reception r
        WHERE r.received_by_id = %s AND ((r.hop_limit IS NULL AND r.hop_start IS NULL) OR (r.hop_start - r.hop_limit = 0))
          AND r.rx_time > %s
        GROUP BY r.from_id ORDER BY last_rx_time DESC
    """, (node_id, cutoff_time))
    zero_hop_heard = cursor.fetchall()

    # Query for zero-hop messages sent by this node
    cursor.execute("""
        SELECT r.received_by_id, COUNT(*) AS count, MAX(r.rx_snr) AS best_snr,
               AVG(r.rx_snr) AS avg_snr, MAX(r.rx_time) AS last_rx_time
        FROM message_reception r
        WHERE r.from_id = %s AND ((r.hop_limit IS NULL AND r.hop_start IS NULL) OR (r.hop_start - r.hop_limit = 0))
          AND r.rx_time > %s
        GROUP BY r.received_by_id ORDER BY last_rx_time DESC
    """, (node_id, cutoff_time))
    zero_hop_heard_by = cursor.fetchall()
    cursor.close()

    # --- Create a lean dictionary of only the linked nodes needed by the template ---
    linked_node_ids = set()
    if 'neighbors' in current_node:
        for neighbor in current_node.get('neighbors', []):
            linked_node_ids.add(neighbor['neighbor_id'])
    for heard in zero_hop_heard:
        linked_node_ids.add(heard['from_id'])
    for neighbor in neighbor_heard_by:
        linked_node_ids.add(neighbor['id'])
    for heard in zero_hop_heard_by:
        linked_node_ids.add(heard['received_by_id'])
    if current_node.get('updated_via'):
        linked_node_ids.add(current_node.get('updated_via'))
        
    linked_nodes_details = {}
    for linked_id_int in linked_node_ids:
        if not linked_id_int: continue
        nid_hex = utils.convert_node_id_from_int_to_hex(linked_id_int)
        node_data = all_nodes.get(nid_hex)
        if node_data:
            # Copy only the fields required by the template
            linked_nodes_details[nid_hex] = {
                'short_name': node_data.get('short_name'),
                'long_name': node_data.get('long_name'),
                'position': node_data.get('position')
            }

    # Build elsewhere links
    node_hex_id = utils.convert_node_id_from_int_to_hex(node_id)
    elsewhere_links = get_elsewhere_links(node_id, node_hex_id)
    
    # Return a dictionary that does NOT include the full `all_nodes` object
    return {
        'node': current_node,
        'linked_nodes_details': linked_nodes_details,
        'telemetry_graph': telemetry_graph,
        'node_route': node_route,
        'los_profiles': los_profiles,
        'neighbor_heard_by': neighbor_heard_by,
        'zero_hop_heard': zero_hop_heard,
        'zero_hop_heard_by': zero_hop_heard_by,
        'zero_hop_timeout': zero_hop_timeout,
        'max_distance_km': max_distance_km,
        'elsewhere_links': elsewhere_links,
    }

@app.route('/chat-classic.html')
def chat():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
        
    chat_data = get_cached_chat_data(page, per_page)
    if not chat_data:
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "chat.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        chat=chat_data["items"],
        pagination=chat_data,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        debug=False,
    )

@cache.memoize(timeout=get_cache_timeout())  # Cache for 5 minutes
def calculate_node_distance(node1_hex, node2_hex):
    """Calculate distance between two nodes, cached to avoid repeated calculations."""
    nodes = get_cached_nodes()
    if not nodes:
        return None
    
    node1 = nodes.get(node1_hex)
    node2 = nodes.get(node2_hex)
    
    if not node1 or not node2:
        return None
    
    if not node1.get("position") or not node2.get("position"):
        return None
    
    return utils.calculate_distance_between_nodes(node1, node2)

@app.route('/chat.html')
def chat2():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
        
    chat_data = get_cached_chat_data(page, per_page)
    if not chat_data:
        abort(503, description="Database connection unavailable")
    
    # Pre-process nodes to reduce template complexity
    # Only include nodes that are actually used in the chat messages
    used_node_ids = set()
    for message in chat_data["items"]:
        used_node_ids.add(message["from"])
        if message["to"] != "ffffffff":
            used_node_ids.add(message["to"])
        for reception in message.get("receptions", []):
            node_id = utils.convert_node_id_from_int_to_hex(reception["node_id"])
            used_node_ids.add(node_id)
    
    # Create simplified nodes dict with only needed data
    simplified_nodes = {}
    for node_id in used_node_ids:
        if node_id in nodes:
            node = nodes[node_id]
            simplified_nodes[node_id] = {
                'long_name': node.get('long_name', ''),
                'short_name': node.get('short_name', ''),
                'hw_model': node.get('hw_model'),
                'hw_model_name': meshtastic_support.get_hardware_model_name(node.get('hw_model')) if node.get('hw_model') else None,
                'role': node.get('role'),
                'role_name': utils.get_role_name(node.get('role')) if node.get('role') is not None else None,
                'firmware_version': node.get('firmware_version'),
                'owner_username': node.get('owner_username'),
                'owner': node.get('owner'),
                'position': node.get('position'),
                'telemetry': node.get('telemetry'),
                'ts_seen': node.get('ts_seen')
            }
    
    return render_template(
        "chat2.html.j2",
        auth=auth(),
        config=config,
        nodes=simplified_nodes,
        chat=chat_data["items"],
        pagination=chat_data,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        meshtastic_support=meshtastic_support,
        debug=False,
    )

@app.route('/')
def serve_index(success_message=None, error_message=None):
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
    
    active_nodes = get_cached_active_nodes()
    
    return render_template(
        "index.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        active_nodes=active_nodes,
        timestamp=datetime.datetime.now(),
        success_message=success_message,
        error_message=error_message
    )

@app.route('/nodes.html')
def nodes():
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
    latest = get_cached_latest_node()
    logging.info(f"/nodes.html: Loaded {len(nodes)} nodes.")
    
    # Get hardware model filter from query parameters
    hw_model_filter = request.args.get('hw_model')
    hw_name_filter = request.args.get('hw_name')
    
    return render_template(
        "nodes.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        show_inactive=False,
        latest=latest,
        hw_model_filter=hw_model_filter,
        hw_name_filter=hw_name_filter,
        hardware=meshtastic_support.HardwareModel,
        meshtastic_support=meshtastic_support,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@app.route('/allnodes.html')
def allnodes():
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
    latest = get_cached_latest_node()
    logging.info(f"/allnodes.html: Loaded {len(nodes)} nodes.")
    
    # Get hardware model filter from query parameters
    hw_model_filter = request.args.get('hw_model')
    hw_name_filter = request.args.get('hw_name')
    
    return render_template(
        "allnodes.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        show_inactive=True,
        latest=latest,
        hw_model_filter=hw_model_filter,
        hw_name_filter=hw_name_filter,
        hardware=meshtastic_support.HardwareModel,
        meshtastic_support=meshtastic_support,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@app.route('/api/debug/memory')
def debug_memory():
    """Manual trigger for detailed memory analysis."""
    if not auth():
        abort(401)
    
    log_memory_usage(force=True)
    log_detailed_memory_analysis()
    
    return jsonify({
        'status': 'success',
        'message': 'Memory analysis completed. Check logs for details.'
    })

@app.route('/api/debug/cache')
def debug_cache():
    """Manual trigger for cache analysis."""
    if not auth():
        abort(401)
    
    log_cache_stats()
    
    return jsonify({
        'status': 'success',
        'message': 'Cache analysis completed. Check logs for details.'
    })

@app.route('/api/debug/cleanup')
def debug_cleanup():
    """Manual trigger for cache cleanup."""
    if not auth():
        abort(401)
    
    try:
        # Check database privileges first
        config = configparser.ConfigParser()
        config.read('config.ini')
        db_cache = DatabaseCache(config)
        privileges = db_cache.check_privileges()
        
        # Perform cleanup operations
        cleanup_cache()
        
        # Also clear nodes cache and force garbage collection
        clear_nodes_cache()
        clear_database_cache()
        gc.collect()
        
        # Prepare response message
        if privileges['reload']:
            message = 'Cache cleanup completed successfully. Database query cache cleared.'
        else:
            message = 'Cache cleanup completed. Note: Database query cache could not be cleared due to insufficient privileges (RELOAD required).'
        
        return jsonify({
            'status': 'success',
            'message': message,
            'database_privileges': privileges
        })
        
    except Exception as e:
        logging.error(f"Error during debug cleanup: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error during cache cleanup: {str(e)}'
        }), 500

@app.route('/api/debug/clear-nodes')
def debug_clear_nodes():
    """Manual trigger to clear nodes cache."""
    if not auth():
        abort(401)
    
    clear_nodes_cache()
    clear_database_cache()
    gc.collect()
    
    return jsonify({
        'status': 'success',
        'message': 'Nodes cache cleared. Check logs for details.'
    })

@app.route('/api/debug/database-cache')
def debug_database_cache():
    """Manual trigger for database cache analysis."""
    if not auth():
        abort(401)
    
    try:
        # Check database privileges
        config = configparser.ConfigParser()
        config.read('config.ini')
        db_cache = DatabaseCache(config)
        privileges = db_cache.check_privileges()
        
        md = get_meshdata()
        if md and hasattr(md, 'db_cache'):
            stats = md.db_cache.get_cache_stats()
            
            # Get application cache info
            app_cache_info = {}
            if hasattr(md, '_nodes_cache'):
                app_cache_info = {
                    'cache_entries': len(md._nodes_cache),
                    'cache_keys': list(md._nodes_cache.keys()),
                    'cache_timestamps': {k: v['timestamp'] for k, v in md._nodes_cache.items()}
                }
            
            return jsonify({
                'status': 'success',
                'database_cache_stats': stats,
                'application_cache_info': app_cache_info,
                'database_privileges': privileges
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Database cache not available',
                'database_privileges': privileges
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error getting database cache stats: {e}'
        })

@app.route('/api/geocode')
def api_geocode():
    """API endpoint for reverse geocoding to avoid CORS issues."""
    try:
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        
        if lat is None or lon is None:
            return jsonify({'error': 'Missing lat or lon parameters'}), 400
        
        # Use the existing geocoding function from utils
        geocoded = utils.geocode_position(
            config.get('geocoding', 'apikey', fallback=''),
            lat,
            lon
        )
        
        if geocoded:
            return jsonify(geocoded)
        else:
            return jsonify({'error': 'Geocoding failed'}), 500
            
    except Exception as e:
        logging.error(f"Geocoding error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@cache.memoize(timeout=get_cache_timeout())  # Cache for 5 minutes
def get_node_positions_batch(node_ids):
    """Get position data for multiple nodes efficiently."""
    nodes = get_cached_nodes()
    if not nodes:
        return {}
    
    positions = {}
    for node_id in node_ids:
        if node_id in nodes:
            node = nodes[node_id]
            if node.get('position') and node['position'].get('latitude') and node['position'].get('longitude'):
                positions[node_id] = {
                    'latitude': node['position']['latitude'],
                    'longitude': node['position']['longitude']
                }
    
    return positions

@app.route('/api/node-positions')
def api_node_positions():
    """API endpoint to get position data for specific nodes for client-side distance calculations."""
    try:
        # Get list of node IDs from query parameter
        node_ids = request.args.get('nodes', '').split(',')
        node_ids = [nid.strip() for nid in node_ids if nid.strip()]
        
        if not node_ids:
            return jsonify({'positions': {}})
        
        # Use the cached batch function
        positions = get_node_positions_batch(tuple(node_ids))  # Convert to tuple for caching
        
        return jsonify({'positions': positions})
        
    except Exception as e:
        logging.error(f"Error fetching node positions: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def run():
    # Enable Waitress logging
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = int(config["webserver"]["port"])

    waitress_logger = logging.getLogger("waitress")
    waitress_logger.setLevel(logging.DEBUG)  # Enable all logs from Waitress
    
    # Configure Waitress to trust proxy headers for real IP addresses
    # This is needed when running behind Docker, nginx, or other reverse proxies
    serve(
        TransLogger(
            app,
            setup_console_handler=False,
            logger=waitress_logger
        ),
        port=port,
        trusted_proxy='127.0.0.1,::1,172.16.0.0/12,192.168.0.0/16,10.0.0.0/8',  # Trust Docker and local networks
        trusted_proxy_count=1,  # Trust one level of proxy (Docker)
        trusted_proxy_headers={
            'x-forwarded-for': 'X-Forwarded-For',
            'x-forwarded-proto': 'X-Forwarded-Proto',
            'x-forwarded-host': 'X-Forwarded-Host',
            'x-forwarded-port': 'X-Forwarded-Port'
        }
    )

def clear_nodes_cache():
    """Clear nodes-related cache entries."""
    try:
        cache.delete_memoized(get_cached_nodes)
        cache.delete_memoized(get_cached_active_nodes)
        cache.delete_memoized(get_cached_message_map_data)
        cache.delete_memoized(get_cached_graph_data)
        cache.delete_memoized(get_cached_neighbors_data)
        logging.info("Cleared nodes-related cache entries")
    except Exception as e:
        logging.error(f"Error clearing nodes-related cache: {e}")

def clear_database_cache():
    """Clear database query cache."""
    try:
        # Try to get meshdata with app context first
        try:
            md = get_meshdata()
            if md and hasattr(md, 'db_cache'):
                md.db_cache.clear_query_cache()
                logging.info("Cleared database query cache")
            if md:
                md.clear_nodes_cache()
                logging.info("Cleared application nodes cache")
        except RuntimeError as e:
            # If we're outside app context, clear cache directly
            if "application context" in str(e):
                logging.info("Outside app context, clearing cache directly")
                # Clear database cache directly without app context
                config = configparser.ConfigParser()
                config.read('config.ini')
                db_cache = DatabaseCache(config)
                db_cache.clear_query_cache()
                logging.info("Cleared database query cache (direct)")
            else:
                raise
    except Exception as e:
        logging.error(f"Error clearing database cache: {e}")

def find_relay_node_by_suffix(relay_suffix, nodes, receiver_ids=None, sender_id=None, zero_hop_links=None, sender_pos=None, receiver_pos=None, debug=False):
    """
    Improved relay node matcher: prefer zero-hop/extended neighbors, then select the physically closest candidate to the sender (or receiver), using scoring only as a tiebreaker.
    """
    import time
    relay_suffix = relay_suffix.lower()[-2:]
    candidates = []
    for node_id_hex, node_data in nodes.items():
        if len(node_id_hex) == 8 and node_id_hex.lower()[-2:] == relay_suffix:
            candidates.append((node_id_hex, node_data))

    if not candidates:
        if debug:
            print(f"[RelayMatch] No candidates for suffix {relay_suffix}")
        return None
    if len(candidates) == 1:
        if debug:
            print(f"[RelayMatch] Only one candidate for suffix {relay_suffix}: {candidates[0][0]}")
        return candidates[0][0]

    # --- Zero-hop filter: only consider zero-hop neighbors if any exist ---
    zero_hop_candidates = []
    if zero_hop_links:
        for node_id_hex, node_data in candidates:
            is_zero_hop = False
            if sender_id and node_id_hex in zero_hop_links.get(sender_id, {}).get('heard', {}):
                is_zero_hop = True
            if receiver_ids:
                for rid in receiver_ids:
                    if node_id_hex in zero_hop_links.get(rid, {}).get('heard', {}):
                        is_zero_hop = True
            if is_zero_hop:
                zero_hop_candidates.append((node_id_hex, node_data))
    if zero_hop_candidates:
        if debug:
            print(f"[RelayMatch] Restricting to zero-hop candidates: {[c[0] for c in zero_hop_candidates]}")
        candidates = zero_hop_candidates
    else:
        # --- Extended neighbor filter: only consider candidates that have ever been heard by or heard from sender/receivers ---
        extended_candidates = []
        if zero_hop_links:
            local_set = set()
            if sender_id and sender_id in zero_hop_links:
                local_set.update(zero_hop_links[sender_id].get('heard', {}).keys())
                local_set.update(zero_hop_links[sender_id].get('heard_by', {}).keys())
            if receiver_ids:
                for rid in receiver_ids:
                    if rid in zero_hop_links:
                        local_set.update(zero_hop_links[rid].get('heard', {}).keys())
                        local_set.update(zero_hop_links[rid].get('heard_by', {}).keys())
            local_set_hex = set()
            for n in local_set:
                try:
                    if isinstance(n, int):
                        local_set_hex.add(utils.convert_node_id_from_int_to_hex(n))
                    elif isinstance(n, str) and len(n) == 8:
                        local_set_hex.add(n)
                except Exception:
                    continue
            for node_id_hex, node_data in candidates:
                if node_id_hex in local_set_hex:
                    extended_candidates.append((node_id_hex, node_data))
        if extended_candidates:
            if debug:
                print(f"[RelayMatch] Restricting to extended neighbor candidates: {[c[0] for c in extended_candidates]}")
            candidates = extended_candidates
        else:
            if debug:
                print(f"[RelayMatch] No local/extended candidates, using all: {[c[0] for c in candidates]}")

    # --- Distance-first selection among remaining candidates ---
    def get_distance(node_data, ref_pos):
        npos = node_data.get('position')
        if not npos or not ref_pos:
            return float('inf')
        nlat = npos.get('latitude') if isinstance(npos, dict) else getattr(npos, 'latitude', None)
        nlon = npos.get('longitude') if isinstance(npos, dict) else getattr(npos, 'longitude', None)
        if nlat is None or nlon is None:
            return float('inf')
        # Fix: Use 'latitude' and 'longitude' keys, not 'lat' and 'lon'
        ref_lat = ref_pos.get('latitude') if isinstance(ref_pos, dict) else getattr(ref_pos, 'latitude', None)
        ref_lon = ref_pos.get('longitude') if isinstance(ref_pos, dict) else getattr(ref_pos, 'longitude', None)
        if ref_lat is None or ref_lon is None:
            return float('inf')
        return utils.distance_between_two_points(ref_lat, ref_lon, nlat, nlon)

    ref_pos = sender_pos if sender_pos else receiver_pos
    if ref_pos:
        # Compute distances
        distances = [(node_id_hex, node_data, get_distance(node_data, ref_pos)) for node_id_hex, node_data in candidates]
        min_dist = min(d[2] for d in distances)
        closest = [d for d in distances if abs(d[2] - min_dist) < 1e-3]  # Allow for float rounding
        if debug:
            print(f"[RelayMatch] Closest candidates by distance: {[(c[0], c[2]) for c in closest]}")
        if len(closest) == 1:
            return closest[0][0]
        # If tie, fall back to scoring among closest
        candidates = [(c[0], c[1]) for c in closest]

    # --- Scoring system as tiebreaker ---
    scores = {}
    now = time.time()
    for node_id_hex, node_data in candidates:
        score = 0
        reasons = []
        if zero_hop_links:
            if sender_id and node_id_hex in zero_hop_links.get(sender_id, {}).get('heard', {}):
                score += 100
                reasons.append('zero-hop-sender')
            if receiver_ids:
                for rid in receiver_ids:
                    if node_id_hex in zero_hop_links.get(rid, {}).get('heard', {}):
                        score += 100
                        reasons.append(f'zero-hop-receiver-{rid}')
        proximity_score = 0
        pos_fresh = False
        if sender_pos and node_data.get('position'):
            npos = node_data['position']
            nlat = npos.get('latitude') if isinstance(npos, dict) else getattr(npos, 'latitude', None)
            nlon = npos.get('longitude') if isinstance(npos, dict) else getattr(npos, 'longitude', None)
            ntime = npos.get('position_time') if isinstance(npos, dict) else getattr(npos, 'position_time', None)
            if nlat is not None and nlon is not None and ntime is not None:
                # Convert datetime to timestamp if needed
                if isinstance(ntime, datetime.datetime):
                    ntime = ntime.timestamp()
                if now - ntime > 21600:
                    score -= 50
                    reasons.append('stale-position')
                else:
                    pos_fresh = True
                    # Fix: Use 'latitude' and 'longitude' keys, not 'lat' and 'lon'
                    sender_lat = sender_pos.get('latitude') if isinstance(sender_pos, dict) else getattr(sender_pos, 'latitude', None)
                    sender_lon = sender_pos.get('longitude') if isinstance(sender_pos, dict) else getattr(sender_pos, 'longitude', None)
                    if sender_lat is not None and sender_lon is not None:
                        dist = utils.distance_between_two_points(sender_lat, sender_lon, nlat, nlon)
                        proximity_score = max(0, 100 - dist * 2)
                        score += proximity_score
                        reasons.append(f'proximity:{dist:.1f}km(+{proximity_score:.1f})')
                    else:
                        score -= 50
                        reasons.append('missing-sender-position')
            else:
                score -= 100
                reasons.append('missing-position')
        ts_seen = node_data.get('ts_seen')
        if ts_seen:
            # Convert datetime to timestamp if needed
            if isinstance(ts_seen, datetime.datetime):
                ts_seen = ts_seen.timestamp()
            if now - ts_seen < 3600:
                score += 10
                reasons.append('recently-seen')
        if node_data.get('role') not in [1, 8]:
            score += 5
            reasons.append('relay-capable')
        scores[node_id_hex] = (score, reasons)
    if debug:
        print(f"[RelayMatch] Candidates for suffix {relay_suffix}:")
        for nid, (score, reasons) in scores.items():
            print(f"  {nid}: score={score}, reasons={reasons}")
    if not scores:
        return None
    best = max(scores.items(), key=lambda x: x[1][0])
    if debug:
        print(f"[RelayMatch] Selected {best[0]} for suffix {relay_suffix} (score={best[1][0]})")
    return best[0]

@app.route('/message-paths.html')
def message_paths():
    days = float(request.args.get('days', 0.167))  # Default to 4 hours if not provided
    
    md = get_meshdata()
    if not md:
        abort(503, description="Database connection unavailable")
    
    # Get relay network data
    relay_data = md.get_relay_network_data(days)
    
    return render_template(
        "message-paths.html.j2",
        auth=auth(),
        config=config,
        relay_data=relay_data,
        stats=relay_data['stats'],
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@cache.memoize(timeout=get_cache_timeout())  # Cache for 5 minutes
def get_cached_hardware_models():
    """Get hardware model statistics for the most and least common models."""
    try:
        md = get_meshdata()
        if not md:
            return {'error': 'Database connection unavailable'}
        
        # Get hardware model statistics
        cur = md.db.cursor(dictionary=True)
        
        # Query to get hardware model counts with model names
        sql = """
        SELECT 
            hw_model,
            COUNT(*) as node_count,
            GROUP_CONCAT(DISTINCT short_name ORDER BY short_name SEPARATOR ', ') as sample_names
        FROM nodeinfo 
        WHERE hw_model IS NOT NULL 
        GROUP BY hw_model 
        ORDER BY node_count DESC
        """
        
        cur.execute(sql)
        results = cur.fetchall()
        cur.close()
        
        # Process results and get hardware model names - use tuples to reduce memory
        hardware_stats = []
        for row in results:
            hw_model_id = row['hw_model']
            hw_model_name = meshtastic_support.get_hardware_model_name(hw_model_id)
            
            # Get a sample node for icon
            sample_node = row['sample_names'].split(', ')[0] if row['sample_names'] else f"Model {hw_model_id}"
            
            # Use tuple instead of dict to reduce memory overhead
            hardware_stats.append((
                hw_model_id,
                hw_model_name or f"Unknown Model {hw_model_id}",
                row['node_count'],
                row['sample_names'],
                utils.graph_icon(sample_node)
            ))
        
        # Get top 15 most common
        most_common = hardware_stats[:15]
        
        # Get bottom 15 least common (but only if we have more than 15 total models)
        # Sort in ascending order (lowest count first)
        least_common = hardware_stats[-15:] if len(hardware_stats) > 15 else hardware_stats
        least_common = sorted(least_common, key=lambda x: x[2])  # Sort by node_count (index 2)
        
        # Convert tuples to dicts only for JSON serialization
        def tuple_to_dict(hw_tuple):
            return {
                'model_id': hw_tuple[0],
                'model_name': hw_tuple[1],
                'node_count': hw_tuple[2],
                'sample_names': hw_tuple[3],
                'icon_url': hw_tuple[4]
            }
        
        return {
            'most_common': [tuple_to_dict(hw) for hw in most_common],
            'least_common': [tuple_to_dict(hw) for hw in least_common],
            'total_models': len(hardware_stats)
        }
        
    except Exception as e:
        logging.error(f"Error fetching hardware models: {e}")
        return {'error': 'Failed to fetch hardware model data'}

@app.route('/api/utilization-data')
def get_utilization_data():
    md = get_meshdata()
    if not md:
        abort(503, description="Database connection unavailable")
    
    try:
        # Get parameters from request
        time_range = request.args.get('time_range', '24')  # hours
        channel = request.args.get('channel', 'all')
        
        # Calculate time window
        hours = int(time_range)
        cutoff_time = datetime.datetime.now() - datetime.timedelta(hours=hours)
        
        cursor = md.db.cursor(dictionary=True)
        
        # Build channel condition
        channel_condition = ""
        if channel != 'all':
            channel_condition = f" AND channel = {channel}"
        
        # Get active nodes from cache (much faster than complex DB queries)
        nodes = get_cached_nodes()
        if not nodes:
            return jsonify({'error': 'No node data available'}), 503
        
        # Get most recent telemetry for active nodes only
        sql = f"""
            SELECT 
                t.id,
                t.channel_utilization,
                t.ts_created
            FROM telemetry t
            WHERE t.ts_created >= NOW() - INTERVAL {hours} HOUR
                AND t.channel_utilization IS NOT NULL
                AND t.channel_utilization > 0
                {channel_condition}
            ORDER BY t.id, t.ts_created DESC
        """
        
        cursor.execute(sql)
        telemetry_rows = cursor.fetchall()
        
        # Get only the most recent utilization per node
        node_utilization = {}
        for row in telemetry_rows:
            node_id = row['id']
            if node_id not in node_utilization:
                node_utilization[node_id] = {
                    'utilization': row['channel_utilization'],
                    'ts_created': row['ts_created']
                }
        
        # Get contact data for active nodes in one efficient query
        active_node_ids = list(node_utilization.keys())
        contact_data = {}
        
        if active_node_ids:
            # Use placeholders for the IN clause
            placeholders = ','.join(['%s'] * len(active_node_ids))
            contact_sql = f"""
                SELECT 
                    from_id,
                    received_by_id,
                    p1.latitude_i as from_lat_i,
                    p1.longitude_i as from_lon_i,
                    p2.latitude_i as to_lat_i,
                    p2.longitude_i as to_lon_i
                FROM message_reception r
                LEFT JOIN position p1 ON p1.id = r.from_id
                LEFT JOIN position p2 ON p2.id = r.received_by_id
                WHERE (r.hop_limit IS NULL AND r.hop_start IS NULL)
                    OR (r.hop_start - r.hop_limit = 0)
                AND r.rx_time >= NOW() - INTERVAL {hours} HOUR
                AND r.from_id IN ({placeholders})
                AND p1.latitude_i IS NOT NULL 
                AND p1.longitude_i IS NOT NULL
                AND p2.latitude_i IS NOT NULL 
                AND p2.longitude_i IS NOT NULL
            """
            
            cursor.execute(contact_sql, active_node_ids)
            contact_rows = cursor.fetchall()
            
            # Build contact distance lookup
            for row in contact_rows:
                from_id = row['from_id']
                to_id = row['received_by_id']
                
                # Check for null coordinates before calculating distance
                if (row['from_lat_i'] is None or row['from_lon_i'] is None or 
                    row['to_lat_i'] is None or row['to_lon_i'] is None):
                    continue
                
                # Calculate distance using Haversine formula
                lat1 = row['from_lat_i'] / 10000000.0
                lon1 = row['from_lon_i'] / 10000000.0
                lat2 = row['to_lat_i'] / 10000000.0
                lon2 = row['to_lon_i'] / 10000000.0
                
                # Haversine distance calculation
                import math
                R = 6371  # Earth's radius in km
                dlat = math.radians(lat2 - lat1)
                dlon = math.radians(lon2 - lon1)
                a = (math.sin(dlat/2) * math.sin(dlat/2) + 
                     math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * 
                     math.sin(dlon/2) * math.sin(dlon/2))
                c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
                distance = R * c
                
                # Sanity check: skip distances over 150km
                if distance > 150:
                    continue
                
                # Store contact data
                if from_id not in contact_data:
                    contact_data[from_id] = {'distances': [], 'contacts': set()}
                contact_data[from_id]['distances'].append(distance)
                contact_data[from_id]['contacts'].add(to_id)
        
        # Build result using cached node data
        result = []
        for node_id, telemetry_data in node_utilization.items():
            node_hex = utils.convert_node_id_from_int_to_hex(node_id)
            node_data = nodes.get(node_hex)
            
            if node_data and node_data.get('position'):
                position = node_data['position']
                if position and position.get('latitude_i') and position.get('longitude_i'):
                    # Calculate contact distance
                    node_contacts = contact_data.get(node_id, {'distances': [], 'contacts': set()})
                    mean_distance = 2.0  # Default
                    contact_count = len(node_contacts['contacts'])
                    
                    if node_contacts['distances']:
                        mean_distance = sum(node_contacts['distances']) / len(node_contacts['distances'])
                        mean_distance = max(2.0, mean_distance)  # Minimum 2km
                    
                    # Use cached node data for position and names
                    result.append({
                        'id': node_id,
                        'utilization': round(telemetry_data['utilization'], 2),
                        'position': {
                            'latitude_i': position['latitude_i'],
                            'longitude_i': position['longitude_i'],
                            'altitude': position.get('altitude')
                        },
                        'short_name': node_data.get('short_name', ''),
                        'long_name': node_data.get('long_name', ''),
                        'mean_contact_distance': round(mean_distance, 2),
                        'contact_count': contact_count
                    })
        
        cursor.close()
        
        return jsonify({
            'nodes': result,
            'time_range': time_range,
            'channel': channel
        })
        
    except Exception as e:
        logging.error(f"Error fetching utilization data: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'Error fetching utilization data: {str(e)}'
        }), 500

@app.route('/api/hardware-models')
def get_hardware_models():
    """Get hardware model statistics for the most and least common models."""
    result = get_cached_hardware_models()
    
    if 'error' in result:
        return jsonify(result), 503 if result['error'] == 'Database connection unavailable' else 500
    
    return jsonify(result)

def get_elsewhere_links(node_id, node_hex_id):
    """
    Build Elsewhere links for a node based on config.ini [tools] section.
    
    Args:
        node_id: The node ID as integer
        node_hex_id: The node ID as hex string
        
    Returns:
        List of (label, url, icon) tuples for the Elsewhere section
    """
    elsewhere_links = []
    
    def get_icon_for_tool(label, url):
        """Determine appropriate icon based on tool name and URL."""
        label_lower = label.lower()
        url_lower = url.lower()
        
        # Map-related tools
        if 'map' in label_lower or 'map' in url_lower:
            return '🗺️'
        
        # Logs/Logging tools
        if 'log' in label_lower or 'log' in url_lower:
            return '📋'
        
        # Dashboard/Monitoring tools
        if 'dashboard' in label_lower or 'monitor' in label_lower:
            return '📊'
        
        # Network/Graph tools
        if 'graph' in label_lower or 'network' in label_lower:
            return '🕸️'
        
        # Chat/Message tools
        if 'chat' in label_lower or 'message' in label_lower:
            return '💬'
        
        # Settings/Config tools
        if 'config' in label_lower or 'setting' in label_lower:
            return '⚙️'
        
        # Default icon for external links
        return '🔗'
    
    # Process keys ending with _node_link
    for key, value in config.items('tools'):
        if key.endswith('_node_link'):
            # Extract the base key (remove _node_link suffix)
            base_key = key[:-10]  # Remove '_node_link'
            
            # Get the label from the corresponding _label key
            label_key = base_key + '_label'
            label = config.get('tools', label_key, fallback=None)
            if not label:
                # Fallback to a generated label if no _label is found
                label = base_key.replace('_', ' ').title()
            
            # Replace placeholders in URL and strip any extra quotes
            url = value.replace('{{ node.id }}', str(node_id)).replace('{{ node.hex_id }}', node_hex_id).strip('"')
            
            # Get appropriate icon
            icon = get_icon_for_tool(label, url)
            
            elsewhere_links.append((label, url, icon))
    
    return elsewhere_links

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = int(config["webserver"]["port"])
    app.run(debug=True, port=port)
