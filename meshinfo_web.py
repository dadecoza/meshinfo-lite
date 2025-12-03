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
    current_app,
    send_file
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
import requests
from io import BytesIO
import staticmaps

import utils
# Remove direct import to reduce circular references
# import meshtastic_support
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
from meshinfo_utils import (
    get_meshdata, get_cache_timeout, auth, config, log_memory_usage, 
    clear_nodes_cache, clear_database_cache, get_cached_chat_data, get_node_page_data,
    calculate_node_distance, find_relay_node_by_suffix, get_elsewhere_links, get_role_badge
)
from PIL import Image, ImageDraw
import PIL.ImageDraw

def textsize(self: PIL.ImageDraw.ImageDraw, *args, **kwargs):
    x, y, w, h = self.textbbox((0, 0), *args, **kwargs)
    return w, h

# Monkeypatch fix for https://github.com/flopp/py-staticmaps/issues/39
PIL.ImageDraw.ImageDraw.textsize = textsize

app = Flask(__name__)

# --- OG image generation for message_map ---
OG_IMAGE_DIR = "/tmp/og_images"
os.makedirs(OG_IMAGE_DIR, exist_ok=True)

def generate_message_map_image_staticmaps(message_id, sender_pos, receiver_positions):
    width, height = 800, 400
    extra = 40  # extra height for attribution
    context = staticmaps.Context()
    context.set_tile_provider(staticmaps.tile_provider_OSM)
    
    # Add sender marker and lines if sender position is available
    if sender_pos and sender_pos.get('latitude') and sender_pos.get('longitude'):
        sender = staticmaps.create_latlng(sender_pos['latitude'], sender_pos['longitude'])
        
        # Add all lines from sender to receivers first (so they appear behind markers)
        for pos in receiver_positions:
            if pos.get('latitude') and pos.get('longitude'):
                receiver = staticmaps.create_latlng(pos['latitude'], pos['longitude'])
                context.add_object(staticmaps.Line([sender, receiver], color=staticmaps.BLUE, width=2))
        
        # Add sender marker
        context.add_object(staticmaps.Marker(sender, color=staticmaps.RED, size=8))
    
    # Add all receiver markers
    for pos in receiver_positions:
        if pos.get('latitude') and pos.get('longitude'):
            receiver = staticmaps.create_latlng(pos['latitude'], pos['longitude'])
            context.add_object(staticmaps.Marker(receiver, color=staticmaps.BLUE, size=6))
    
    image = context.render_pillow(width, height + extra)
    # Crop off the bottom 'extra' pixels to remove attribution
    image = image.crop((0, 0, width, height))
    OG_IMAGE_DIR = "/tmp/og_images"
    os.makedirs(OG_IMAGE_DIR, exist_ok=True)
    path = os.path.join(OG_IMAGE_DIR, f"message_map_{message_id}.png")
    image.save(path)
    return path

@app.route('/og_image/message_map/<int:message_id>.png')
def og_image_message_map(message_id):
    from meshinfo_web import get_cached_message_map_data
    data = get_cached_message_map_data(message_id)
    if not data or not data.get('receiver_positions'):
        abort(404)
    
    sender_pos = data.get('sender_position')
    def get_latlon(pos):
        lat = pos.get('latitude')
        lon = pos.get('longitude')
        if lat is None and 'latitude_i' in pos:
            lat = pos['latitude_i'] / 1e7
        if lon is None and 'longitude_i' in pos:
            lon = pos['longitude_i'] / 1e7
        return {'latitude': lat, 'longitude': lon}
    
    # Handle sender position (optional)
    sender_pos_processed = None
    if sender_pos:
        sender_pos_processed = get_latlon(sender_pos)
        if not sender_pos_processed['latitude'] or not sender_pos_processed['longitude']:
            sender_pos_processed = None
    
    # Process receiver positions
    receiver_positions = [get_latlon(p) for p in data['receiver_positions'].values() if p]
    receiver_positions = [p for p in receiver_positions if p['latitude'] and p['longitude']]
    
    if not receiver_positions:
        abort(404)
    
    path = os.path.join("/tmp/og_images", f"message_map_{message_id}.png")
    cache_expired = False
    
    if os.path.exists(path):
        # Check file age
        file_age = time.time() - os.path.getmtime(path)
        max_cache_age = 3600  # 1 hour in seconds
        
        # Also check if message was updated since image was created
        if data.get('message', {}).get('ts_created'):
            message_created = data['message']['ts_created']
            if hasattr(message_created, 'timestamp'):
                message_created = message_created.timestamp()
            
            if file_age > max_cache_age or (message_created and os.path.getmtime(path) < message_created):
                cache_expired = True
        elif file_age > max_cache_age:
            cache_expired = True
    
    if not os.path.exists(path) or cache_expired:
        generate_message_map_image_staticmaps(message_id, sender_pos_processed, receiver_positions)
    return send_file(path, mimetype='image/png')

def generate_traceroute_map_image_staticmaps(traceroute_id, source_pos, destination_pos, forward_hop_positions, return_hop_positions):
    width, height = 800, 400
    extra = 40  # extra height for attribution
    context = staticmaps.Context()
    context.set_tile_provider(staticmaps.tile_provider_OSM)
    
    # Add all lines first (so they appear behind markers)
    if source_pos and destination_pos:
        source = staticmaps.create_latlng(source_pos['latitude'], source_pos['longitude'])
        destination = staticmaps.create_latlng(destination_pos['latitude'], destination_pos['longitude'])
        
        # Create forward path through all hops
        forward_path_points = [source]
        for hop_pos in forward_hop_positions:
            if hop_pos and hop_pos.get('latitude') and hop_pos.get('longitude'):
                forward_path_points.append(staticmaps.create_latlng(hop_pos['latitude'], hop_pos['longitude']))
        forward_path_points.append(destination)
        
        # Add forward path lines (green)
        for i in range(len(forward_path_points) - 1):
            context.add_object(staticmaps.Line([forward_path_points[i], forward_path_points[i+1]], color=staticmaps.Color(68, 170, 68), width=2))
        
        # Create return path if return hops exist
        if return_hop_positions:
            return_path_points = [destination]
            for hop_pos in return_hop_positions:
                if hop_pos and hop_pos.get('latitude') and hop_pos.get('longitude'):
                    return_path_points.append(staticmaps.create_latlng(hop_pos['latitude'], hop_pos['longitude']))
            return_path_points.append(source)
            
            # Add return path lines (purple)
            for i in range(len(return_path_points) - 1):
                context.add_object(staticmaps.Line([return_path_points[i], return_path_points[i+1]], color=staticmaps.Color(170, 68, 170), width=2))
    
    # Add all markers after lines (so they appear on top)
    if source_pos:
        source = staticmaps.create_latlng(source_pos['latitude'], source_pos['longitude'])
        context.add_object(staticmaps.Marker(source, color=staticmaps.RED, size=8))
    
    # Add forward hop markers (green)
    for i, hop_pos in enumerate(forward_hop_positions):
        if hop_pos and hop_pos.get('latitude') and hop_pos.get('longitude'):
            hop = staticmaps.create_latlng(hop_pos['latitude'], hop_pos['longitude'])
            context.add_object(staticmaps.Marker(hop, color=staticmaps.Color(68, 170, 68), size=6))
    
    if destination_pos:
        destination = staticmaps.create_latlng(destination_pos['latitude'], destination_pos['longitude'])
        context.add_object(staticmaps.Marker(destination, color=staticmaps.BLUE, size=8))
    
    # Add return hop markers (purple) - but only if they're different from forward hops
    for i, hop_pos in enumerate(return_hop_positions):
        if hop_pos and hop_pos.get('latitude') and hop_pos.get('longitude'):
            hop = staticmaps.create_latlng(hop_pos['latitude'], hop_pos['longitude'])
            context.add_object(staticmaps.Marker(hop, color=staticmaps.Color(170, 68, 170), size=6))
    
    image = context.render_pillow(width, height + extra)
    # Crop off the bottom 'extra' pixels to remove attribution
    image = image.crop((0, 0, width, height))
    OG_IMAGE_DIR = "/tmp/og_images"
    os.makedirs(OG_IMAGE_DIR, exist_ok=True)
    path = os.path.join(OG_IMAGE_DIR, f"traceroute_map_{traceroute_id}.png")
    image.save(path)
    return path

@app.route('/og_image/traceroute_map/<int:traceroute_id>.png')
def og_image_traceroute_map(traceroute_id):
    md = get_meshdata()
    if not md:
        abort(404)
    
    # Get traceroute data
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT from_id, to_id, route, route_back, ts_created
        FROM traceroute 
        WHERE traceroute_id = %s
    """, (traceroute_id,))
    traceroute_data = cursor.fetchone()
    cursor.close()
    
    if not traceroute_data:
        abort(404)
    
    # Get positions for source and destination
    def get_node_position(node_id):
        cursor = md.db.cursor(dictionary=True)
        cursor.execute("""
            SELECT latitude_i, longitude_i, position_time
            FROM position 
            WHERE id = %s 
            ORDER BY position_time DESC 
            LIMIT 1
        """, (node_id,))
        pos = cursor.fetchone()
        cursor.close()
        
        if pos and pos['latitude_i'] is not None and pos['longitude_i'] is not None:
            return {
                'latitude': pos['latitude_i'] / 1e7,
                'longitude': pos['longitude_i'] / 1e7,
                'position_time': pos['position_time']
            }
        return None
    
    source_pos = get_node_position(traceroute_data['from_id'])
    destination_pos = get_node_position(traceroute_data['to_id'])
    
    if not source_pos or not destination_pos:
        abort(404)
    
    # Get positions for all hops
    forward_hop_positions = []
    if traceroute_data['route']:
        route = [int(hop) for hop in traceroute_data['route'].split(';') if hop]
        for hop_id in route:
            hop_pos = get_node_position(hop_id)
            forward_hop_positions.append(hop_pos)
    
    # Get positions for return hops
    return_hop_positions = []
    if traceroute_data['route_back']:
        route_back = [int(hop) for hop in traceroute_data['route_back'].split(';') if hop]
        for hop_id in route_back:
            hop_pos = get_node_position(hop_id)
            return_hop_positions.append(hop_pos)
    
    # Generate the image
    path = os.path.join("/tmp/og_images", f"traceroute_map_{traceroute_id}.png")
    cache_expired = False
    
    if os.path.exists(path):
        # Check file age
        file_age = time.time() - os.path.getmtime(path)
        max_cache_age = 3600  # 1 hour in seconds
        
        # Also check if traceroute was updated since image was created
        if traceroute_data.get('ts_created'):
            traceroute_created = traceroute_data['ts_created']
            if hasattr(traceroute_created, 'timestamp'):
                traceroute_created = traceroute_created.timestamp()
            
            if file_age > max_cache_age or (traceroute_created and os.path.getmtime(path) < traceroute_created):
                cache_expired = True
        elif file_age > max_cache_age:
            cache_expired = True
    
    if not os.path.exists(path) or cache_expired:
        generate_traceroute_map_image_staticmaps(traceroute_id, source_pos, destination_pos, forward_hop_positions, return_hop_positions)
    
    return send_file(path, mimetype='image/png')

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
app.jinja_env.globals.update(get_role_badge=get_role_badge)

# Add template filters
@app.template_filter('safe_hw_model')
def safe_hw_model(value):
    try:
        return get_hardware_model_name(value)
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
        meshtastic_support=get_meshtastic_support(),
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
        Channel=get_channel_enum(),  # Add Channel enum to template context
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
        Channel=get_channel_enum(),  # Add Channel enum to template context
    )

@app.route('/map.html')
def map():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    return render_template(
        "map_api.html.j2",
        auth=auth(),
        config=config,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        Channel=get_channel_enum(),  # Add Channel enum to template context
    )

@app.route('/map-classic.html')
def map_classic():
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
        Channel=get_channel_enum(),  # Add Channel enum to template context
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
        meshtastic_support=get_meshtastic_support(),
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

@app.route('/routing.html')
def routing():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    error_only = request.args.get('error_only', 'false').lower() == 'true'
    days = request.args.get('days', 7, type=int)
    
    # Get routing messages
    routing_data = md.get_routing_messages(page=page, per_page=per_page, error_only=error_only, days=days)
    
    # Get routing statistics
    stats = md.get_routing_stats(days=days)
    error_breakdown = md.get_routing_errors_by_type(days=days)
    
    # Create template context
    template_context = {
        "auth": auth(),
        "config": config,
        "routing_messages": routing_data['items'],
        "pagination": routing_data,
        "stats": stats,
        "error_breakdown": error_breakdown,
        "error_only": error_only,
        "days": days,
        "utils": utils,
        "datetime": datetime.datetime,
        "timestamp": datetime.datetime.now(),
        "meshtastic_support": get_meshtastic_support()
    }
    
    response = render_template("routing.html.j2", **template_context)
    
    # Clean up large objects to help with memory management
    del template_context
    del routing_data
    del stats
    del error_breakdown
    
    # Force garbage collection
    gc.collect()
    
    return response

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
        hardware=get_hardware_model_enum(),
        meshtastic_support=get_meshtastic_support(),
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

@app.route('/account.html')
def account():
    owner = auth()
    if not owner:
        return redirect(url_for('login'))
    # Don't use cached nodes for account page - always get fresh data from database
    md = get_meshdata()
    if not md:
        abort(503, description="Database connection unavailable")
    # Clear MeshData cache and get fresh nodes directly from database
    md.clear_nodes_cache()
    nodes = md.get_nodes(active=False)  # Get fresh from database, bypassing all caches
    if not nodes:
        abort(503, description="Database connection unavailable")
    mynodes = utils.get_owner_nodes(nodes, owner["email"])
    response = make_response(render_template(
        "account.html.j2",
        auth=owner,
        config=config,
        nodes=mynodes,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    ))
    # Add no-cache headers to prevent browser/proxy caching
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

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
            hardware=get_hardware_model_enum(),
            meshtastic_support=get_meshtastic_support(),
            hardware_photos=get_hardware_photos(),
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
            hardware=get_hardware_model_enum(),
            meshtastic_support=get_meshtastic_support(),
            hardware_photos=get_hardware_photos(),
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
        Channel=get_channel_enum(),
        utils=utils
    )

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



@app.route('/chat.html')
def chat2():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    channel = request.args.get('channel', 'all')
    
    # Get cached data
    nodes = get_cached_nodes()
    if not nodes:
        abort(503, description="Database connection unavailable")
        
    chat_data = get_cached_chat_data(page, per_page, channel)
    if not chat_data:
        abort(503, description="Database connection unavailable")
    
    # Get available channels from meshtastic_support
    import meshtastic_support
    available_channels = []
    for channel_enum in meshtastic_support.Channel:
        available_channels.append({
            'value': channel_enum.value,
            'name': meshtastic_support.get_channel_name(channel_enum.value),
            'short_name': meshtastic_support.get_channel_name(channel_enum.value, use_short_names=True)
        })
    
    # Process channel display for the template
    channel_display = "All"
    if channel != 'all':
        selected_channels = channel.split(',')
        short_names = []
        for channel_info in available_channels:
            if str(channel_info['value']) in selected_channels:
                short_names.append(channel_info['short_name'])
        if short_names:
            channel_display = ', '.join(short_names)
        else:
            channel_display = channel
    
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
                'hw_model_name': get_hardware_model_name(node.get('hw_model')) if node.get('hw_model') else None,
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
        meshtastic_support=get_meshtastic_support(),
        debug=False,
        channel=channel,
        available_channels=available_channels,
        channel_display=channel_display
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
        hardware=get_hardware_model_enum(),
        meshtastic_support=get_meshtastic_support(),
        hardware_photos=get_hardware_photos(),
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
        hardware=get_hardware_model_enum(),
        meshtastic_support=get_meshtastic_support(),
        hardware_photos=get_hardware_photos(),
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

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
            hw_model_name = get_hardware_model_name(hw_model_id)
            
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

def generate_node_map_image_staticmaps(node_id, node_position, node_name):
    width, height = 800, 400
    extra = 40  # extra height for attribution
    context = staticmaps.Context()
    context.set_tile_provider(staticmaps.tile_provider_OSM)
    
    # Convert position coordinates
    lat = node_position['latitude_i'] / 10000000.0
    lon = node_position['longitude_i'] / 10000000.0
    node_point = staticmaps.create_latlng(lat, lon)
    
    # Add node marker
    context.add_object(staticmaps.Marker(node_point, color=staticmaps.RED, size=16))
    
    # Render the image
    image = context.render_pillow(width, height + extra)
    # Crop off the bottom 'extra' pixels to remove attribution
    image = image.crop((0, 0, width, height))
    
    return image

@app.route('/og_image/node_map/<int:node_id>.png')
def og_image_node_map(node_id):
    """Generate OG image for a node showing its position on a map."""
    try:
        # Ensure the OG images directory exists
        os.makedirs("/tmp/og_images", exist_ok=True)
        
        # Get node data using the existing cached function
        nodes = get_cached_nodes()
        if not nodes:
            return "Database unavailable", 503
        
        # Convert node ID to hex format
        node_id_hex = utils.convert_node_id_from_int_to_hex(node_id)
        
        # Get node data
        node_data = nodes.get(node_id_hex)
        if not node_data:
            return "Node not found", 404
        
        # Check if node has position data
        position = node_data.get('position')
        if not position or not position.get('latitude_i') or not position.get('longitude_i'):
            return "Node has no position data", 404
        
        # Check cache expiration
        path = os.path.join("/tmp/og_images", f"node_map_{node_id}.png")
        cache_expired = False
        
        if os.path.exists(path):
            # Check file age
            file_age = time.time() - os.path.getmtime(path)
            max_cache_age = 3600  # 1 hour in seconds
            
            # Also check if node position has been updated since image was created
            ts_seen = node_data.get('ts_seen')
            if ts_seen:
                if hasattr(ts_seen, 'timestamp'):
                    node_last_seen = ts_seen.timestamp()
                else:
                    node_last_seen = ts_seen
                
                if file_age > max_cache_age or (node_last_seen and os.path.getmtime(path) < node_last_seen):
                    cache_expired = True
            elif file_age > max_cache_age:
                cache_expired = True
        
        # Generate the image if it doesn't exist or is expired
        if not os.path.exists(path) or cache_expired:
            node_position = {
                'latitude_i': position['latitude_i'],
                'longitude_i': position['longitude_i']
            }
            node_name = node_data.get('short_name') or node_data.get('long_name') or f"Node {node_id}"
            
            image = generate_node_map_image_staticmaps(node_id, node_position, node_name)
            image.save(path)
        
        # Serve the image
        return send_file(path, mimetype='image/png')
        
    except Exception as e:
        logging.error(f"Error generating node map OG image: {e}")
        return "Error generating image", 500

# Helper functions to avoid circular references
def get_meshtastic_support():
    """Lazy import of meshtastic_support to avoid circular references."""
    import meshtastic_support
    return meshtastic_support

def get_hardware_model_enum():
    """Get HardwareModel enum without direct module reference."""
    import meshtastic_support
    return meshtastic_support.HardwareModel

def get_channel_enum():
    """Get Channel enum without direct module reference."""
    import meshtastic_support
    return meshtastic_support.Channel

def get_routing_error_description(error_reason):
    """Get routing error description without direct module reference."""
    import meshtastic_support
    return meshtastic_support.get_routing_error_description(error_reason)

def get_hardware_model_name(hw_model):
    """Get hardware model name without direct module reference."""
    import meshtastic_support
    return meshtastic_support.get_hardware_model_name(hw_model)

def get_hardware_photos():
    """Get HARDWARE_PHOTOS dict without direct module reference."""
    import meshtastic_support
    return meshtastic_support.HARDWARE_PHOTOS

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

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = int(config["webserver"]["port"])
    app.run(debug=True, port=port)
