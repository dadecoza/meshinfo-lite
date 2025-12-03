from flask import Blueprint, request, jsonify, current_app, abort
from datetime import datetime, timedelta
import logging
import sys
import psutil
from meshinfo_utils import get_meshdata, get_cache_timeout, auth, config, log_cache_stats, log_memory_usage
from meshdata import MeshData
from database_cache import DatabaseCache
from meshinfo_register import Register
import utils
import time

# Create API blueprint
api = Blueprint('api', __name__, url_prefix='/api')

def api_auth():
    """Authenticate API request using JWT from cookie."""
    jwt_token = request.cookies.get('jwt')
    if not jwt_token:
        return None
    reg = Register()
    decoded_jwt = reg.auth(jwt_token)
    return decoded_jwt

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

def get_cached_nodes():
    """Get nodes data for API endpoints."""
    md = get_meshdata()
    if not md:
        return None
    
    # Use the cached method to prevent duplicate dictionaries
    nodes_data = md.get_nodes_cached()
    logging.debug(f"Fetched {len(nodes_data)} nodes from API cache")
    return nodes_data

@api.route('/metrics')
def get_metrics():
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    try:
        # Get time range from request parameters
        time_range = request.args.get('time_range', 'day')  # day, week, month, year, all
        channel = request.args.get('channel', 'all')  # Get channel parameter
        
        # Set time range based on parameter
        end_time = datetime.now()
        if time_range == 'week':
            start_time = end_time - timedelta(days=7)
            bucket_size = 180  # 3 hours in minutes
        elif time_range == 'month':
            start_time = end_time - timedelta(days=30)
            bucket_size = 720  # 12 hours in minutes
        elif time_range == 'year':
            start_time = end_time - timedelta(days=365)
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
                start_time = end_time - timedelta(days=365)
            
            bucket_size = 10080  # 7 days in minutes
        else:  # default to day
            start_time = end_time - timedelta(hours=24)
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
        if channel != 'all':
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
        
        # Moving average helper
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

        # Get metrics_average_interval from config
        metrics_avg_interval = int(config.get('server', 'metrics_average_interval', fallback=7200))  # seconds
        metrics_avg_minutes = metrics_avg_interval // 60

        # Prepare raw data lists
        nodes_online_raw = [nodes_online_data.get(slot, 0) for slot in time_slots]
        channel_util_raw = [channel_util_data.get(slot, 0) for slot in time_slots]
        battery_levels_raw = [battery_data.get(slot, 0) for slot in time_slots]
        temperature_raw = [temperature_data.get(slot, 0) for slot in time_slots]
        snr_raw = [snr_data.get(slot, 0) for slot in time_slots]

        # Get node_activity_prune_threshold from config
        node_activity_prune_threshold = int(config.get('server', 'node_activity_prune_threshold', fallback=7200))

        # For each time slot, count unique nodes heard in the preceding activity window
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
                row['ts_created'] = datetime.strptime(row['ts_created'], '%Y-%m-%d %H:%M:%S')
        # Precompute for each time slot
        nodes_heard_per_slot = []
        for slot in time_slots:
            # slot is a string, convert to datetime
            if '%H:%M' in time_format or '%H:%i' in time_format:
                slot_time = datetime.strptime(slot, '%Y-%m-%d %H:%M')
            elif '%H:00' in time_format:
                slot_time = datetime.strptime(slot, '%Y-%m-%d %H:%M')
            else:
                slot_time = datetime.strptime(slot, '%Y-%m-%d')
            window_start = slot_time - timedelta(seconds=node_activity_prune_threshold)
            # Find all node ids with telemetry in [window_start, slot_time]
            active_nodes = set()
            for row in all_telemetry:
                if window_start < row['ts_created'] <= slot_time:
                    active_nodes.add(row['id'])
            nodes_heard_per_slot.append(len(active_nodes))
        # Now apply moving average and round to nearest integer
        nodes_online_smoothed = [round(x) for x in moving_average_centered(nodes_heard_per_slot, metrics_avg_minutes, bucket_size)]
        
        cursor.close()
    
        # Apply moving averages to other metrics
        channel_util_smoothed = moving_average_centered(channel_util_raw, metrics_avg_minutes, bucket_size)
        battery_levels_smoothed = moving_average_centered(battery_levels_raw, metrics_avg_minutes, bucket_size)
        temperature_smoothed = moving_average_centered(temperature_raw, metrics_avg_minutes, bucket_size)
        snr_smoothed = moving_average_centered(snr_raw, metrics_avg_minutes, bucket_size)

        return jsonify({
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
                'data': channel_util_smoothed
            },
            'battery_levels': {
                'labels': time_slots,
                'data': battery_levels_smoothed
            },
            'temperature': {
                'labels': time_slots,
                'data': temperature_smoothed
            },
            'snr': {
                'labels': time_slots,
                'data': snr_smoothed
            }
        })
        
    except Exception as e:
        logging.error(f"Error in metrics API: {str(e)}")
        return jsonify({'error': f'Error fetching metrics: {str(e)}'}), 500 



@api.route('/chattiest-nodes')
def get_chattiest_nodes():
    """Get the most active nodes in terms of message sending."""
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
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

@api.route('/telemetry/<int:node_id>')
def api_telemetry(node_id):
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    telemetry = md.get_telemetry_for_node(node_id)
    return jsonify(telemetry)

@api.route('/environmental-telemetry/<int:node_id>')
def api_environmental_telemetry(node_id):
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    days = request.args.get('days', 1, type=int)
    # Limit days to reasonable range (1-30 days)
    days = max(1, min(30, days))
    telemetry = md.get_environmental_telemetry_for_node(node_id, days)
    return jsonify(telemetry)

@api.route('/debug/memory')
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

@api.route('/debug/cache')
def debug_cache():
    """Manual trigger for cache analysis."""
    if not auth():
        abort(401)
    
    log_cache_stats()
    
    return jsonify({
        'status': 'success',
        'message': 'Cache analysis completed. Check logs for details.'
    })

@api.route('/debug/cleanup')
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

@api.route('/debug/clear-nodes')
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

@api.route('/debug/database-cache')
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
                'message': 'Database cache not available'
            }), 500
            
    except Exception as e:
        logging.error(f"Error during database cache analysis: {e}")
        return jsonify({
            'status': 'error',
            'message': f'Error during database cache analysis: {str(e)}'
        }), 500

@api.route('/geocode')
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

@api.route('/node-positions')
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

@api.route('/utilization-data')
def get_utilization_data():
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    try:
        # Get parameters from request
        time_range = request.args.get('time_range', '24')  # hours
        channel = request.args.get('channel', 'all')
        
        # Calculate time window
        hours = int(time_range)
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
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

@api.route('/hardware-models')
def get_hardware_models():
    """Get hardware model statistics."""
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    # Query hardware model data
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT 
            hw_model,
            COUNT(*) as count,
            COUNT(DISTINCT id) as unique_nodes
        FROM nodeinfo
        WHERE hw_model IS NOT NULL
        GROUP BY hw_model
        ORDER BY count DESC
    """)
    hw_models = cursor.fetchall()
    
    # Process results and get hardware model names
    hardware_stats = []
    for row in hw_models:
        hw_model_id = row['hw_model']
        # Use lazy import to avoid circular references
        import meshtastic_support
        hw_model_name = meshtastic_support.get_hardware_model_name(hw_model_id)
        
        hardware_stats.append({
            'model_id': hw_model_id,
            'model_name': hw_model_name or f"Unknown Model {hw_model_id}",
            'node_count': row['count'],
            'unique_nodes': row['unique_nodes']
        })
    
    # Get top 15 most common
    most_common = hardware_stats[:15]
    
    # Get bottom 15 least common (but only if we have more than 15 total models)
    least_common = hardware_stats[-15:] if len(hardware_stats) > 15 else hardware_stats
    least_common = sorted(least_common, key=lambda x: x['node_count'])  # Sort by node_count
    
    cursor.close()
    return jsonify({
        'most_common': most_common,
        'least_common': least_common,
        'total_models': len(hardware_stats)
    }) 

@api.route('/map-data')
def get_map_data():
    """Get map data with filtering options for better performance."""
    md = get_meshdata()
    if not md:
        return jsonify({'error': 'Database connection unavailable'}), 503
    
    try:
        # Get filter parameters from request
        nodes_max_age = request.args.get('nodes_max_age', '0', type=int)  # seconds, 0 = show all
        nodes_disconnected_age = request.args.get('nodes_disconnected_age', '10800', type=int)  # seconds
        nodes_offline_age = request.args.get('nodes_offline_age', '10800', type=int)  # seconds
        channel_filter = request.args.get('channel_filter', 'all')  # all or specific channel
        neighbours_max_distance = request.args.get('neighbours_max_distance', '5000', type=int)  # meters
        
        cursor = md.db.cursor(dictionary=True)
        now = int(time.time())
        
        # Build WHERE conditions for filtering nodes at database level
        where_conditions = []
        params = []
        
        # Apply max age filter at database level
        if nodes_max_age > 0:
            cutoff_time = now - nodes_max_age
            where_conditions.append("n.ts_seen >= FROM_UNIXTIME(%s)")
            params.append(cutoff_time)
        
        # Channel filter will be applied after the query since it comes from CTE
        
        # Build the main query with filters
        where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
        
        # Debug logging
        logging.info(f"Map API filters: nodes_max_age={nodes_max_age}, channel_filter={channel_filter}")
        logging.info(f"WHERE clause: {where_clause}")
        logging.info(f"Parameters: {params}")
        
        # Use the existing cached nodes function for better performance
        all_nodes = md.get_nodes_cached()
        if not all_nodes:
            return jsonify({'error': 'Failed to load nodes data'}), 503
        
        # Filter nodes based on criteria
        filtered_nodes = {}
        node_ids = []
        
        for node_id_hex, node_data in all_nodes.items():
            # Apply max age filter
            if nodes_max_age > 0:
                ts_seen = node_data.get('ts_seen')
                if ts_seen:
                    if hasattr(ts_seen, 'timestamp'):
                        ts_seen = ts_seen.timestamp()
                    if now - ts_seen > nodes_max_age:
                        continue
            
            # Apply channel filter
            if channel_filter != 'all':
                node_channel = node_data.get('channel')
                if node_channel != int(channel_filter):
                    continue
            
            # Convert hex ID to int for zero-hop data
            try:
                node_id_int = utils.convert_node_id_from_hex_to_int(node_id_hex)
                node_ids.append(node_id_int)
            except:
                continue
            
            # Create filtered node data
            ts_seen = node_data.get('ts_seen')
            if hasattr(ts_seen, 'timestamp'):
                ts_seen = ts_seen.timestamp()
            
            ts_uplink = node_data.get('ts_uplink')
            if hasattr(ts_uplink, 'timestamp'):
                ts_uplink = ts_uplink.timestamp()
            
            # Check if node should be shown as offline
            show_as_offline = False
            if nodes_offline_age != 'never' and ts_seen:
                if now - ts_seen > nodes_offline_age:
                    show_as_offline = True
            
            # Calculate active status
            active_threshold = int(config.get('server', 'node_activity_prune_threshold', fallback=7200))
            is_active = ts_seen and (now - ts_seen) <= active_threshold
            
            filtered_node_data = {
                'id': node_id_hex,
                'short_name': node_data.get('short_name', ''),
                'long_name': node_data.get('long_name', ''),
                'last_seen': ts_seen,
                'ts_uplink': ts_uplink,
                'online': is_active,
                'channel': node_data.get('channel'),
                'channel_name': utils.get_channel_name(node_data.get('channel')) if node_data.get('channel') else 'Unknown',
                'has_default_channel': node_data.get('has_default_channel'),
                'num_online_local_nodes': node_data.get('num_online_local_nodes'),
                'region': node_data.get('region'),
                'modem_preset': node_data.get('modem_preset'),
                'show_as_offline': show_as_offline,
                'zero_hop_data': {'heard': [], 'heard_by': []},
                'neighbors': []
            }
            
            # Add position if available
            position = node_data.get('position')
            if position and isinstance(position, dict):
                latitude = position.get('latitude')
                longitude = position.get('longitude')
                if latitude is not None and longitude is not None:
                    filtered_node_data['position'] = [longitude, latitude]
                else:
                    filtered_node_data['position'] = None
            else:
                filtered_node_data['position'] = None
            
            filtered_nodes[node_id_hex] = filtered_node_data
        
        logging.info(f"Map API filtered to {len(filtered_nodes)} nodes")
        
        # Node processing is now done above in the filtering loop
        
        # Use existing functions to get zero-hop and neighbor data
        zero_hop_timeout = int(config.get('server', 'zero_hop_timeout', fallback=43200))
        cutoff_time = now - zero_hop_timeout
        
        # Get zero-hop data using existing function
        zero_hop_links, zero_hop_last_heard = md.get_zero_hop_links(cutoff_time)
        
        # Get neighbor info data using existing function
        neighbor_info_links = md.get_neighbor_info_links(days=1)
        
        # Add zero-hop data to filtered nodes
        for node_id_int in node_ids:
            node_id_hex = utils.convert_node_id_from_int_to_hex(node_id_int)
            if node_id_hex in filtered_nodes:
                # Add zero-hop heard data
                if node_id_int in zero_hop_links:
                    for neighbor_id_int, link_data in zero_hop_links[node_id_int]['heard'].items():
                        neighbor_id_hex = utils.convert_node_id_from_int_to_hex(neighbor_id_int)
                        
                        # Convert last_heard to timestamp if it's a datetime object
                        last_heard_timestamp = link_data.get('last_heard', now)
                        if hasattr(last_heard_timestamp, 'timestamp'):
                            last_heard_timestamp = last_heard_timestamp.timestamp()
                        
                        zero_hop_data = {
                            'node_id': neighbor_id_hex,
                            'count': link_data.get('message_count', 1),
                            'best_snr': link_data.get('snr'),
                            'avg_snr': link_data.get('snr'),  # Use same value for avg
                            'last_rx_time': last_heard_timestamp
                        }
                        filtered_nodes[node_id_hex]['zero_hop_data']['heard'].append(zero_hop_data)
                    
                    # Add zero-hop heard_by data
                    for neighbor_id_int, link_data in zero_hop_links[node_id_int]['heard_by'].items():
                        neighbor_id_hex = utils.convert_node_id_from_int_to_hex(neighbor_id_int)
                        
                        # Convert last_heard to timestamp if it's a datetime object
                        last_heard_timestamp = link_data.get('last_heard', now)
                        if hasattr(last_heard_timestamp, 'timestamp'):
                            last_heard_timestamp = last_heard_timestamp.timestamp()
                        
                        zero_hop_data = {
                            'node_id': neighbor_id_hex,
                            'count': link_data.get('message_count', 1),
                            'best_snr': link_data.get('snr'),
                            'avg_snr': link_data.get('snr'),  # Use same value for avg
                            'last_rx_time': last_heard_timestamp
                        }
                        filtered_nodes[node_id_hex]['zero_hop_data']['heard_by'].append(zero_hop_data)
                
                # Add neighbor info data
                if node_id_int in neighbor_info_links:
                    for neighbor_id_int, link_data in neighbor_info_links[node_id_int]['heard'].items():
                        neighbor_id_hex = utils.convert_node_id_from_int_to_hex(neighbor_id_int)
                        neighbor_data = {
                            'id': neighbor_id_hex,
                            'snr': link_data.get('snr'),
                            'distance': link_data.get('distance')
                        }
                        filtered_nodes[node_id_hex]['neighbors'].append(neighbor_data)
        
        cursor.close()
        
        response = jsonify({
            'nodes': filtered_nodes,
            'filters': {
                'nodes_max_age': nodes_max_age,
                'nodes_disconnected_age': nodes_disconnected_age,
                'nodes_offline_age': nodes_offline_age,
                'channel_filter': channel_filter,
                'neighbours_max_distance': neighbours_max_distance
            },
            'timestamp': now,
            'node_count': len(filtered_nodes)
        })
        
        # Add cache headers for better performance
        response.headers['Cache-Control'] = 'public, max-age=60'
        return response
        
    except Exception as e:
        logging.error(f"Error fetching map data: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'Error fetching map data: {str(e)}'
        }), 500

@api.route('/account/change-password', methods=['POST'])
def api_change_password():
    """API endpoint to change user password."""
    user = api_auth()
    if not user:
        abort(401)
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    if not old_password or not new_password or not confirm_password:
        return jsonify({'error': 'All password fields are required'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': 'New passwords do not match'}), 400
    
    reg = Register()
    result = reg.change_password(user['email'], old_password, new_password)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result), 200

@api.route('/account/unlink-node', methods=['POST'])
def api_unlink_node():
    """API endpoint to unlink a node from user account."""
    user = api_auth()
    if not user:
        abort(401)
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    node_id = data.get('node_id')
    if not node_id:
        return jsonify({'error': 'Node ID is required'}), 400
    
    reg = Register()
    result = reg.unlink_node(user['email'], node_id)
    
    if 'error' in result:
        return jsonify(result), 400
    
    # Clear all relevant caches to ensure fresh data on next request
    try:
        from flask import current_app
        from flask_caching import Cache
        # Get the cache instance and delete the cached nodes
        cache = current_app.extensions.get('cache')
        if cache:
            # Clear the memoized cache for nodes
            cache.delete_memoized('get_cached_nodes')
            # Also clear the database-level cache in MeshData
            from meshdata import MeshData
            md = MeshData()
            if md:
                md.clear_nodes_cache()
    except Exception as e:
        logging.warning(f"Could not clear nodes cache: {e}")
        pass  # Don't fail if cache clearing fails
    
    # Add no-cache headers to the response
    response = jsonify(result)
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response, 200 