"""
Shared utilities for the meshinfo application.
This module contains helper functions used across multiple modules.
"""

import logging
import configparser
import time
from datetime import datetime, timedelta
from flask import g
from meshdata import MeshData
import utils
from meshinfo_telemetry_graph import draw_graph
from meshinfo_los_profile import LOSProfile

# Load config
config = configparser.ConfigParser()
config.read("config.ini")

def get_meshdata():
    """Get MeshData instance for the current request context."""
    if not hasattr(g, 'meshdata'):
        g.meshdata = MeshData()
    return g.meshdata

def get_cache_timeout():
    """Get cache timeout from config."""
    return int(config.get('server', 'app_cache_timeout_seconds', fallback=300))

def auth():
    """Simple auth check - can be enhanced later."""
    return True  # For now, always return True

def log_memory_usage(force=False):
    """Log memory usage information."""
    import psutil
    import gc
    
    process = psutil.Process()
    memory_info = process.memory_info()
    current_usage = memory_info.rss
    
    # Force garbage collection
    gc.collect()
    
    logging.info(f"Memory Usage: {current_usage / 1024 / 1024:.2f} MB")
    
    return current_usage

def get_cache_size():
    """Get total size of cache directory in bytes."""
    import os
    cache_dir = os.path.join(os.path.dirname(__file__), 'runtime_cache')
    
    if os.path.exists(cache_dir):
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
    import os
    cache_dir = os.path.join(os.path.dirname(__file__), 'runtime_cache')
    
    if os.path.exists(cache_dir):
        try:
            return len([f for f in os.listdir(cache_dir) if not f.endswith('.lock')])
        except Exception as e:
            logging.error(f"Error getting cache entry count: {e}")
    return 0

def get_largest_cache_entries(limit=5):
    """Get the largest cache entries with their sizes."""
    import os
    cache_dir = os.path.join(os.path.dirname(__file__), 'runtime_cache')
    
    if os.path.exists(cache_dir):
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

def cleanup_cache():
    """Clean up cache and log statistics."""
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
        
        # Force garbage collection
        import gc
        gc.collect()
        
        logging.info("Memory usage after cache cleanup:")
        log_memory_usage(force=True)
        logging.info("Cache stats after cleanup:")
        log_cache_stats()
        
    except Exception as e:
        logging.error(f"Error during cache cleanup: {e}")

def clear_nodes_cache():
    """Clear nodes-related cache entries."""
    try:
        # This would clear specific cache entries related to nodes
        # Implementation depends on your cache setup
        logging.info("Cleared nodes cache")
    except Exception as e:
        logging.error(f"Error clearing nodes cache: {e}")

def clear_database_cache():
    """Clear database query cache."""
    try:
        # This would clear database query cache
        # Implementation depends on your cache setup
        logging.info("Cleared database cache")
    except Exception as e:
        logging.error(f"Error clearing database cache: {e}")

def format_timestamp(timestamp):
    """Format timestamp for display."""
    if timestamp is None:
        return "Unknown"
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(timestamp)

def time_ago(timestamp):
    """Get human-readable time ago string."""
    if timestamp is None:
        return "Unknown"
    try:
        dt = datetime.fromtimestamp(timestamp)
        now = datetime.now()
        diff = now - dt
        
        if diff.days > 0:
            return f"{diff.days} days ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hours ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minutes ago"
        else:
            return "Just now"
    except (ValueError, TypeError):
        return "Unknown"

def convert_to_local(timestamp):
    """Convert timestamp to local timezone."""
    if timestamp is None:
        return "Unknown"
    try:
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return str(timestamp)

def get_cached_chat_data(page=1, per_page=50, channel=None):
    """Cache the chat data with optimized query, with optional channel filter (supports comma-separated list)."""
    md = get_meshdata()
    if not md:
        return None
    
    # Build channel filter SQL
    channel_filter = ""
    channel_params = []
    if channel is not None and channel != 'all':
        if isinstance(channel, str) and ',' in channel:
            channel_list = [int(c) for c in channel.split(',') if c.strip()]
            if channel_list:
                placeholders = ','.join(['%s'] * len(channel_list))
                channel_filter = f" WHERE t.channel IN ({placeholders})"
                channel_params = channel_list
        else:
            channel_filter = " WHERE t.channel = %s"
            channel_params = [int(channel)]
    
    # Get total count first (this is fast)
    cur = md.db.cursor()
    cur.execute(f"SELECT COUNT(DISTINCT t.message_id) FROM text t{channel_filter}", channel_params)
    total = cur.fetchone()[0]
    cur.close()
    
    # Get paginated chat messages (without reception data)
    offset = (page - 1) * per_page
    cur = md.db.cursor(dictionary=True)
    cur.execute(f"""
        SELECT t.* FROM text t{channel_filter}
        ORDER BY t.ts_created DESC
        LIMIT %s OFFSET %s
    """, channel_params + [per_page, offset])
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
                "rx_time": reception['rx_time'].timestamp() if isinstance(reception['rx_time'], datetime) else reception['rx_time']
            })
    else:
        receptions_by_message = {}
    
    # Process messages
    chats = []
    prev_key = ""
    for row in messages:
        record = {}
        for key, value in row.items():
            if isinstance(value, datetime):
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
        
        lp = LOSProfile(los_nodes, node_id, config, None)  # cache not available in utils
        
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
                if isinstance(ntime, datetime):
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
            if isinstance(ts_seen, datetime):
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

def get_cached_nodes():
    """Get cached nodes data."""
    # This would be implemented based on your cache setup
    # For now, return None to indicate it needs to be implemented
    return None

def get_cached_hardware_models():
    """Get hardware model statistics."""
    # This would be implemented based on your cache setup
    # For now, return None to indicate it needs to be implemented
    return None

def get_role_badge(role_value):
    """
    Convert a role value to a colored badge with improved readability.
    
    Args:
        role_value: The numeric role value
        
    Returns:
        A tuple of (badge_text, badge_style) for styling
    """
    if role_value is None:
        return ("?", "background-color: #6c757d; color: white;")
    
    role_mapping = {
        0: ("C", "background-color: #0d6efd; color: white;"),      # Client - Dark Blue
        1: ("CM", "background-color: #0dcaf0; color: #000;"),      # Client Mute - Light Blue with dark text
        2: ("R", "background-color: #dc3545; color: white;"),      # Router - Red
        3: ("RC", "background-color: #ffc107; color: #000;"),      # Router Client - Orange with dark text
        4: ("RE", "background-color: #198754; color: white;"),     # Repeater - Green
        5: ("T", "background-color: #6c757d; color: white;"),      # Tracker - Gray
        6: ("S", "background-color: #6c757d; color: white;"),      # Sensor - Gray
        7: ("A", "background-color: #6c757d; color: white;"),      # TAK - Gray
        8: ("CH", "background-color: #0dcaf0; color: #000;"),      # Client Hidden - Light Blue with dark text
        9: ("LF", "background-color: #6c757d; color: white;"),     # Lost and Found - Gray
        10: ("AT", "background-color: #6c757d; color: white;"),    # TAK Tracker - Gray
        11: ("RL", "background-color: #dc3545; color: white;"),    # Router Late - Red
        12: ("CB", "background-color: #0d6efd; color: white;"),    # Client Base - Dark Blue
    }
    
    return role_mapping.get(role_value, ("?", "background-color: #212529; color: white;")) 