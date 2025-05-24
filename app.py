@app.route('/metrics.html')
def metrics():
    md = get_meshdata()
    if not md: # Check if MeshData failed to initialize
        abort(503, description="Database connection unavailable")
    return render_template(
        "metrics.html.j2",
        auth=auth(),
        config=config,
        this_page="metrics",
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@app.route('/api/metrics')
def get_metrics():
    db = MeshData()
    # Get time_range from query params
    time_range = request.args.get('time_range', 'day')  # day, week, month
    end_time = datetime.now()
    if time_range == 'week':
        start_time = end_time - timedelta(days=7)
    elif time_range == 'month':
        start_time = end_time - timedelta(days=30)
    else:  # default to day
        start_time = end_time - timedelta(hours=24)
    metrics_avg_interval = int(config.get('server', 'metrics_average_interval', fallback=7200))
    metrics_avg_minutes = metrics_avg_interval // 60
    node_activity_prune_threshold = int(config.get('server', 'node_activity_prune_threshold', fallback=7200))

    # For day view, calculate the correct extended_start_time for all queries
    if time_range == 'day':
        window_buckets = max(1, metrics_avg_minutes // 60)
        half_window = window_buckets // 2
        extended_bucket_start = start_time - timedelta(hours=half_window)
        # Extend by even more - go back at least 48 hours to ensure we have sufficient history
        fetch_start_time = min(
            extended_bucket_start - timedelta(seconds=3 * node_activity_prune_threshold),
            start_time - timedelta(hours=48)
        )
        extended_start_time = fetch_start_time
        extended_end_time = end_time + timedelta(hours=half_window)
    else:
        extra_minutes = metrics_avg_minutes // 2
        extended_start_time = start_time - timedelta(minutes=extra_minutes)
        extended_end_time = end_time + timedelta(minutes=extra_minutes)

    # Nodes Online (per hour)
    nodes_online = db.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            COUNT(DISTINCT id) as node_count
        FROM telemetry
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Message Traffic (per hour)
    message_traffic = db.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            COUNT(*) as message_count
        FROM text
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Channel Utilization
    channel_util = db.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            AVG(channel_utilization) as avg_util
        FROM telemetry
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Battery Levels (for each node)
    battery_levels = db.execute("""
        SELECT 
            id,
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            AVG(battery_level) as avg_battery
        FROM telemetry
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY id, hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Temperature Readings
    temperature = db.execute("""
        SELECT 
            id,
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            AVG(temperature) as avg_temp
        FROM telemetry
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY id, hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Signal Strength (SNR)
    snr = db.execute("""
        SELECT 
            strftime('%Y-%m-%d %H:00', datetime(timestamp, 'unixepoch')) as hour,
            AVG(snr) as avg_snr
        FROM message_reception
        WHERE timestamp >= ? AND timestamp <= ?
        GROUP BY hour
        ORDER BY hour
    """, (int(extended_start_time.timestamp()), int(extended_end_time.timestamp())))
    
    # Process battery levels data
    battery_data = {}
    for row in battery_levels:
        if row['id'] not in battery_data:
            battery_data[row['id']] = {'hours': [], 'levels': []}
        battery_data[row['id']]['hours'].append(row['hour'])
        battery_data[row['id']]['levels'].append(row['avg_battery'])
    
    # Process temperature data
    temp_data = {}
    for row in temperature:
        if row['id'] not in temp_data:
            temp_data[row['id']] = {'hours': [], 'temps': []}
        temp_data[row['id']]['hours'].append(row['hour'])
        temp_data[row['id']]['temps'].append(row['avg_temp'])
    
    # Build extended labels and data for nodes_online
    extended_labels = [row['hour'] for row in nodes_online]
    extended_data = [row['node_count'] for row in nodes_online]

    # For day view, use 'active in window' approach for nodes heard with true centered smoothing
    if time_range == 'day':
        # Calculate how many extra buckets are needed for smoothing
        window_buckets = max(1, metrics_avg_minutes // 60)
        half_window = window_buckets // 2
        # Generate all expected hourly labels from (start_time - half_window*1hr) to (end_time + half_window*1hr)
        extended_bucket_start = start_time - timedelta(hours=half_window)
        extended_bucket_end = end_time + timedelta(hours=half_window)
        expected_labels = []
        current = extended_bucket_start.replace(minute=0, second=0, microsecond=0)
        while current <= extended_bucket_end:
            expected_labels.append(current.strftime('%Y-%m-%d %H:%M'))
            current += timedelta(hours=1)
        # Extend the fetch window to cover the full activity window before the first extended bucket
        fetch_start_time = extended_bucket_start - timedelta(seconds=node_activity_prune_threshold)
        # Fetch all telemetry records in the full time range
        all_telemetry = db.execute("""
            SELECT id, timestamp FROM telemetry
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp
        """, (int(fetch_start_time.timestamp()), int(extended_bucket_end.timestamp())))
        # Convert to list of (id, datetime)
        telemetry_points = [(row['id'], datetime.fromtimestamp(row['timestamp'])) for row in all_telemetry]
        # First, get all node IDs that appeared in our data
        all_node_ids = set(node_id for node_id, _ in telemetry_points)

        # Find the earliest telemetry timestamp
        earliest_telemetry_time = min((ts for _, ts in telemetry_points), default=extended_bucket_start)

        # For the main visible time range (not the extended range), calculate the average number of
        # nodes that are typically active in any given hour
        visible_range_active_nodes = []
        for label in expected_labels:
            bucket_time = datetime.strptime(label, '%Y-%m-%d %H:%M')
            # Only consider buckets within our actual display window (not extended)
            if start_time <= bucket_time <= end_time:
                window_start = bucket_time - timedelta(seconds=node_activity_prune_threshold)
                # Only count this bucket if we have complete history for it
                if window_start >= earliest_telemetry_time:
                    active_nodes = set()
                    for node_id, ts in telemetry_points:
                        if window_start < ts <= bucket_time:
                            active_nodes.add(node_id)
                    visible_range_active_nodes.append(len(active_nodes))

        # Calculate the median of fully visible buckets with sufficient history
        if visible_range_active_nodes:
            median_active_nodes = sorted(visible_range_active_nodes)[len(visible_range_active_nodes) // 2]
        else:
            # Fallback if we somehow don't have any good buckets
            median_active_nodes = len(all_node_ids)

        # Now process all buckets, but force buckets with insufficient history to use the median
        extended_data = []
        for i, label in enumerate(expected_labels):
            bucket_time = datetime.strptime(label, '%Y-%m-%d %H:%M')
            window_start = bucket_time - timedelta(seconds=node_activity_prune_threshold)
            
            # Check if we have enough history for this bucket
            if window_start < earliest_telemetry_time:
                # No sufficient history - use the median value from good buckets
                extended_data.append(median_active_nodes)
            else:
                # Normal calculation for buckets with good history
                active_nodes = set()
                for node_id, ts in telemetry_points:
                    if window_start < ts <= bucket_time:
                        active_nodes.add(node_id)
                extended_data.append(len(active_nodes))
            
            if not has_sufficient_history:
                insufficient_history_buckets.append(i)
        
        # Fix the buckets with insufficient history by estimating based on later data
        if insufficient_history_buckets and len(extended_data) > max(insufficient_history_buckets) + 1:
            # Find the median value from buckets with sufficient history
            sufficient_buckets = [i for i in range(len(extended_data)) if i not in insufficient_history_buckets]
            if sufficient_buckets:
                sufficient_values = [extended_data[i] for i in sufficient_buckets]
                median_value = sorted(sufficient_values)[len(sufficient_values) // 2]
                
                # Replace insufficient bucket values with this median
                for i in insufficient_history_buckets:
                    if i < len(extended_data):
                        extended_data[i] = median_value
        
        # Apply smoothing to extended data with improved edge handling
        smoothed_data = moving_average_centered_with_edge_handling(extended_data, window_buckets)
        
        # Trim to original window
        trimmed_labels = []
        trimmed_data = []
        for label, value in zip(extended_labels, smoothed_data):
            label_dt = datetime.strptime(label, '%Y-%m-%d %H:%M')
            if start_time <= label_dt <= end_time:
                trimmed_labels.append(label)
                trimmed_data.append(value)
        
        # Overwrite for output
        extended_labels = trimmed_labels
        extended_data = trimmed_data

    return jsonify({
        'nodes_online': {
            'labels': extended_labels,
            'data': extended_data
        },
        'message_traffic': {
            'labels': [row['hour'] for row in message_traffic],
            'data': [row['message_count'] for row in message_traffic]
        },
        'channel_util': {
            'labels': [row['hour'] for row in channel_util],
            'data': [row['avg_util'] for row in channel_util]
        },
        'battery_levels': {
            'labels': list(set([hour for data in battery_data.values() for hour in data['hours']])),
            'datasets': [
                {
                    'node_id': node_id,
                    'data': data['levels']
                }
                for node_id, data in battery_data.items()
            ]
        },
        'temperature': {
            'labels': list(set([hour for data in temp_data.values() for hour in data['hours']])),
            'datasets': [
                {
                    'node_id': node_id,
                    'data': data['temps']
                }
                for node_id, data in temp_data.items()
            ]
        },
        'snr': {
            'labels': [row['hour'] for row in snr],
            'data': [row['avg_snr'] for row in snr]
        }
    }) 

# Moving average helper (centered, with mirrored edge handling)
def moving_average_centered_with_edge_handling(data, window_size):
    """
    Apply centered moving average with proper edge handling.
    Uses mirroring at the edges to ensure consistent smoothing.
    """
    # Get the median value for more robust padding
    # This helps avoid using outliers at the edges
    sorted_data = sorted(data)
    median_value = sorted_data[len(sorted_data) // 2]
    
    result = []
    half_window = window_size // 2
    
    # For each point, calculate the average of the window centered on that point
    for i in range(len(data)):
        window_sum = 0
        window_count = 0
        
        for j in range(i - half_window, i + half_window + 1):
            if 0 <= j < len(data):
                # Within bounds, use actual data
                window_sum += data[j]
                window_count += 1
            elif j < 0:
                # Before start, use median or first value
                window_sum += median_value  # Alternative: data[0]
                window_count += 1
            else:  # j >= len(data)
                # After end, use median or last value
                window_sum += median_value  # Alternative: data[-1]
                window_count += 1
        
        result.append(window_sum / window_count)
    
    return result