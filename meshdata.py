import configparser
import mysql.connector
import datetime
import json
import time
import utils
import logging
import re


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8")  # Convert bytes to string
        elif isinstance(obj, datetime.datetime):
            return obj.isoformat()  # Convert datetime to ISO format
        elif isinstance(obj, datetime.date):
            return obj.isoformat()  # Convert date to string
        elif isinstance(obj, set):
            return list(obj)  # Convert set to list
        # Use default serialization for other types
        return super().default(obj)


class MeshData:
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.config = config
        self.db = None
        self.connect_db()

    def __del__(self):
        if self.db:
            self.db.close()

    def int_id(self, id):
        try:
            id = id.replace("!", "")
            return int(f"0x{id}", 16)
        except Exception as e:
            pass
        return None

    def hex_id(self, id):
        return utils.convert_node_id_from_int_to_hex(id)

    def unknown(self, id):
        hexid = self.hex_id(id)
        short_name = hexid[-4:]
        long_name = f"Meshtastic {short_name}"
        return {
            "from": id,
            "decoded": {
                "json_payload": {
                    "long_name": long_name,
                    "short_name": short_name
                }
            }
        }

    def connect_db(self):
        max_retries = 5
        retry_delay = 10  # seconds
        
        for attempt in range(max_retries):
            try:
                self.db = mysql.connector.connect(
                    host=self.config["database"]["host"],
                    user=self.config["database"]["username"],
                    password=self.config["database"]["password"],
                    database=self.config["database"]["database"],
                    charset="utf8mb4"
                )
                cur = self.db.cursor()
                cur.execute("SET NAMES utf8mb4;")
                cur.close()
                return
            except mysql.connector.Error as err:
                if attempt < max_retries - 1:
                    logging.warning(f"Waiting for database to become ready. Attempt {attempt + 1}/{max_retries}")
                    time.sleep(retry_delay)
                else:
                    raise

    def get_telemetry(self, id):
        telemetry = {}
        sql = """SELECT * FROM telemetry WHERE id = %s
AND battery_level IS NOT NULL
ORDER BY telemetry_time DESC LIMIT 1"""
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        if row:
            column_names = [desc[0] for desc in cur.description]
            for i in range(1, len(row)):
                if isinstance(row[i], datetime.datetime):
                    telemetry[column_names[i]] = row[i].timestamp()
                else:
                    telemetry[column_names[i]] = row[i]
        cur.close()
        return telemetry

    def get_telemetry_all(self):
        telemetry = []
        sql = """SELECT * FROM telemetry
ORDER BY ts_created DESC LIMIT 1000"""
        cur = self.db.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        for row in rows:
            record = {}
            column_names = [desc[0] for desc in cur.description]
            for i in range(0, len(row)):
                if isinstance(row[i], datetime.datetime):
                    record[column_names[i]] = row[i].timestamp()
                else:
                    record[column_names[i]] = row[i]
            telemetry.append(record)
        cur.close()
        return telemetry

    def get_node_telemetry(self, node_id):
        telemetry = []
        sql = """SELECT * FROM telemetry
WHERE ts_created >= NOW() - INTERVAL 1 DAY
AND id = %s AND battery_level IS NOT NULL
ORDER BY ts_created"""
        params = (node_id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        for row in rows:
            record = {}
            column_names = [desc[0] for desc in cur.description]
            for i in range(0, len(row)):
                if isinstance(row[i], datetime.datetime):
                    record[column_names[i]] = row[i].timestamp()
                else:
                    record[column_names[i]] = row[i]
            telemetry.append(record)
        cur.close()
        return telemetry

    def get_position(self, id):
        position = {}
        sql = "SELECT * FROM position WHERE id = %s"
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        if row:
            column_names = [desc[0] for desc in cur.description]
            for i in range(1, len(row)):
                if isinstance(row[i], datetime.datetime):
                    position[column_names[i]] = row[i].timestamp()
                else:
                    position[column_names[i]] = row[i]
        cur.close()
        return position

    def get_neighbors(self, id):
        neighbors = []
        sql = """SELECT
    a.id,
    a.neighbor_id,
    a.snr,
    p1.latitude_i lat1_i,
    p1.longitude_i lon1_i,
    p2.latitude_i lat2_i,
    p2.longitude_i lon2_i
FROM neighborinfo a
LEFT OUTER JOIN position p1 ON p1.id = a.id
LEFT OUTER JOIN position p2 ON p2.id = a.neighbor_id
WHERE a.id = %s
AND a.ts_created < NOW() - INTERVAL 1 DAY
"""
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        for row in rows:
            record = {}
            for i in range(1, len(row)):
                if isinstance(row[i], datetime.datetime):
                    record[column_names[i]] = row[i].timestamp()
                else:
                    record[column_names[i]] = row[i]

            if record["lat1_i"] and record["lon1_i"] and \
                    record["lat2_i"] and record["lon2_i"]:
                distance = round(utils.distance_between_two_points(
                    record["lat1_i"] / 10000000,
                    record["lon1_i"] / 10000000,
                    record["lat2_i"] / 10000000,
                    record["lon2_i"] / 10000000
                ), 2)
            else:
                distance = None
            record["distance"] = distance
            del record["lat1_i"]
            del record["lon1_i"]
            del record["lat2_i"]
            del record["lon2_i"]
            neighbors.append(record)
        cur.close()
        return neighbors

    def get_traceroutes(self, page=1, per_page=25):
        """Get paginated traceroutes with SNR information."""
        # Get total count first
        cur = self.db.cursor()
        cur.execute("SELECT COUNT(*) FROM traceroute")
        total = cur.fetchone()[0]
        
        # Get paginated results with all fields
        sql = """SELECT traceroute_id, from_id, to_id, route, route_back,
            snr_towards, snr_back, success, channel, hop_limit, ts_created
            FROM traceroute 
            ORDER BY ts_created DESC
            LIMIT %s OFFSET %s"""
        
        offset = (page - 1) * per_page
        cur.execute(sql, (per_page, offset))
        rows = cur.fetchall()
        
        traceroutes = []
        for row in rows:
            traceroutes.append({
                "id": row[0],
                "from_id": row[1],
                "to_id": row[2],
                "route": [int(a) for a in row[3].split(";")] if row[3] else [],
                "route_back": [int(a) for a in row[4].split(";")] if row[4] else [],
                "snr_towards": [float(s) for s in row[5].split(";")] if row[5] else [],
                "snr_back": [float(s) for s in row[6].split(";")] if row[6] else [],
                "success": row[7],
                "channel": row[8],
                "hop_limit": row[9],
                "ts_created": row[10].timestamp()
            })
        cur.close()
        
        return {
            "items": traceroutes,
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
            "has_prev": page > 1,
            "has_next": page * per_page < total,
            "prev_num": page - 1,
            "next_num": page + 1
        }

    def iter_pages(current_page, total_pages, left_edge=2, left_current=2, right_current=2, right_edge=2):
        """Helper function to generate page numbers for pagination."""
        last = 0
        for num in range(1, total_pages + 1):
            if (num <= left_edge or
                (current_page - left_current - 1 < num < current_page + right_current) or
                num > total_pages - right_edge):
                if last + 1 != num:
                    yield None
                yield num
                last = num

    def get_nodes(self, active=False):
        nodes = {}
        active_threshold = int(
            self.config["server"]["node_activity_prune_threshold"]
        )
        # Modified to include all nodes but still mark active status
        all_sql = """SELECT n.*, u.username owner_username,
            CASE WHEN n.ts_seen > FROM_UNIXTIME(%s) THEN 1 ELSE 0 END as is_active
        FROM nodeinfo n 
        LEFT OUTER JOIN meshuser u ON n.owner = u.email"""
        
        cur = self.db.cursor()
        timeout = time.time() - active_threshold
        params = (timeout, )
        cur.execute(all_sql, params)
        rows = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        
        for row in rows:
            record = {}
            for i in range(len(row)):
                if isinstance(row[i], datetime.datetime):
                    record[column_names[i]] = row[i].timestamp()
                else:
                    record[column_names[i]] = row[i]
            
            # Use the is_active field from the query
            is_active = bool(record.get("is_active", 0))
            record["telemetry"] = self.get_telemetry(row[0])
            record["neighbors"] = self.get_neighbors(row[0])
            record["position"] = self.get_position(row[0])
            if record["position"]:
                if record["position"]["latitude_i"]:
                    record["position"]["latitude"] = \
                        record["position"]["latitude_i"] / 10000000
                else:
                    record["position"]["latitude"] = None
                if record["position"]["longitude_i"]:
                    record["position"]["longitude"] = \
                        record["position"]["longitude_i"] / 10000000
                else:
                    record["position"]["longitude"] = None
            record["role"] = record["role"] or 0
            record["active"] = is_active
            record["last_seen"] = utils.time_since(record["ts_seen"])
            node_id = utils.convert_node_id_from_int_to_hex(row[0])
            nodes[node_id] = record
        
        cur.close()
        return nodes

    def get_chat(self, page=1, per_page=50):
        """Get paginated chat messages with reception data."""
        # Get total count first
        cur = self.db.cursor()
        cur.execute("SELECT COUNT(DISTINCT t.message_id) FROM text t")
        total = cur.fetchone()[0]
        
        # Get paginated results with reception data
        sql = """
        SELECT t.*,
            GROUP_CONCAT(
                CONCAT_WS(':', r.received_by_id, r.rx_snr, r.rx_rssi, r.hop_limit, r.hop_start)
                SEPARATOR '|'
            ) AS reception_data
        FROM text t
        LEFT JOIN message_reception r ON t.message_id = r.message_id
        GROUP BY t.message_id, t.from_id, t.to_id, t.text, t.ts_created
        ORDER BY t.ts_created DESC
        LIMIT %s OFFSET %s
        """
        
        offset = (page - 1) * per_page
        cur = self.db.cursor()
        cur.execute(sql, (per_page, offset))
        rows = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        
        chats = []
        prev_key = ""
        for row in rows:
            record = {}
            for i in range(len(row)):
                col = column_names[i]
                if isinstance(row[i], datetime.datetime):
                    record[col] = row[i].timestamp()
                else:
                    record[col] = row[i]
            
            # Parse reception information
            record["receptions"] = []
            receptions_str = record.get("reception_data")
            if receptions_str:
                for reception in receptions_str.split("|"):
                    if reception and reception.count(':') >= 2:
                        try:
                            parts = reception.split(":")
                            node_id = parts[0]
                            snr = parts[1]
                            rssi = parts[2]
                            hop_limit = parts[3] if len(parts) > 3 else None
                            hop_start = parts[4] if len(parts) > 4 else None
                            
                            reception_data = {
                                "node_id": int(node_id),
                                "rx_snr": float(snr),
                                "rx_rssi": int(rssi),
                                "hop_limit": int(hop_limit) if hop_limit and hop_limit != "None" else None,
                                "hop_start": int(hop_start) if hop_start and hop_start != "None" else None
                            }
                            record["receptions"].append(reception_data)
                        except (ValueError, TypeError):
                            continue
                            
            record["from"] = self.hex_id(record["from_id"])
            record["to"] = self.hex_id(record["to_id"])
            msg_key = f"{record['from']}{record['to']}{record['text']}{record['message_id']}"
            if msg_key != prev_key:
                chats.append(record)
                prev_key = msg_key
        
        cur.close()
        
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

    def get_route_coordinates(self, id):
        sql = """SELECT longitude_i, latitude_i
FROM positionlog WHERE id = %s
AND source = 'position'
ORDER BY ts_created DESC"""
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        coords = []
        for row in cur.fetchall():
            coords.append([
                row[0] / 10000000,
                row[1] / 10000000
            ])
        cur.close()
        return list(reversed(coords))

    def get_logs(self):
        logs = []
        sql = "SELECT * FROM meshlog ORDER BY ts_created DESC"
        cur = self.db.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        for row in rows:
            record = {}
            for i in range(len(row)):
                col = column_names[i]
                if isinstance(row[i], datetime.datetime):
                    record[col] = row[i].timestamp()
                else:
                    record[col] = row[i]
            logs.append(record)
        return logs

    def get_latest_node(self):
        sql = """select id, ts_created from nodeinfo
where id <> 4294967295 order by ts_created desc limit 1"""
        cur = self.db.cursor()
        cur.execute(sql)
        row = cur.fetchone()
        latest = {}
        if row:
            latest = {
                "id": row[0],
                "ts_created": row[1].timestamp()
            }
        cur.close()
        return latest

    def get_user(self, username):
        sql = "SELECT * FROM meshuser WHERE username=%s"
        params = (username, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        column_names = [desc[0] for desc in cur.description]
        record = {}
        if row:
            for i in range(len(row)):
                col = column_names[i]
                if isinstance(row[i], datetime.datetime):
                    record[col] = row[i].timestamp()
                else:
                    record[col] = row[i]
        cur.close()
        return record

    def update_geocode(self, id, lat, lon):
        if self.config["geocoding"]["enabled"] != "true":
            return
        update = False
        sql = """SELECT 1 FROM position WHERE
id=%s AND (geocoded IS NULL OR (latitude_i <> %s OR longitude_i <> %s))"""
        params = (
            id,
            lat,
            lon
        )
        cur = self.db.cursor()
        cur.execute(sql, params)
        update = True if cur.fetchone() else False
        geo = None
        cur.close()
        if not update:
            return

        latitude = lat / 10000000
        longitude = lon / 10000000
        geocoded = utils.geocode_position(
            self.config['geocoding']['apikey'],
            latitude,
            longitude
        )
        if geocoded and "display_name" in geocoded:
            geo = geocoded["display_name"]

        sql = """UPDATE position SET
latitude_i = %s,
longitude_i = %s,
geocoded = %s
WHERE id = %s
"""
        params = (
            lat,
            lon,
            geo,
            id
        )
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()

    def graph_nodes(self):
        graph_data = {
            "nodes": [],
            "edges": []
        }
        nodes = self.get_nodes()
        known_edges = []
        known_nodes = []
        for id, node in nodes.items():
            if id not in known_nodes:
                if "neighbors" not in node:
                    continue
                if not node["neighbors"]:
                    continue

                graph_data['nodes'].append(
                    {
                        "id": id,
                        "name": node['long_name'],
                        "short": node['short_name'],
                        "height": 30,
                        "stroke": None,
                        'fill': {"src": utils.graph_icon(node['long_name'])}
                    }
                )
                known_nodes.append(id)
                for neighbor in node['neighbors']:
                    neigbor_id = \
                        utils.convert_node_id_from_int_to_hex(
                            neighbor["neighbor_id"]
                        )
                    edge_key_1 = f"{id}.{neigbor_id}"
                    edge_key_2 = f"{neigbor_id}.{id}"
                    if edge_key_1 not in known_edges and \
                            edge_key_2 not in known_edges:
                        if neigbor_id in nodes:
                            graph_data["edges"].append(
                                {"from": id, "to": neigbor_id}
                            )
                            known_edges.append(edge_key_1)
                            known_edges.append(edge_key_2)
        for edge in graph_data["edges"]:
            to = edge['to']
            to_node = None
            if to in nodes:
                to_node = nodes[to]
            else:
                to_node = self.unknown(self.int_id(to))
            if to not in known_nodes:
                known_nodes.append(to)
                graph_data['nodes'].append(
                    {
                        "id": to,
                        "name": to_node['long_name'],
                        "short": to_node['short_name'],
                        "height": 30,
                        "stroke": None,
                        'fill': {"src": utils.graph_icon(to_node['long_name'])}
                    }
                )

        return graph_data

    def store_node(self, data):
        if not data:
            return
        payload = dict(data["decoded"]["json_payload"])
        expected = [
            "hw_model",
            "long_name",
            "short_name",
            "role",
            "firmware_version"
        ]
        for attr in expected:
            if attr not in payload:
                payload[attr] = None

        sql = """INSERT INTO nodeinfo (
    id,
    long_name,
    short_name,
    hw_model,
    role,
    firmware_version,
    ts_updated
)
VALUES (%s, %s, %s, %s, %s, %s, NOW())
ON DUPLICATE KEY UPDATE
long_name = VALUES(long_name),
short_name = VALUES(short_name),
hw_model = COALESCE(VALUES(hw_model), hw_model),
role = COALESCE(VALUES(role), role),
firmware_version = COALESCE(VALUES(firmware_version), firmware_version),
ts_updated = VALUES(ts_updated)"""
        values = (
            data["from"],
            payload["long_name"],
            payload["short_name"],
            payload["hw_model"],
            payload["role"],
            payload["firmware_version"]
        )
        cur = self.db.cursor()
        cur.execute(sql, values)
        self.db.commit()

    def store_position(self, data, source="position"):
        payload = dict(data["decoded"]["json_payload"])
        expected = [
            "altitude",
            "ground_speed",
            "ground_track",
            "latitude_i",
            "location_source",
            "longitude_i",
            "precision_bits",
            "time"
        ]
        if "position_precision" in payload:
            payload["precision_bits"] = payload["position_precision"]
        for attr in expected:
            if attr not in payload:
                payload[attr] = None
        if payload["latitude_i"] and payload["longitude_i"]:
            self.update_geocode(
                self.verify_node(data["from"]),
                payload["latitude_i"],
                payload["longitude_i"]
            )
        sql = """INSERT INTO position (
    id,
    altitude,
    ground_speed,
    ground_track,
    latitude_i,
    location_source,
    longitude_i,
    precision_bits,
    position_time,
    ts_updated
)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, FROM_UNIXTIME(%s), NOW())
ON DUPLICATE KEY UPDATE
altitude = VALUES(altitude),
ground_speed = VALUES(ground_speed),
ground_track = VALUES(ground_track),
latitude_i = VALUES(latitude_i),
location_source = VALUES(location_source),
longitude_i = VALUES(longitude_i),
precision_bits= VALUES(precision_bits),
position_time = VALUES(position_time),
ts_updated = VALUES(ts_updated)"""
        values = (
            self.verify_node(data["from"]),
            payload["altitude"],
            payload["ground_speed"],
            payload["ground_track"],
            payload["latitude_i"],
            payload["location_source"],
            payload["longitude_i"],
            payload["precision_bits"],
            payload["time"] or time.time()
        )
        cur = self.db.cursor()
        cur.execute(sql, values)
        self.log_position(
            data["from"],
            payload["latitude_i"],
            payload["longitude_i"],
            source
        )
        self.db.commit()

    def store_mapreport(self, data):
        self.store_node(data)
        self.store_position(data, "mapreport")

    def store_neighborinfo(self, data):
        node_id = self.verify_node(data["from"])
        payload = dict(data["decoded"]["json_payload"])
        if "neighbors" not in payload:
            return
        sql = "DELETE FROM neighborinfo WHERE id = %s"
        params = (node_id, )
        self.db.cursor().execute(sql, params)
        for neighbor in payload["neighbors"]:
            sql = """INSERT INTO neighborinfo
(id, neighbor_id, snr, ts_created) VALUES (%s, %s, %s, NOW())"""
            params = (
                node_id,
                self.verify_node(neighbor["node_id"]),
                neighbor["snr"] if "snr" in neighbor else None
            )
            self.db.cursor().execute(sql, params)
        self.db.commit()

    def store_traceroute(self, data):
        from_id = self.verify_node(data["from"])
        to_id = self.verify_node(data["to"])
        payload = dict(data["decoded"]["json_payload"])
        
        # Process forward route and SNR
        route = None
        snr_towards = None
        if "route" in payload:
            route = ";".join(str(r) for r in payload["route"])
        if "snr_towards" in payload:
            snr_towards = ";".join(str(s) for s in payload["snr_towards"])
        
        # Process return route and SNR
        route_back = None
        snr_back = None
        if "route_back" in payload:
            route_back = ";".join(str(r) for r in payload["route_back"])
        if "snr_back" in payload:
            snr_back = ";".join(str(s) for s in payload["snr_back"])

        # A traceroute is successful if we have either:
        # 1. A direct connection with SNR data in both directions
        # 2. A multi-hop route with SNR data in both directions
        is_direct = not bool(route and route_back)  # True if no hops in either direction
        
        success = False
        if is_direct:
            # For direct connections, we just need SNR data in both directions
            success = bool(snr_towards and snr_back)
        else:
            # For multi-hop routes, we need both routes and their SNR data
            success = bool(route and route_back and snr_towards and snr_back)

        # Extract additional metadata
        channel = data.get("channel", None)
        hop_limit = data.get("hop_limit", None)
        request_id = data.get("id", None)
        traceroute_time = payload.get("time", None)

        sql = """INSERT INTO traceroute
        (from_id, to_id, channel, hop_limit, success, request_id, route, route_back, 
        snr_towards, snr_back, time, ts_created)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FROM_UNIXTIME(%s), NOW())"""
        
        params = (
            from_id,
            to_id,
            channel,
            hop_limit,
            success,
            request_id,
            route,
            route_back,
            snr_towards,
            snr_back,
            traceroute_time
        )
        self.db.cursor().execute(sql, params)
        self.db.commit()

    def get_successful_traceroutes(self):
        sql = """
        SELECT 
            t.traceroute_id,
            t.from_id,
            t.to_id,
            t.route,
            t.route_back,
            t.snr,
            t.snr_back,
            t.ts_created,
            n1.short_name as from_name,
            n2.short_name as to_name
        FROM traceroute t
        JOIN nodeinfo n1 ON t.from_id = n1.id
        JOIN nodeinfo n2 ON t.to_id = n2.id
        WHERE t.route_back IS NOT NULL
        AND t.route_back != ''
        ORDER BY t.ts_created DESC
        """
        cur = self.db.cursor()
        cur.execute(sql)
        
        results = []
        column_names = [desc[0] for desc in cur.description]
        for row in cur.fetchall():
            result = dict(zip(column_names, row))
            # Convert timestamp to Unix timestamp if needed
            if isinstance(result['ts_created'], datetime.datetime):
                result['ts_created'] = result['ts_created'].timestamp()
            results.append(result)
        
        cur.close()
        return results

    def store_telemetry(self, data):
        cur = self.db.cursor()
        cur.execute(f"SELECT COUNT(*) FROM telemetry")
        count = cur.fetchone()[0]
        if count >= 20000:
            cur.execute(f"""DELETE FROM telemetry
ORDER BY ts_created ASC LIMIT 1""")
        cur.close()
        self.db.commit()

        node_id = self.verify_node(data["from"])
        payload = dict(data["decoded"]["json_payload"])

        data = {
            "air_util_tx": None,
            "battery_level": None,
            "channel_utilization": None,
            "uptime_seconds": None,
            "voltage": None,
            "temperature": None,
            "relative_humidity": None,
            "barometric_pressure": None,
            "gas_resistance": None,
            "current": None
        }

        metrics = [
            "device_metrics",
            "environment_metrics"
        ]
        for metric in metrics:
            if metric not in payload:
                continue
            for key in data:
                if key in payload[metric]:
                    data[key] = payload[metric][key]

        sql = """INSERT INTO telemetry
(id, air_util_tx, battery_level, channel_utilization,
uptime_seconds, voltage, temperature, relative_humidity,
barometric_pressure, gas_resistance, current, telemetry_time)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, FROM_UNIXTIME(%s))
"""
        params = (
            node_id,
            data["air_util_tx"],
            data["battery_level"],
            data["channel_utilization"],
            data["uptime_seconds"],
            data["voltage"],
            data["temperature"],
            data["relative_humidity"],
            data["barometric_pressure"],
            data["gas_resistance"],
            data["current"],
            payload["time"]
        )
        self.db.cursor().execute(sql, params)
        self.db.commit()

    def store_text(self, data, topic):
        """Store text message."""
        if "from" not in data or "to" not in data or "decoded" not in data:
            return
        if "json_payload" not in data["decoded"] or "text" not in data["decoded"]["json_payload"]:
            return
                
        from_id = data["from"]
        to_id = data["to"]
        text = data["decoded"]["json_payload"]["text"]
        channel = data.get("channel", 0)
        message_id = data.get("id")

        if not message_id:  # Skip messages without ID
            return

        # Check if message already exists
        cur = self.db.cursor()
        cur.execute("SELECT 1 FROM text WHERE message_id = %s", (message_id,))
        exists = cur.fetchone()
        cur.close()

        if not exists:
            # Store the message only if it doesn't exist
            sql = """INSERT INTO text
            (from_id, to_id, text, channel, message_id, ts_created)
            VALUES (%s, %s, %s, %s, %s, NOW())"""
            params = (from_id, to_id, text, channel, message_id)
            cur = self.db.cursor()
            cur.execute(sql, params)
            cur.close()
            self.db.commit()

        # Reception information is now handled by the main store() method
        # No need to duplicate that code here
        
        # Check for meshinfo command
        if isinstance(text, bytes):
            text = text.decode()
        match = re.search(r"meshinfo (\d{4})", text, re.IGNORECASE)
        if match:
            otp = match.group(1)
            node = from_id
            self.claim_node(node, otp)

    def claim_node(self, node, otp):
        sql = """SELECT email FROM meshuser
WHERE otp = %s"""
        params = (otp, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        owner = row[0] if row else None
        cur.close()
        if not owner:
            return
        sql = """UPDATE meshuser
SET otp = NULL WHERE email = %s
"""
        params = (owner, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()

        sql = """UPDATE nodeinfo
SET owner = %s WHERE id = %s"""
        params = (
            owner,
            node
        )
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()

    def verify_node(self, id, via=None):
        query = "SELECT 1 FROM nodeinfo where id = %s"
        param = (id, )
        cur = self.db.cursor()
        cur.execute(query, param)
        found = True if cur.fetchone() else False
        cur.close()
        if not found:
            self.store_node(self.unknown(id))
        else:
            if via:
                sql = """UPDATE nodeinfo SET
ts_seen = NOW(), updated_via = %s WHERE id = %s"""
                param = (via, id)
            else:
                sql = "UPDATE nodeinfo SET ts_seen = NOW() WHERE id = %s"
                param = (id, )
            cur = self.db.cursor()
            cur.execute(sql, param)
            cur.close()
        return id

    def log_data(self, topic, data):
        cur = self.db.cursor()
        cur.execute(f"SELECT COUNT(*) FROM meshlog")
        count = cur.fetchone()[0]
        if count >= 1000:
            cur.execute(f"DELETE FROM meshlog ORDER BY ts_created ASC LIMIT 1")
        self.db.commit()

        sql = "INSERT INTO meshlog (topic, message) VALUES (%s, %s)"
        params = (topic, json.dumps(data, indent=4, cls=CustomJSONEncoder))
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()
        logging.debug(json.dumps(data, indent=4, cls=CustomJSONEncoder))

    def log_position(self, id, lat, lon, source):
        if not lat or not lon:
            return
        sql = """DELETE FROM positionlog
WHERE ts_created < NOW() - INTERVAL 1 DAY
AND id = %s"""
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()
        moved = True
        sql = """SELECT latitude_i, longitude_i FROM positionlog
WHERE id = %s ORDER BY ts_created DESC LIMIT 1"""
        params = (id, )
        cur = self.db.cursor()
        cur.execute(sql, params)
        row = cur.fetchone()
        if row and row[0] == lat and row[1] == lon:
            moved = False
        cur.close()
        if not moved:
            return
        sql = """INSERT INTO positionlog
(id, latitude_i, longitude_i, source) VALUES (%s, %s, %s, %s)"""
        params = (id, lat, lon, source)
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()
        logging.info(f"Position updated for {id}")

    def store(self, data, topic):
        if not data:
            return
        self.log_data(topic, data)
        if "from" in data:
            frm = data["from"]
            via = self.int_id(topic.split("/")[-1])
            self.verify_node(frm, via)
        
        # Extract common hop information before processing specific message types
        message_id = data.get("id")
        hop_limit = data.get("hop_limit")
        hop_start = data.get("hop_start")
        rx_snr = data.get("rx_snr")
        rx_rssi = data.get("rx_rssi")
        
        # Store reception information if this is a received message with SNR/RSSI data
        if message_id and rx_snr is not None and rx_rssi is not None:
            received_by = None
            # Try to determine the receiving node from the topic
            topic_parts = topic.split("/")
            if len(topic_parts) > 1:
                received_by = self.int_id(topic_parts[-1])
                
            if received_by and received_by != data.get("from"):  # Don't store reception by sender
                self.store_reception(message_id, data["from"], received_by, rx_snr, rx_rssi, 
                                    data.get("rx_time"), hop_limit, hop_start)
        
        # Continue with the regular message type processing
        tp = data["type"]
        if tp == "nodeinfo":
            self.store_node(data)
        elif tp == "position":
            self.store_position(data)
        elif tp == "mapreport":
            self.store_mapreport(data)
        elif tp == "neighborinfo":
            self.store_neighborinfo(data)
        elif tp == "traceroute":
            self.store_traceroute(data)
        elif tp == "telemetry":
            self.store_telemetry(data)
        elif tp == "text":
            self.store_text(data, topic)  # Only one text handler, with topic parameter

    def store_reception(self, message_id, from_id, received_by_id, rx_snr, rx_rssi, rx_time, hop_limit, hop_start):
        """Store reception information for any message type with hop data."""
        sql = """INSERT INTO message_reception
        (message_id, from_id, received_by_id, rx_snr, rx_rssi, rx_time, hop_limit, hop_start)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        rx_snr = VALUES(rx_snr),
        rx_rssi = VALUES(rx_rssi),
        rx_time = VALUES(rx_time),
        hop_limit = VALUES(hop_limit),
        hop_start = VALUES(hop_start)"""
        params = (
            message_id,
            from_id,
            received_by_id,
            rx_snr,
            rx_rssi,
            rx_time,
            hop_limit,
            hop_start
        )
        cur = self.db.cursor()
        cur.execute(sql, params)
        cur.close()
        self.db.commit()

    def setup_database(self):
        creates = [
            """CREATE TABLE IF NOT EXISTS meshuser (
    email VARCHAR(255) PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password BINARY(60) NOT NULL,
    verification CHAR(4),
    otp CHAR(4),
    status VARCHAR(12) DEFAULT 'CREATED',
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ts_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (username),
    INDEX idx_meshuser_username (username)
)""",
            """CREATE TABLE IF NOT EXISTS nodeinfo (
    id INT UNSIGNED PRIMARY KEY,
    long_name VARCHAR(40) NOT NULL,
    short_name VARCHAR(5) NOT NULL,
    hw_model INT UNSIGNED,
    role INT UNSIGNED,
    firmware_version VARCHAR(40),
    owner VARCHAR(255),
    updated_via INT UNSIGNED,
    ts_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ts_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner) REFERENCES meshuser(email)
)""",
            """CREATE TABLE IF NOT EXISTS position (
    id INT UNSIGNED PRIMARY KEY,
    altitude INT,
    ground_speed INT,
    ground_track INT,
    latitude_i INT,
    longitude_i INT,
    location_source INT,
    precision_bits INT UNSIGNED,
    position_time TIMESTAMP,
    geocoded VARCHAR(255),
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ts_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)""",
            """CREATE TABLE IF NOT EXISTS neighborinfo (
    id INT UNSIGNED,
    neighbor_id INT UNSIGNED,
    snr INT SIGNED,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, neighbor_id)
)""",
            """CREATE TABLE IF NOT EXISTS traceroute (
    from_id INT UNSIGNED NOT NULL,
    to_id INT UNSIGNED NOT NULL,
    route VARCHAR(255),
    snr VARCHAR(255),
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)""",
            """CREATE TABLE IF NOT EXISTS telemetry (
    id INT UNSIGNED NOT NULL,
    air_util_tx FLOAT(10, 7),
    battery_level INT,
    channel_utilization FLOAT(10, 7),
    uptime_seconds INT UNSIGNED,
    voltage FLOAT(10, 7),
    temperature FLOAT(10, 7),
    relative_humidity FLOAT(10, 7),
    barometric_pressure FLOAT(12, 7),
    gas_resistance DOUBLE,
    current FLOAT(10, 7),
    telemetry_time TIMESTAMP,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_telemetry_id (id)
)
""",
            """CREATE TABLE IF NOT EXISTS text (
    from_id INT UNSIGNED NOT NULL,
    to_id INT UNSIGNED NOT NULL,
    channel INT UNSIGNED NOT NULL,
    text VARCHAR(255),
    message_id BIGINT,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_text_message_id (message_id)
)""",
            """CREATE TABLE IF NOT EXISTS  meshlog (
    topic varchar(255) not null,
    message text,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)""",
            """CREATE TABLE IF NOT EXISTS  positionlog (
    id INT UNSIGNED NOT NULL,
    latitude_i INT NOT NULL,
    longitude_i INT NOT NULL,
    source VARCHAR(35) NOT NULL,
    ts_created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, ts_created)
)"""
        ]
        cur = self.db.cursor()
        for create in creates:
            cur.execute(create)
        cur.close()

        # Run migrations before final commit
        try:
            # Use explicit path relative to meshdata.py location
            import os
            import sys
            migrations_path = os.path.join(os.path.dirname(__file__), 'migrations')
            sys.path.insert(0, os.path.dirname(__file__))
            import migrations.add_message_reception as add_message_reception
            add_message_reception.migrate(self.db)
        except ImportError as e:
            logging.error(f"Failed to import migration module: {e}")
            # Continue with database setup even if migration fails
            pass
        except Exception as e:
            logging.error(f"Failed to run migration: {e}")
            raise
        try:
            import migrations.add_message_reception as add_message_reception
            import migrations.add_traceroute_snr as add_traceroute_snr
            import migrations.add_traceroute_id as add_traceroute_id
            add_message_reception.migrate(self.db)
            add_traceroute_snr.migrate(self.db)
            add_traceroute_id.migrate(self.db)
        except ImportError as e:
            logging.error(f"Failed to import migration module: {e}")
            pass

        self.db.commit()

    def import_nodes(self, filename):
        fh = open(filename, "r")
        j = json.loads(fh.read())
        fh.close()
        records = []
        for node_id in j:
            record = {}
            node = j[node_id]
            int_id = self.int_id(node_id)
            record["id"] = int_id
            record["long_name"] = node["longname"]
            record["short_name"] = node["shortname"]
            record["hw_model"] = node["hardware"]
            record["role"] = node["role"] if "role" in node else 0
            if "mapreport" in node and "firmware_version" in node["mapreport"]:
                record["firmware_version"] = \
                    node["mapreport"]["firmware_version"]
            else:
                record["firmware_version"] = None
            records.append(record)

        for record in records:
            sql = """INSERT INTO nodeinfo (
    id,
    long_name,
    short_name,
    hw_model,
    role,
    firmware_version,
    ts_updated
)
VALUES (%s, %s, %s, %s, %s, %s, NOW())
ON DUPLICATE KEY UPDATE
long_name = VALUES(long_name),
short_name = VALUES(short_name),
hw_model = COALESCE(VALUES(hw_model), hw_model),
role = COALESCE(VALUES(role), role),
firmware_version = COALESCE(VALUES(firmware_version), firmware_version),
ts_updated = VALUES(ts_updated)"""
            values = (
                record["id"],
                record["long_name"],
                record["short_name"],
                record["hw_model"],
                record["role"],
                record["firmware_version"]
            )
            cur = self.db.cursor()
            cur.execute(sql, values)
        self.db.commit()

    def import_chat(self, filename):
        fh = open(filename, "r")
        j = json.loads(fh.read())
        fh.close()
        records = []
        for channel in j["channels"]:
            for message in j["channels"][channel]["messages"]:
                records.append({
                    "from_id": self.int_id(message["from"]),
                    "to_id": self.int_id(message["to"]),
                    "channel": channel,
                    "text": message["text"],
                    "ts_created": message["timestamp"]
                })
        sorted_records = sorted(
            records,
            key=lambda x: x["ts_created"],
            reverse=True
        )
        sql = """INSERT into text (from_id, to_id, channel, text, ts_created)
VALUES (%s, %s, %s, %s, FROM_UNIXTIME(%s))
"""
        total = len(sorted_records)
        count = 1
        for record in sorted_records:
            params = (
                record["from_id"],
                record["to_id"],
                record["channel"],
                record["text"],
                record["ts_created"]
            )
            print(f"Writing record {count} of {total} ...")
            count += 1
            try:
                cur = self.db.cursor()
                cur.execute(sql, params)
                cur.close()
            except Exception as e:
                print(f"failed to write record.")
        self.db.commit()


def create_database():
    config = configparser.ConfigParser()
    config.read('config.ini')

    db = mysql.connector.connect(
        host="db",
        user="root",
        password="passw0rd",
    )
    sqls = [
        f"""CREATE DATABASE IF NOT EXISTS {config["database"]["database"]}""",
        f"""CREATE USER IF NOT EXISTS '{config["database"]["username"]}'@'%'
IDENTIFIED BY '{config["database"]["password"]}'""",
        f"""GRANT ALL ON {config["database"]["username"]}.*
TO '$DB_USER'@'%'""",
        f"""ALTER DATABASE {config["database"]["database"]}
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"""
    ]
    for sql in sqls:
        cur = db.cursor()
        cur.execute(sql)
        cur.close()
    db.commit()


if __name__ == "__main__":
    md = MeshData()
    md.setup_database()
