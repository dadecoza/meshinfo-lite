from flask import (
    Flask,
    send_from_directory,
    render_template,
    request,
    make_response,
    redirect,
    url_for,
    abort
)
from waitress import serve
from paste.translogger import TransLogger
import configparser
import logging
import os

import utils
import meshtastic_support
from meshdata import MeshData
from meshinfo_register import Register
from meshtastic_monday import MeshtasticMonday
from meshinfo_telemetry_graph import draw_graph
from meshinfo_los_profile import LOSProfile
from timezone_utils import convert_to_local, format_timestamp, time_ago
import json
import datetime
import time
import re

app = Flask(__name__)

# Make timezone utilities available to templates
app.jinja_env.globals.update(convert_to_local=convert_to_local)
app.jinja_env.globals.update(format_timestamp=format_timestamp)
app.jinja_env.globals.update(time_ago=time_ago)
app.jinja_env.globals.update(min=min)
app.jinja_env.globals.update(max=max)

config = configparser.ConfigParser()
config.read("config.ini")


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


# Serve static files from the root directory
@app.route('/')
def serve_index(success_message=None, error_message=None):
    md = MeshData()
    nodes = md.get_nodes()
    return render_template(
        "index.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        active_nodes=utils.active_nodes(nodes),
        timestamp=datetime.datetime.now(),
        success_message=success_message,
        error_message=error_message
    )


@app.route('/nodes.html')
def nodes():
    md = MeshData()
    nodes = md.get_nodes()
    latest = md.get_latest_node()
    return render_template(
        "nodes.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        show_inactive=False,  # Add this line
        latest=latest,
        hardware=meshtastic_support.HardwareModel,
        meshtastic_support=meshtastic_support,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )

@app.route('/allnodes.html')
def allnodes():
    md = MeshData()
    nodes = md.get_nodes()
    latest = md.get_latest_node()
    return render_template(
        "nodes.html.j2",  # Change to use nodes.html.j2
        auth=auth(),
        config=config,
        nodes=nodes,
        show_inactive=True,
        latest=latest,
        hardware=meshtastic_support.HardwareModel,
        meshtastic_support=meshtastic_support,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )


@app.route('/chat.html')
def chat():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    md = MeshData()
    nodes = md.get_nodes()
    chat_data = md.get_chat(page=page, per_page=per_page)
    
    # start_item and end_item for pagination
    chat_data['start_item'] = (page - 1) * per_page + 1 if chat_data['total'] > 0 else 0
    chat_data['end_item'] = min(page * per_page, chat_data['total'])
    
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

@app.route('/chat2.html')
def chat2():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    md = MeshData()
    nodes = md.get_nodes()
    chat_data = md.get_chat(page=page, per_page=per_page)
    
    chat_data['start_item'] = (page - 1) * per_page + 1 if chat_data['total'] > 0 else 0
    chat_data['end_item'] = min(page * per_page, chat_data['total'])
    
    return render_template(
        "chat2.html.j2",
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

@app.route('/message_map.html')
def message_map():
    message_id = request.args.get('id')
    if not message_id:
        abort(404)
        
    md = MeshData()
    nodes = md.get_nodes()
    
    # Get message and reception data
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT t.*, r.*
        FROM text t
        LEFT JOIN message_reception r ON t.message_id = r.message_id
        WHERE t.message_id = %s
    """, (message_id,))
    
    message_data = cursor.fetchall()
    if not message_data:
        abort(404)
        
    # Process message data
    message = {
        'id': message_id,
        'from_id': message_data[0]['from_id'],
        'text': message_data[0]['text'],
        'ts_created': message_data[0]['ts_created'],
        'receptions': []
    }
    
    # Only process receptions if they exist
    for reception in message_data:
        if reception['received_by_id'] is not None:  # Add this check
            message['receptions'].append({
                'node_id': reception['received_by_id'],
                'rx_snr': reception['rx_snr'],
                'rx_rssi': reception['rx_rssi'],
                'hop_start': reception['hop_start'],
                'hop_limit': reception['hop_limit'],
                'rx_time': reception['rx_time']
            })
    
    cursor.close()

    # Check if sender has position data before rendering map
    from_id = utils.convert_node_id_from_int_to_hex(message['from_id'])
    if from_id not in nodes or not nodes[from_id].get('position'):
        abort(404, description="Sender position data not available")
    
    return render_template(
        "message_map.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        message=message,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@app.route('/traceroute_map.html')
def traceroute_map():
    traceroute_id = request.args.get('id')
    if not traceroute_id:
        abort(404)
        
    md = MeshData()
    nodes = md.get_nodes()
    
    # Get traceroute data
    cursor = md.db.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM traceroute WHERE traceroute_id = %s
    """, (traceroute_id,))
    
    traceroute_data = cursor.fetchone()
    if not traceroute_data:
        abort(404)
    
    # Format the forward route data
    route = []
    if traceroute_data['route']:
        route = [int(hop) for hop in traceroute_data['route'].split(';')]
    
    # Format the return route data
    route_back = []
    if traceroute_data['route_back']:
        route_back = [int(hop) for hop in traceroute_data['route_back'].split(';')]
    
    # Format the forward SNR values
    snr_towards = []
    if traceroute_data['snr_towards']:
        snr_towards = [float(s) for s in traceroute_data['snr_towards'].split(';')]
    
    # Format the return SNR values
    snr_back = []
    if traceroute_data['snr_back']:
        snr_back = [float(s) for s in traceroute_data['snr_back'].split(';')]
    
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
    
    return render_template(
        "traceroute_map.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        traceroute=traceroute,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now()
    )

@app.route('/graph.html')
def graph():
    md = MeshData()
    nodes = md.get_nodes()
    graph = md.graph_nodes()
    return render_template(
        "graph.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        graph=graph,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )


@app.route('/map.html')
def map():
    md = MeshData()
    nodes = md.get_nodes()
    
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
        datetime=datetime,
        timestamp=datetime.datetime.now()
    )


@app.route('/neighbors.html')
def neighbors():
    view_type = request.args.get('view', 'neighbor_info')
    md = MeshData()
    nodes = md.get_nodes()
    
    zero_hop_timeout = int(config.get("server", "zero_hop_timeout", fallback=43200))
    cutoff_time = int(time.time()) - zero_hop_timeout
    
    active_nodes_with_connections = {}
    
    if view_type in ['neighbor_info', 'merged']:
        neighbor_info_nodes = {}
        for node_id, node in nodes.items():
            if node.get("active") and node.get("neighbors"):
                node_data = dict(node)
                if 'last_heard' not in node_data:
                    node_data['last_heard'] = datetime.datetime.now()
                elif isinstance(node_data['last_heard'], (int, float)):
                    node_data['last_heard'] = datetime.datetime.fromtimestamp(node_data['last_heard'])
                
                # Add heard-by data from neighbor info
                node_data['heard_by_neighbors'] = []
                for other_id, other_node in nodes.items():
                    if other_node.get("neighbors"):
                        for neighbor in other_node["neighbors"]:
                            if utils.convert_node_id_from_int_to_hex(neighbor["neighbor_id"]) == node_id:
                                node_data['heard_by_neighbors'].append({
                                    'neighbor_id': utils.convert_node_id_from_hex_to_int(other_id),
                                    'snr': neighbor["snr"],
                                    'distance': neighbor.get("distance")
                                })
                
                neighbor_info_nodes[node_id] = node_data
                
        if view_type == 'neighbor_info':
            active_nodes_with_connections = neighbor_info_nodes
    
    if view_type in ['zero_hop', 'merged']:
        cursor = md.db.cursor(dictionary=True)
        
        # First get nodes that have heard messages
        cursor.execute("""
            SELECT DISTINCT 
                received_by_id as node_id,
                MAX(rx_time) as last_heard
            FROM message_reception
            WHERE rx_time > %s
            AND (
                (hop_limit IS NULL AND hop_start IS NULL)
                OR
                (hop_start - hop_limit = 0)
            )
            GROUP BY received_by_id
        """, (cutoff_time,))
        
        zero_hop_nodes = {}
        for row in cursor.fetchall():
            node_id = utils.convert_node_id_from_int_to_hex(row['node_id'])
            if node_id in nodes and nodes[node_id].get("active"):
                node_data = dict(nodes[node_id])
                node_data['zero_hop_neighbors'] = []
                node_data['heard_by_zero_hop'] = []
                node_data['last_heard'] = datetime.datetime.fromtimestamp(row['last_heard'])
                
                # Get nodes this node heard
                cursor.execute("""
                    SELECT 
                        from_id as neighbor_id,
                        MAX(rx_snr) as snr,
                        COUNT(*) as message_count,
                        MAX(rx_time) as last_heard,
                        p1.latitude_i as lat1_i,
                        p1.longitude_i as lon1_i,
                        p2.latitude_i as lat2_i,
                        p2.longitude_i as lon2_i
                    FROM message_reception m
                    LEFT OUTER JOIN position p1 ON p1.id = m.received_by_id
                    LEFT OUTER JOIN position p2 ON p2.id = m.from_id
                    WHERE m.received_by_id = %s
                    AND m.rx_time > %s
                    AND (
                        (m.hop_limit IS NULL AND m.hop_start IS NULL)
                        OR
                        (m.hop_start - m.hop_limit = 0)
                    )
                    GROUP BY from_id, p1.latitude_i, p1.longitude_i, p2.latitude_i, p2.longitude_i
                """, (row['node_id'], cutoff_time))
                
                # Process nodes this node heard
                for neighbor in cursor.fetchall():
                    distance = None
                    if (neighbor['lat1_i'] and neighbor['lon1_i'] and 
                        neighbor['lat2_i'] and neighbor['lon2_i']):
                        distance = round(utils.distance_between_two_points(
                            neighbor['lat1_i'] / 10000000,
                            neighbor['lon1_i'] / 10000000,
                            neighbor['lat2_i'] / 10000000,
                            neighbor['lon2_i'] / 10000000
                        ), 2)
                    
                    node_data['zero_hop_neighbors'].append({
                        'neighbor_id': neighbor['neighbor_id'],
                        'snr': neighbor['snr'],
                        'message_count': neighbor['message_count'],
                        'distance': distance,
                        'last_heard': datetime.datetime.fromtimestamp(neighbor['last_heard'])
                    })
                
                # Get nodes that heard this node
                cursor.execute("""
                    SELECT 
                        received_by_id as neighbor_id,
                        MAX(rx_snr) as snr,
                        COUNT(*) as message_count,
                        MAX(rx_time) as last_heard,
                        p1.latitude_i as lat1_i,
                        p1.longitude_i as lon1_i,
                        p2.latitude_i as lat2_i,
                        p2.longitude_i as lon2_i
                    FROM message_reception m
                    LEFT OUTER JOIN position p1 ON p1.id = m.received_by_id
                    LEFT OUTER JOIN position p2 ON p2.id = m.from_id
                    WHERE m.from_id = %s
                    AND m.rx_time > %s
                    AND (
                        (m.hop_limit IS NULL AND m.hop_start IS NULL)
                        OR
                        (m.hop_start - m.hop_limit = 0)
                    )
                    GROUP BY received_by_id, p1.latitude_i, p1.longitude_i, p2.latitude_i, p2.longitude_i
                """, (row['node_id'], cutoff_time))
                
                # Process nodes that heard this node
                for neighbor in cursor.fetchall():
                    distance = None
                    if (neighbor['lat1_i'] and neighbor['lon1_i'] and 
                        neighbor['lat2_i'] and neighbor['lon2_i']):
                        distance = round(utils.distance_between_two_points(
                            neighbor['lat1_i'] / 10000000,
                            neighbor['lon1_i'] / 10000000,
                            neighbor['lat2_i'] / 10000000,
                            neighbor['lon2_i'] / 10000000
                        ), 2)
                    
                    node_data['heard_by_zero_hop'].append({
                        'neighbor_id': neighbor['neighbor_id'],
                        'snr': neighbor['snr'],
                        'message_count': neighbor['message_count'],
                        'distance': distance,
                        'last_heard': datetime.datetime.fromtimestamp(neighbor['last_heard'])
                    })
                
                if node_data['zero_hop_neighbors'] or node_data['heard_by_zero_hop']:
                    zero_hop_nodes[node_id] = node_data
        
        if view_type == 'zero_hop':
            active_nodes_with_connections = zero_hop_nodes
        else:  # merged view
            active_nodes_with_connections = neighbor_info_nodes.copy()
            for node_id, node_data in zero_hop_nodes.items():
                if node_id in active_nodes_with_connections:
                    active_nodes_with_connections[node_id]['zero_hop_neighbors'] = node_data['zero_hop_neighbors']
                    active_nodes_with_connections[node_id]['heard_by_zero_hop'] = node_data['heard_by_zero_hop']
                    if (node_data['last_heard'] > 
                        active_nodes_with_connections[node_id]['last_heard']):
                        active_nodes_with_connections[node_id]['last_heard'] = node_data['last_heard']
                else:
                    active_nodes_with_connections[node_id] = node_data
        
        cursor.close()

    return render_template(
        "neighbors.html.j2",
        auth=auth(),
        config=config,
        nodes=nodes,
        active_nodes_with_connections=active_nodes_with_connections,
        view_type=view_type,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )

@app.route('/telemetry.html')
def telemetry():
    md = MeshData()
    nodes = md.get_nodes()
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
    md = MeshData()
    page = request.args.get('page', 1, type=int)
    per_page = 100
    
    nodes = md.get_nodes()
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
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
    )


@app.route('/logs.html')
def logs():
    md = MeshData()
    logs = md.get_logs()
    return render_template(
        "logs.html.j2",
        auth=auth(),
        config=config,
        logs=logs,
        utils=utils,
        datetime=datetime.datetime,
        timestamp=datetime.datetime.now(),
        json=json
    )


@app.route('/monday.html')
def monday():
    md = MeshData()
    nodes = md.get_nodes()
    chat = md.get_chat()
    monday = MeshtasticMonday(chat).get_data()
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
    md = MeshData()
    nodes = md.get_nodes()
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
        md = MeshData()
        match = re.match(nodep, filename)
        node = match.group(1)
        nodes = md.get_nodes()
        if node not in nodes:
            abort(404)
        node_id = utils.convert_node_id_from_hex_to_int(node)
        node_telemetry = md.get_node_telemetry(node_id)
        node_route = md.get_route_coordinates(node_id)
        telemetry_graph = draw_graph(node_telemetry)
        lp = LOSProfile(nodes, node_id)
        
        # Get timeout from config
        zero_hop_timeout = int(config.get("server", "zero_hop_timeout", fallback=43200))  # Default 12 hours
        cutoff_time = int(time.time()) - zero_hop_timeout
        
        # Query for zero-hop messages heard by this node (within timeout period)
        db = md.db
        zero_hop_heard = []
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT 
                r.from_id,
                COUNT(*) AS count,
                MAX(r.rx_snr) AS best_snr,
                AVG(r.rx_snr) AS avg_snr,
                MAX(r.rx_time) AS last_rx_time
            FROM 
                message_reception r
            WHERE
                r.received_by_id = %s
                AND (
                    (r.hop_limit IS NULL AND r.hop_start IS NULL)
                    OR
                    (r.hop_start - r.hop_limit = 0)
                )
                AND r.rx_time > %s
            GROUP BY 
                r.from_id
            ORDER BY
                last_rx_time DESC
        """, (node_id, cutoff_time))
        zero_hop_heard = cursor.fetchall()
        
        # Query for zero-hop messages sent by this node and heard by others (within timeout period)
        zero_hop_heard_by = []
        cursor.execute("""
            SELECT 
                r.received_by_id,
                COUNT(*) AS count,
                MAX(r.rx_snr) AS best_snr,
                AVG(r.rx_snr) AS avg_snr,
                MAX(r.rx_time) AS last_rx_time
            FROM 
                message_reception r
            WHERE
                r.from_id = %s
                AND (
                    (r.hop_limit IS NULL AND r.hop_start IS NULL)
                    OR
                    (r.hop_start - r.hop_limit = 0)
                )
                AND r.rx_time > %s
            GROUP BY 
                r.received_by_id
            ORDER BY
                last_rx_time DESC
        """, (node_id, cutoff_time))
        zero_hop_heard_by = cursor.fetchall()
        cursor.close()
        
        return render_template(
                f"node.html.j2",
                auth=auth(),
                config=config,
                node=nodes[node],
                nodes=nodes,
                hardware=meshtastic_support.HardwareModel,
                meshtastic_support=meshtastic_support,
                los_profiles=lp.get_profiles(),
                telemetry_graph=telemetry_graph,
                node_route=node_route,
                utils=utils,
                datetime=datetime.datetime,
                timestamp=datetime.datetime.now(),
                zero_hop_heard=zero_hop_heard,
                zero_hop_heard_by=zero_hop_heard_by,
                zero_hop_timeout=zero_hop_timeout,
            )

    if re.match(userp, filename):
        match = re.match(userp, filename)
        username = match.group(1)
        md = MeshData()
        owner = md.get_user(username)
        if not owner:
            abort(404)
        nodes = md.get_nodes()
        owner_nodes = utils.get_owner_nodes(nodes, owner["email"])
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


def run():
    # Enable Waitress logging
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = int(config["webserver"]["port"])

    waitress_logger = logging.getLogger("waitress")
    waitress_logger.setLevel(logging.DEBUG)  # Enable all logs from Waitress
    #  serve(app, host="0.0.0.0", port=port)
    serve(
        TransLogger(
            app,
            setup_console_handler=False,
            logger=waitress_logger
        ),
        port=port
    )


if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read('config.ini')
    port = int(config["webserver"]["port"])
    app.run(debug=True, port=port)
