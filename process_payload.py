import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2
from google.protobuf.json_format import MessageToJson
from meshdata import MeshData
import configparser
import json
import logging

config = configparser.ConfigParser()
config.read("config.ini")

DEFAULT_KEY = config["mesh"]["channel_key"]


def decrypt_packet(mp):
    key_bytes = base64.b64decode(DEFAULT_KEY)
    nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
    nonce_from_node = getattr(mp, "from").to_bytes(8, "little")
    nonce = nonce_packet_id + nonce_from_node
    cipher = Cipher(
        algorithms.AES(key_bytes),
        modes.CTR(nonce),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(
        getattr(mp, "encrypted")
    ) + decryptor.finalize()
    data = mesh_pb2.Data()
    data.ParseFromString(decrypted_bytes)
    mp.decoded.CopyFrom(data)
    return mp


def get_packet(payload):
    mp = None
    try:
        se = mqtt_pb2.ServiceEnvelope()
        se.ParseFromString(payload)
        mp = se.packet
        
        # Extract hop information if available
        try:
            if hasattr(mp, 'hop_limit'):
                mp.hop_limit = getattr(mp, 'hop_limit', 0)
            else:
                mp.hop_limit = None
                
            if hasattr(mp, 'hop_start'):
                mp.hop_start = getattr(mp, 'hop_start', 0)
            else:
                mp.hop_start = None
                
        except Exception as e:
            if config.get("server", "debug") == "true":
                logging.debug(f"Hop information extraction failed: {e}")
            mp.hop_limit = None
            mp.hop_start = None
            
        if mp.HasField("encrypted") and not mp.HasField("decoded"):
            return decrypt_packet(mp)
    except Exception as e:
        logging.error("Failed to decode payload " + str(e))
    return mp


def to_json(msg):
    return json.loads(
        MessageToJson(
            msg,
            preserving_proto_field_name=True,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            use_integers_for_enums=True
        )
    )


def get_data(msg):
    try:
        j = to_json(msg)
        if "decoded" not in j:
            logging.debug("Message has no decoded payload")
            return None
        
        # Add hop information to the JSON data
        if hasattr(msg, 'hop_limit'):
            j["hop_limit"] = msg.hop_limit
        if hasattr(msg, 'hop_start'):
            j["hop_start"] = msg.hop_start
        
        portnum = j["decoded"]["portnum"]
        
        # Initialize type before the portnum checks
        j["type"] = None
        
        if portnum == portnums_pb2.NODEINFO_APP:
            j["type"] = "nodeinfo"
            j["decoded"]["json_payload"] = to_json(
                mesh_pb2.User().FromString(msg.decoded.payload)
            )
        elif portnum == portnums_pb2.MAP_REPORT_APP:
            j["type"] = "mapreport"
            j["decoded"]["json_payload"] = to_json(
                mqtt_pb2.MapReport().FromString(msg.decoded.payload)
            )
        elif portnum == portnums_pb2.TEXT_MESSAGE_APP:
            j["type"] = "text"
            j["decoded"]["json_payload"] = {
                "text": msg.decoded.payload
            }
        elif portnum == portnums_pb2.NEIGHBORINFO_APP:
            j["type"] = "neighborinfo"
            j["decoded"]["json_payload"] = to_json(
                mesh_pb2.NeighborInfo().FromString(msg.decoded.payload)
            )
        elif portnum == portnums_pb2.ROUTING_APP:
            j["type"] = "routing"
            
            # Parse the routing message
            routing_msg = mesh_pb2.Routing().FromString(msg.decoded.payload)
            routing_data = to_json(routing_msg)
            
            # Extract routing information based on actual packet structure
            routing_info = {
                "routing_data": routing_data,
                "error_reason": routing_data.get("error_reason", None),
                "request_id": j.get("request_id", None),
                "relay_node": j.get("relay_node", None),
                "hop_limit": j.get("hop_limit", None),
                "hop_start": j.get("hop_start", None),
                "hops_taken": (j.get("hop_start", 0) - j.get("hop_limit", 0)) if j.get("hop_start") is not None and j.get("hop_limit") is not None else None,
                "is_error": routing_data.get("error_reason") is not None and routing_data.get("error_reason") > 0,
                "success": routing_data.get("error_reason") is None or routing_data.get("error_reason") == 0
            }
            
            # Add error reason descriptions
            error_reason = routing_data.get("error_reason")
            if error_reason is not None:
                error_descriptions = {
                    0: "None",
                    1: "No Interface",
                    2: "No Route",
                    3: "Got Nak",
                    4: "Timeout",
                    5: "No Interface",
                    6: "No Route",
                    7: "Got Nak",
                    8: "Timeout",
                    9: "No Interface",
                    10: "No Route",
                    11: "Got Nak",
                    12: "Timeout"
                }
                routing_info["error_description"] = error_descriptions.get(error_reason, f"Unknown Error {error_reason}")
            
            j["decoded"]["json_payload"] = routing_info
        elif portnum == portnums_pb2.TRACEROUTE_APP:
            j["type"] = "traceroute"
                        
            route_discovery = mesh_pb2.RouteDiscovery().FromString(msg.decoded.payload)
            
            route_data = to_json(route_discovery)
            
            # Ensure we have all required fields with proper defaults
            route_data.setdefault("route", [])
            route_data.setdefault("route_back", [])
            route_data.setdefault("snr_towards", [])
            route_data.setdefault("snr_back", [])
            route_data.setdefault("time", None)
            
            # A traceroute is successful if we have SNR data in either direction,
            # even for direct (zero-hop) connections
            route_data["success"] = (
                (len(route_data["snr_towards"]) > 0 or len(route_data["route"]) == 0) and
                (len(route_data["snr_back"]) > 0 or len(route_data["route_back"]) == 0)
            )
            
            j["decoded"]["json_payload"] = route_data
            
            # Log the final data that will be stored
            #logging.info(f"Final traceroute data to be stored: {json.dumps(j['decoded']['json_payload'], indent=2)}")

        elif portnum == portnums_pb2.POSITION_APP:
            j["type"] = "position"
            j["decoded"]["json_payload"] = to_json(
                mesh_pb2.Position().FromString(msg.decoded.payload)
            )
        elif portnum == portnums_pb2.TELEMETRY_APP:
            j["type"] = "telemetry"
            j["decoded"]["json_payload"] = to_json(
                telemetry_pb2.Telemetry().FromString(msg.decoded.payload)
            )
        elif portnum == portnums_pb2.STORE_FORWARD_APP:
            j["type"] = "store_forward"
            # Store & Forward messages contain routing information for delayed message delivery
            # We'll log them but not store them in the database as they're internal routing messages
            j["decoded"]["json_payload"] = {
                "message": "Store & Forward routing message"
            }
            logging.debug(f"Received Store & Forward message from {j['from']} - internal routing message")
        elif portnum == portnums_pb2.RANGE_TEST_APP:
            j["type"] = "range_test"
            # Range test messages are used for testing radio range
            j["decoded"]["json_payload"] = {
                "message": "Range test message"
            }
            logging.debug(f"Received Range Test message from {j['from']}")
        elif portnum == portnums_pb2.SIMULATOR_APP:
            j["type"] = "simulator"
            # Simulator messages are used for testing
            j["decoded"]["json_payload"] = {
                "message": "Simulator message"
            }
            logging.debug(f"Received Simulator message from {j['from']}")
        elif portnum == portnums_pb2.ZPS_APP:
            j["type"] = "zps"
            # ZPS (Zero Power Sensor) messages
            j["decoded"]["json_payload"] = {
                "message": "ZPS message"
            }
            logging.debug(f"Received ZPS message from {j['from']}")
        elif portnum == portnums_pb2.POWERSTRESS_APP:
            j["type"] = "powerstress"
            # Power stress test messages
            j["decoded"]["json_payload"] = {
                "message": "Power stress test message"
            }
            logging.debug(f"Received Power Stress message from {j['from']}")
        elif portnum == portnums_pb2.RETICULUM_TUNNEL_APP:
            j["type"] = "reticulum_tunnel"
            # Reticulum tunnel messages
            j["decoded"]["json_payload"] = {
                "message": "Reticulum tunnel message"
            }
            logging.debug(f"Received Reticulum Tunnel message from {j['from']}")
        
        if j["type"]:  # Only log if we successfully determined the type
            msg_type = j["type"]
            msg_from = j["from"]
            
            if msg_type == "traceroute":
                route_info = j["decoded"]["json_payload"]
                forward_hops = len(route_info.get("route", []))
                return_hops = len(route_info.get("route_back", []))
                logging.info(f"Received traceroute from {msg_from} with {forward_hops} forward hops and {return_hops} return hops")
            elif msg_type == "routing":
                routing_info = j["decoded"]["json_payload"]
                error_reason = routing_info.get("error_reason", 0)
                error_desc = routing_info.get("error_description", "Unknown")
                hops_taken = routing_info.get("hops_taken", 0)
                relay_node = routing_info.get("relay_node", "None")
                success = routing_info.get("success", False)
                logging.info(f"Received routing from {msg_from} via relay {relay_node} with {hops_taken} hops (error: {error_desc}, success: {success})")
            elif msg_type == "text" and j.get("hop_limit") is not None and j.get("hop_start") is not None:
                hop_count = j["hop_start"] - j["hop_limit"]
                logging.info(f"Received {msg_type} from {msg_from} with {hop_count} hops ({j['hop_limit']}/{j['hop_start']})")
            else:
                logging.info(f"Received {msg_type} from {msg_from}")
        else:
            logging.warning(f"Received message with unknown portnum: {portnum}")
            
        return j
    except Exception as e:
        logging.error(f"Error processing message data: {str(e)}")
        return None


def process_payload(payload, topic, md: MeshData):
    # --- Add log at the start ---
    logger = logging.getLogger(__name__) # Get logger instance
    logger.debug(f"process_payload: Entered function for topic: {topic}")
    
    # Check if this is an ignored channel
    if "/2/e/" in topic:
        channel_name = topic.split("/")[-2]  # Get channel name from topic
        ignored_channels = config.get("channels", "ignored_channels", fallback="").split(",")
        if channel_name in ignored_channels:
            logger.debug(f"Ignoring message from channel: {channel_name}")
            return
    
    # --- End log ---
    mp = get_packet(payload)
    if mp:
        try:
            data = get_data(mp)
            if data:  # Only store if we got valid data
                logger.debug(f"process_payload: Calling md.store() for topic {topic}")
                # Use the passed-in MeshData instance
                md.store(data, topic)
            else:
                # Log topic only if debug is enabled or if it's an unsupported type
                if config.get("server", "debug") == "true":
                    logging.warning(f"Received invalid or unsupported message type on topic {topic}. Payload: {payload[:100]}...") # Log partial payload for debug
                else:
                    logger.warning(f"process_payload: get_packet returned None for topic {topic}")

        except KeyError as e:
            logging.warning(f"Failed to process message: Missing key {str(e)} in payload on topic {topic}")
        except Exception as e:
                # Log the full traceback for unexpected errors
            logging.exception(f"Unexpected error processing message on topic {topic}: {str(e)}") # Use logging.exception