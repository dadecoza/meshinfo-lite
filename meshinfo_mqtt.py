import logging
from paho.mqtt import client as mqtt_client
from process_payload import process_payload
from meshdata import MeshData # Import MeshData
import configparser
import time


config = configparser.ConfigParser()
config.read("config.ini")
logger = logging.getLogger(__name__)

try:
    mesh_data_instance = MeshData()
    logger.info("MeshData instance created successfully.")
except Exception as e:
    logger.error(f"Fatal error: Could not initialize MeshData. Exiting. Error: {e}")
    exit(1) # Exit if we can't connect to the DB

def connect_mqtt() -> mqtt_client:
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to MQTT Broker! Return Code: %d", rc)
            # --- Add log before calling subscribe ---
            logger.info("on_connect: Attempting to subscribe...")
            try:
                subscribe(client, mesh_data_instance)
                logger.info("on_connect: subscribe() call completed.")
            except Exception as e:
                 logger.exception("on_connect: Error calling subscribe()") # Log exception if subscribe fails
            # --- End log ---
        else:
            logger.error("Failed to connect, return code %d", rc)

    def on_disconnect(client, userdata, rc):
        logger.warning(f"Disconnected with result code {rc}. Will attempt reconnect.")
        # No need for manual reconnect loop, paho handles it with reconnect_delay_set

    client = mqtt_client.Client(client_id="", clean_session=True, userdata=mesh_data_instance) # Ensure clean session if needed
    client.user_data_set(mesh_data_instance) # Redundant if passed in constructor, but safe
    if "username" in config["mqtt"] \
            and config["mqtt"]["username"] \
            and "password" in config["mqtt"] \
            and config["mqtt"]["password"]:
        logger.info("Setting MQTT username and password.")
        client.username_pw_set(
            config["mqtt"]["username"],
            config["mqtt"]["password"]
        )
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.reconnect_delay_set(min_delay=5, max_delay=120) # Increased min delay slightly

    broker_address = config["mqtt"]["broker"]
    broker_port = int(config["mqtt"]["port"])
    logger.info(f"Connecting to MQTT broker at {broker_address}:{broker_port}...")
    try:
        client.connect(broker_address, broker_port, 60) # Keepalive 60 seconds
    except Exception as e:
        logger.exception(f"Failed to connect to MQTT broker: {e}")
        raise # Reraise the exception to prevent starting loop_forever on failed connect
    return client


def subscribe(client: mqtt_client, md_instance: MeshData):
    # --- Add log at the start ---
    logger.info("subscribe: Entered function.")
    # --- End log ---
    def on_message(client, userdata, msg):
        # --- Add log for every message received ---
        logger.debug(f"on_message: Received message on topic: {msg.topic}")
        # --- End log ---

        # Filter for relevant topics
        if "/2/e/" in msg.topic or "/2/map/" in msg.topic:
            logger.debug(f"on_message: Processing message from relevant topic: {msg.topic}")
            try:
                # Pass the existing MeshData instance
                process_payload(msg.payload, msg.topic, md_instance)
            except Exception as e:
                logger.exception(f"on_message: Error calling process_payload for topic {msg.topic}")
        else:
            logger.debug(f"on_message: Skipping message from topic: {msg.topic}")


    topic_to_subscribe = config["mqtt"]["topic"]
    logger.info(f"subscribe: Subscribing to topic: {topic_to_subscribe}")
    try:
        result, mid = client.subscribe(topic_to_subscribe)
        if result == mqtt_client.MQTT_ERR_SUCCESS:
            logger.info(f"subscribe: Successfully initiated subscription to {topic_to_subscribe} (MID: {mid})")
        else:
            logger.error(f"subscribe: Failed to initiate subscription to {topic_to_subscribe}, Error code: {result}")
            return # Don't set on_message if subscribe failed

        logger.info("subscribe: Setting on_message callback.")
        client.on_message = on_message
        logger.info("subscribe: on_message callback set.")
    except Exception as e:
        logger.exception(f"subscribe: Error during subscribe call or setting on_message for topic {topic_to_subscribe}")



def run():
    logger.info("Starting MQTT client run sequence...")
    try:
        client = connect_mqtt()
        logger.info("Entering MQTT client loop (loop_forever)...")
        client.loop_forever()
    except Exception as e:
        logger.exception("An error occurred during MQTT client execution.")
    finally:
        logger.info("Exited MQTT client loop.")


if __name__ == '__main__':
    # Configure logging (ensure level allows DEBUG if you want to see the on_message logs)
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s')
    run()
