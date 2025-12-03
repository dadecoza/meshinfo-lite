# Import all migrations here
from .add_traceroute_improvements import migrate as add_traceroute_improvements
from .add_ts_uplink import migrate as add_ts_uplink
from .add_traceroute_snr import migrate as add_traceroute_snr
from .add_channel_info import migrate as add_channel_info
from .add_message_reception import migrate as add_message_reception
from .add_traceroute_id import migrate as add_traceroute_id
from .add_positionlog_log_id import migrate as add_positionlog_log_id
from .add_message_map_indexes import migrate as add_message_map_indexes
from .add_relay_node_to_reception import migrate as add_relay_node_to_reception
from .add_relay_edges_table import migrate as add_relay_edges_table
from .add_message_reception_ts_created import migrate as add_message_reception_ts_created
from .add_mapreport_fields import migrate as add_mapreport_fields
from .add_telemetry_packet_id import migrate as add_telemetry_packet_id
from .add_routing_messages_table import migrate as add_routing_messages_table

# List of migrations to run in order
MIGRATIONS = [
    add_traceroute_improvements,
    add_ts_uplink,
    add_traceroute_snr,
    add_channel_info,
    add_message_reception,
    add_traceroute_id,
    add_positionlog_log_id,
    add_message_map_indexes,
    add_relay_node_to_reception,
    add_relay_edges_table,
    add_message_reception_ts_created,
    add_mapreport_fields,
    add_telemetry_packet_id,
    add_routing_messages_table,
]
