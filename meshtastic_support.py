#!/usr/bin/env python3

from enum import Enum

"""
HardwareModel definition of Meshtastic supported hardware models
from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.HardwareModel
"""


class HardwareModel(Enum):
    UNSET = 0
    TLORA_V2 = 1
    TLORA_V1 = 2
    TLORA_V2_1_1P6 = 3
    TBEAM = 4
    HELTEC_V2_0 = 5
    TBEAM_V0P7 = 6
    T_ECHO = 7
    TLORA_V1_1P3 = 8
    RAK4631 = 9
    HELTEC_V2_1 = 10
    HELTEC_V1 = 11
    LILYGO_TBEAM_S3_CORE = 12
    RAK11200 = 13
    NANO_G1 = 14
    TLORA_V2_1_1P8 = 15
    TLORA_T3_S3 = 16
    NANO_G1_EXPLORER = 17
    NANO_G2_ULTRA = 18
    LORA_TYPE = 19
    WIPHONE = 20
    WIO_WM1110 = 21
    RAK2560 = 22
    HELTEC_HRU_3601 = 23
    HELTEC_WIRELESS_BRIDGE = 24
    STATION_G1 = 25
    RAK11310 = 26
    SENSELORA_RP2040 = 27
    SENSELORA_S3 = 28
    CANARYONE = 29
    RP2040_LORA = 30
    STATION_G2 = 31
    LORA_RELAY_V1 = 32
    NRF52840DK = 33
    PPR = 34
    GENIEBLOCKS = 35
    NRF52_UNKNOWN = 36
    PORTDUINO = 37
    ANDROID_SIM = 38
    DIY_V1 = 39
    NRF52840_PCA10059 = 40
    DR_DEV = 41
    M5STACK = 42
    HELTEC_V3 = 43
    HELTEC_WSL_V3 = 44
    BETAFPV_2400_TX = 45
    BETAFPV_900_NANO_TX = 46
    RPI_PICO = 47
    HELTEC_WIRELESS_TRACKER = 48
    HELTEC_WIRELESS_PAPER = 49
    T_DECK = 50
    T_WATCH_S3 = 51
    PICOMPUTER_S3 = 52
    HELTEC_HT62 = 53
    EBYTE_ESP32_S3 = 54
    ESP32_S3_PICO = 55
    CHATTER_2 = 56
    HELTEC_WIRELESS_PAPER_V1_0 = 57
    HELTEC_WIRELESS_TRACKER_V1_0 = 58
    UNPHONE = 59
    TD_LORAC = 60
    CDEBYTE_EORA_S3 = 61
    TWC_MESH_V4 = 62
    NRF52_PROMICRO_DIY = 63
    RADIOMASTER_900_BANDIT_NANO = 64
    HELTEC_CAPSULE_SENSOR_V3 = 65
    HELTEC_VISION_MASTER_T190 = 66
    HELTEC_VISION_MASTER_E213 = 67
    HELTEC_VISION_MASTER_E290 = 68
    HELTEC_MESH_NODE_T114 = 69
    SENSECAP_INDICATOR = 70
    TRACKER_T1000_E = 71
    RAK3172 = 72
    WIO_E5 = 73
    RADIOMASTER_900_BANDIT = 74
    ME25LS01_4Y10TD = 75
    RP2040_FEATHER_RFM95 = 76
    M5STACK_COREBASIC = 77
    M5STACK_CORE2 = 78
    RPI_PICO2 = 79
    M5STACK_CORES3 = 80
    SEEED_XIAO_S3 = 81
    MS24SF1 = 82
    TLORA_C6 = 83
    WISMESH_TAP = 84
    ROUTASTIC = 85
    MESH_TAB = 86
    MESHLINK = 87
    XIAO_NRF52_KIT = 88
    THINKNODE_M1 = 89
    THINKNODE_M2 = 90
    T_ETH_ELITE = 91
    HELTEC_SENSOR_HUB = 92
    RESERVED_FRIED_CHICKEN = 93
    HELTEC_MESH_POCKET = 94
    SEEED_SOLAR_NODE = 95
    NOMADSTAR_METEOR_PRO = 96
    CROWPANEL = 97
    LINK_32 = 98
    SEEED_WIO_TRACKER_L1 = 99
    SEEED_WIO_TRACKER_L1_EINK = 100
    QWANTZ_TINY_ARMS = 101
    T_DECK_PRO = 102
    T_LORA_PAGER = 103
    GAT562_MESH_TRIAL_TRACKER = 104
    PRIVATE_HW = 255

class Role(Enum):
    """
    Meshtastic node roles
    from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.Config.DeviceConfig.Role
    """
    CLIENT = 0
    CLIENT_MUTE = 1
    ROUTER = 2
    ROUTER_CLIENT = 3  # Deprecated in v2.3.15
    REPEATER = 4  # Deprecated in v2.7.11
    TRACKER = 5
    SENSOR = 6
    TAK = 7
    CLIENT_HIDDEN = 8
    LOST_AND_FOUND = 9
    TAK_TRACKER = 10
    ROUTER_LATE = 11
    CLIENT_BASE = 12

class ShortRole(Enum):
    """
    Meshtastic node short roles
    """
    C = 0
    CM = 1
    R = 2
    RC = 3
    RE = 4
    T = 5
    S = 6
    A = 7
    CH = 8
    LF = 9
    AT = 10
    RL = 11
    CB = 12


class Channel(Enum):
    """
    Meshtastic channel mapping
    Maps channel numbers to their descriptive names
    """
    LONG_FAST = 8
    MEDIUM_FAST = 31
    SHORT_FAST = 112
    LONG_MODERATE = 88
    MEDIUM_SLOW = 24
    # Additional channels will be added as they are discovered

class ShortChannel(Enum):
    """
    Meshtastic channel mapping
    Maps channel numbers to their descriptive names
    """
    LF = 8
    MF = 31
    SF = 112
    LM = 88
    MS = 24
    # Additional channels will be added as they are discovered


class ModemPreset(Enum):
    """
    Meshtastic modem preset configuration
    from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.ModemPreset
    """
    LONG_FAST = 0
    LONG_SLOW = 1
    VERY_LONG_SLOW = 2  # Deprecated in 2.5: Works only with txco and is unusably slow
    MEDIUM_SLOW = 3
    MEDIUM_FAST = 4
    SHORT_SLOW = 5
    SHORT_FAST = 6
    LONG_MODERATE = 7
    SHORT_TURBO = 8  # Fastest preset with 500kHz bandwidth, not legal in all regions

class RebroadcastMode(Enum):
    """
    Meshtastic rebroadcast mode configuration
    from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.Config.DeviceConfig.RebroadcastMode
    """
    ALL = 0
    ALL_SKIP_DECODING = 1
    LOCAL_ONLY = 2
    KNOWN_ONLY = 3
    NONE = 4
    CORE_PORTNUMS_ONLY = 5

class BuzzerMode(Enum):
    """
    Meshtastic buzzer mode configuration
    from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.Config.DeviceConfig.BuzzerMode
    """
    ALL_ENABLED = 0
    DISABLED = 1
    NOTIFICATIONS_ONLY = 2
    SYSTEM_ONLY = 3
    DIRECT_MSG_ONLY = 4

class RoutingError(Enum):
    """
    Meshtastic routing error codes
    from https://buf.build/meshtastic/protobufs/docs/main:meshtastic#meshtastic.RoutingError
    """
    NONE = 0
    NO_ROUTE = 1
    GOT_NAK = 2
    TIMEOUT = 3
    NO_INTERFACE = 4
    MAX_RETRANSMIT = 5
    NO_CHANNEL = 6
    TOO_LARGE = 7
    NO_RESPONSE = 8
    DUTY_CYCLE_LIMIT = 9
    BAD_REQUEST = 32
    NOT_AUTHORIZED = 33
    PKI_FAILED = 34
    PKI_UNKNOWN_PUBKEY = 35
    ADMIN_BAD_SESSION_KEY = 36
    ADMIN_PUBLIC_KEY_UNAUTHORIZED = 37
    RATE_LIMIT_EXCEEDED = 38

def get_channel_name(channel_value, use_short_names=False):
    """
    Convert a channel number to a human-readable name.
    
    Args:
        channel_value: The numeric channel value
        use_short_names: If True, return short channel names (e.g., "LF" instead of "LongFast")
        
    Returns:
        A human-readable channel name or "Unknown (value)" if not recognized
    """
    if channel_value is None:
        return "Default"
    
    try:
        # Try to find the channel in our enum
        if use_short_names:
            for channel in ShortChannel:
                if channel.value == channel_value:
                    return channel.name
        else:
            for channel in Channel:
                if channel.value == channel_value:
                    # Convert the enum name to a more readable format
                    # Keep the underscores but capitalize each word
                    words = channel.name.split('_')
                    formatted_words = [word.capitalize() for word in words]
                    return ''.join(formatted_words)
        
        # If not found in our enum, return unknown with the value
        return f"Unknown ({channel_value})"
    except Exception:
        return f"Unknown ({channel_value})"


HARDWARE_PHOTOS = {
    HardwareModel.HELTEC_HT62: "HELTEC_HT62.webp",
    HardwareModel.HELTEC_V2_0: "HELTEC_V2_0.webp",
    HardwareModel.HELTEC_V2_1: "HELTEC_V2_1.webp",
    HardwareModel.HELTEC_V3: "HELTEC_V3.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER: "HELTEC_WIRELESS_PAPER.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER: "HELTEC_WIRELESS_TRACKER.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER_V1_0: "HELTEC_WIRELESS_TRACKER_V1_0.webp",
    HardwareModel.HELTEC_WSL_V3: "HELTEC_WSL_V3.webp",
    HardwareModel.LILYGO_TBEAM_S3_CORE: "LILYGO_TBEAM_S3_CORE.webp",
    HardwareModel.NANO_G1_EXPLORER: "NANO_G1_EXPLORER.webp",
    HardwareModel.NANO_G2_ULTRA: "NANO_G2_ULTRA.webp",
    HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    HardwareModel.RAK11310: "RAK11310.webp",
    HardwareModel.RAK4631: "RAK4631.webp",
    HardwareModel.RP2040_LORA: "RP2040_LORA.webp",
    HardwareModel.RPI_PICO: "RPI_PICO.webp",
    HardwareModel.TBEAM: "TBEAM.webp",
    HardwareModel.TLORA_T3_S3: "TLORA_T3_S3.webp",
    HardwareModel.TLORA_V2_1_1P6: "TLORA_V2_1_1P6.webp",
    HardwareModel.T_DECK: "T_DECK.webp",
    HardwareModel.T_ECHO: "T_ECHO.webp",
    HardwareModel.T_WATCH_S3: "T_WATCH_S3.webp",
    HardwareModel.PRIVATE_HW: "PRIVATE_HW.webp",
    HardwareModel.PORTDUINO: "PORTDUINO.webp",
    HardwareModel.SEEED_XIAO_S3: "SEEED_XIAO_S3.webp",
    HardwareModel.TBEAM_V0P7: "TBEAM_V0P7.webp",
    HardwareModel.HELTEC_MESH_NODE_T114: "HELTEC_MESH_NODE_T114.webp",
    HardwareModel.HELTEC_CAPSULE_SENSOR_V3: "HELTEC_CAPSULE_SENSOR_V3.webp",
    HardwareModel.TRACKER_T1000_E: "TRACKER_T1000_E.webp",
    HardwareModel.RPI_PICO2: "RPI_PICO.webp",
    HardwareModel.NRF52840DK: "NRF52840DK.webp",
    # Placeholders for all other models:
    # HardwareModel.UNSET: "UNSET.webp",
    HardwareModel.TLORA_V2: "TLORA_V2.webp",
    HardwareModel.TLORA_V1: "TLORA_V1.webp",
    HardwareModel.TLORA_V1_1P3: "TLORA_V1_1P3.webp",
    HardwareModel.TLORA_V2_1_1P8: "TLORA_V2_1_1P8.webp",
    HardwareModel.RAK11200: "RAK11200.webp",
    HardwareModel.NANO_G1: "NANO_G1.webp",
    HardwareModel.LORA_TYPE: "LORA_TYPE.webp",
    HardwareModel.WIPHONE: "WIPHONE.webp",
    HardwareModel.WIO_WM1110: "WIO_WM1110.webp",
    HardwareModel.RAK2560: "RAK2560.webp",
    HardwareModel.HELTEC_HRU_3601: "HELTEC_HRU_3601.webp",
    HardwareModel.HELTEC_WIRELESS_BRIDGE: "HELTEC_WIRELESS_BRIDGE.webp",
    HardwareModel.STATION_G1: "STATION_G1.webp",
    ## HardwareModel.SENSELORA_RP2040: "SENSELORA_RP2040.webp",
    HardwareModel.SENSELORA_S3: "SENSELORA_S3.webp",
    HardwareModel.CANARYONE: "CANARYONE.webp",
    HardwareModel.STATION_G2: "STATION_G2.webp",
    HardwareModel.LORA_RELAY_V1: "LORA_RELAY_V1.webp",
    ## HardwareModel.PPR: "PPR.webp",
    ## HardwareModel.GENIEBLOCKS: "GENIEBLOCKS.webp",
    ## HardwareModel.NRF52_UNKNOWN: "NRF52_UNKNOWN.webp",
    ## HardwareModel.ANDROID_SIM: "ANDROID_SIM.webp",
    ## HardwareModel.DIY_V1: "DIY_V1.webp",
    HardwareModel.NRF52840_PCA10059: "NRF52840_PCA10059.webp",
    ## HardwareModel.DR_DEV: "DR_DEV.webp",
    ## HardwareModel.M5STACK: "M5STACK.webp",
    ## HardwareModel.BETAFPV_2400_TX: "BETAFPV_2400_TX.webp",
    ## HardwareModel.BETAFPV_900_NANO_TX: "BETAFPV_900_NANO_TX.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.UNPHONE: "UNPHONE.webp",
    ## HardwareModel.TD_LORAC: "TD_LORAC.webp",
    # HardwareModel.CDEBYTE_EORA_S3: "CDEBYTE_EORA_S3.webp",
    ## HardwareModel.TWC_MESH_V4: "TWC_MESH_V4.webp",
    ## HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    # HardwareModel.RADIOMASTER_900_BANDIT_NANO: "RADIOMASTER_900_BANDIT_NANO.webp",
    HardwareModel.HELTEC_VISION_MASTER_T190: "HELTEC_VISION_MASTER_T190.webp",
    HardwareModel.HELTEC_VISION_MASTER_E213: "HELTEC_VISION_MASTER_E213.webp",
    HardwareModel.HELTEC_VISION_MASTER_E290: "HELTEC_VISION_MASTER_E290.webp",
    HardwareModel.SENSECAP_INDICATOR: "SENSECAP_INDICATOR.webp",
    HardwareModel.RAK3172: "RAK3172.webp",
    HardwareModel.WIO_E5: "WIO_E5.webp",
    ## HardwareModel.RADIOMASTER_900_BANDIT: "RADIOMASTER_900_BANDIT.webp",
    HardwareModel.ME25LS01_4Y10TD: "ME25LS01_4Y10TD.webp",
    HardwareModel.RP2040_FEATHER_RFM95: "RP2040_FEATHER_RFM95.webp",
    HardwareModel.M5STACK_COREBASIC: "M5STACK_COREBASIC.webp",
    HardwareModel.M5STACK_CORE2: "M5STACK_CORE2.webp",
    HardwareModel.M5STACK_CORES3: "M5STACK_CORES3.webp",
    HardwareModel.MS24SF1: "MS24SF1.webp",
    HardwareModel.TLORA_C6: "TLORA_C6.webp",
    HardwareModel.WISMESH_TAP: "WISMESH_TAP.webp",
    HardwareModel.ROUTASTIC: "ROUTASTIC.webp",
    ## HardwareModel.MESH_TAB: "MESH_TAB.webp",
    ## HardwareModel.MESHLINK: "MESHLINK.webp",
    HardwareModel.XIAO_NRF52_KIT: "XIAO_NRF52_KIT.webp",
    HardwareModel.THINKNODE_M1: "THINKNODE_M1.webp",
    HardwareModel.THINKNODE_M2: "THINKNODE_M2.webp",
    HardwareModel.T_ETH_ELITE: "T_ETH_ELITE.webp",
    HardwareModel.HELTEC_SENSOR_HUB: "HELTEC_SENSOR_HUB.webp",
    HardwareModel.RESERVED_FRIED_CHICKEN: "RESERVED_FRIED_CHICKEN.webp",
    HardwareModel.HELTEC_MESH_POCKET: "HELTEC_MESH_POCKET.webp",
    HardwareModel.HELTEC_HT62: "HELTEC_HT62.webp",
    HardwareModel.HELTEC_V2_0: "HELTEC_V2_0.webp",
    HardwareModel.HELTEC_V2_1: "HELTEC_V2_1.webp",
    HardwareModel.HELTEC_V3: "HELTEC_V3.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER: "HELTEC_WIRELESS_PAPER.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER: "HELTEC_WIRELESS_TRACKER.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER_V1_0: "HELTEC_WIRELESS_TRACKER_V1_0.webp",
    HardwareModel.HELTEC_WSL_V3: "HELTEC_WSL_V3.webp",
    HardwareModel.LILYGO_TBEAM_S3_CORE: "LILYGO_TBEAM_S3_CORE.webp",
    HardwareModel.NANO_G1_EXPLORER: "NANO_G1_EXPLORER.webp",
    HardwareModel.NANO_G2_ULTRA: "NANO_G2_ULTRA.webp",
    HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    HardwareModel.RAK11310: "RAK11310.webp",
    HardwareModel.RAK4631: "RAK4631.webp",
    HardwareModel.RP2040_LORA: "RP2040_LORA.webp",
    HardwareModel.RPI_PICO: "RPI_PICO.webp",
    HardwareModel.TBEAM: "TBEAM.webp",
    HardwareModel.TLORA_T3_S3: "TLORA_T3_S3.webp",
    HardwareModel.TLORA_V2_1_1P6: "TLORA_V2_1_1P6.webp",
    HardwareModel.T_DECK: "T_DECK.webp",
    HardwareModel.T_ECHO: "T_ECHO.webp",
    HardwareModel.T_WATCH_S3: "T_WATCH_S3.webp",
    HardwareModel.PRIVATE_HW: "PRIVATE_HW.webp",
    HardwareModel.PORTDUINO: "PORTDUINO.webp",
    HardwareModel.SEEED_XIAO_S3: "SEEED_XIAO_S3.webp",
    HardwareModel.TBEAM_V0P7: "TBEAM_V0P7.webp",
    HardwareModel.HELTEC_MESH_NODE_T114: "HELTEC_MESH_NODE_T114.webp",
    HardwareModel.HELTEC_CAPSULE_SENSOR_V3: "HELTEC_CAPSULE_SENSOR_V3.webp",
    HardwareModel.TRACKER_T1000_E: "TRACKER_T1000_E.webp",
    HardwareModel.RPI_PICO2: "RPI_PICO.webp",
    HardwareModel.NRF52840DK: "NRF52840DK.webp",
    # Placeholders for all other models:
    # HardwareModel.UNSET: "UNSET.webp",
    HardwareModel.TLORA_V2: "TLORA_V2.webp",
    HardwareModel.TLORA_V1: "TLORA_V1.webp",
    HardwareModel.TLORA_V1_1P3: "TLORA_V1_1P3.webp",
    HardwareModel.TLORA_V2_1_1P8: "TLORA_V2_1_1P8.webp",
    HardwareModel.RAK11200: "RAK11200.webp",
    HardwareModel.NANO_G1: "NANO_G1.webp",
    HardwareModel.LORA_TYPE: "LORA_TYPE.webp",
    HardwareModel.WIPHONE: "WIPHONE.webp",
    HardwareModel.WIO_WM1110: "WIO_WM1110.webp",
    HardwareModel.RAK2560: "RAK2560.webp",
    HardwareModel.HELTEC_HRU_3601: "HELTEC_HRU_3601.webp",
    HardwareModel.HELTEC_WIRELESS_BRIDGE: "HELTEC_WIRELESS_BRIDGE.webp",
    HardwareModel.STATION_G1: "STATION_G1.webp",
    ## HardwareModel.SENSELORA_RP2040: "SENSELORA_RP2040.webp",
    HardwareModel.SENSELORA_S3: "SENSELORA_S3.webp",
    HardwareModel.CANARYONE: "CANARYONE.webp",
    HardwareModel.STATION_G2: "STATION_G2.webp",
    HardwareModel.LORA_RELAY_V1: "LORA_RELAY_V1.webp",
    ## HardwareModel.PPR: "PPR.webp",
    ## HardwareModel.GENIEBLOCKS: "GENIEBLOCKS.webp",
    ## HardwareModel.NRF52_UNKNOWN: "NRF52_UNKNOWN.webp",
    ## HardwareModel.ANDROID_SIM: "ANDROID_SIM.webp",
    ## HardwareModel.DIY_V1: "DIY_V1.webp",
    HardwareModel.NRF52840_PCA10059: "NRF52840_PCA10059.webp",
    ## HardwareModel.DR_DEV: "DR_DEV.webp",
    ## HardwareModel.M5STACK: "M5STACK.webp",
    ## HardwareModel.BETAFPV_2400_TX: "BETAFPV_2400_TX.webp",
    ## HardwareModel.BETAFPV_900_NANO_TX: "BETAFPV_900_NANO_TX.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.UNPHONE: "UNPHONE.webp",
    ## HardwareModel.TD_LORAC: "TD_LORAC.webp",
    # HardwareModel.CDEBYTE_EORA_S3: "CDEBYTE_EORA_S3.webp",
    ## HardwareModel.TWC_MESH_V4: "TWC_MESH_V4.webp",
    ## HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    # HardwareModel.RADIOMASTER_900_BANDIT_NANO: "RADIOMASTER_900_BANDIT_NANO.webp",
    HardwareModel.HELTEC_VISION_MASTER_T190: "HELTEC_VISION_MASTER_T190.webp",
    HardwareModel.HELTEC_VISION_MASTER_E213: "HELTEC_VISION_MASTER_E213.webp",
    HardwareModel.HELTEC_VISION_MASTER_E290: "HELTEC_VISION_MASTER_E290.webp",
    HardwareModel.SENSECAP_INDICATOR: "SENSECAP_INDICATOR.webp",
    HardwareModel.RAK3172: "RAK3172.webp",
    HardwareModel.WIO_E5: "WIO_E5.webp",
    ## HardwareModel.RADIOMASTER_900_BANDIT: "RADIOMASTER_900_BANDIT.webp",
    HardwareModel.ME25LS01_4Y10TD: "ME25LS01_4Y10TD.webp",
    HardwareModel.RP2040_FEATHER_RFM95: "RP2040_FEATHER_RFM95.webp",
    HardwareModel.M5STACK_COREBASIC: "M5STACK_COREBASIC.webp",
    HardwareModel.M5STACK_CORE2: "M5STACK_CORE2.webp",
    HardwareModel.M5STACK_CORES3: "M5STACK_CORES3.webp",
    HardwareModel.MS24SF1: "MS24SF1.webp",
    HardwareModel.TLORA_C6: "TLORA_C6.webp",
    HardwareModel.WISMESH_TAP: "WISMESH_TAP.webp",
    HardwareModel.ROUTASTIC: "ROUTASTIC.webp",
    ## HardwareModel.MESH_TAB: "MESH_TAB.webp",
    ## HardwareModel.MESHLINK: "MESHLINK.webp",
    HardwareModel.XIAO_NRF52_KIT: "XIAO_NRF52_KIT.webp",
    HardwareModel.THINKNODE_M1: "THINKNODE_M1.webp",
    HardwareModel.THINKNODE_M2: "THINKNODE_M2.webp",
    HardwareModel.T_ETH_ELITE: "T_ETH_ELITE.webp",
    HardwareModel.HELTEC_SENSOR_HUB: "HELTEC_SENSOR_HUB.webp",
    HardwareModel.RESERVED_FRIED_CHICKEN: "RESERVED_FRIED_CHICKEN.webp",
    HardwareModel.HELTEC_MESH_POCKET: "HELTEC_MESH_POCKET.webp",
    HardwareModel.HELTEC_HT62: "HELTEC_HT62.webp",
    HardwareModel.HELTEC_V2_0: "HELTEC_V2_0.webp",
    HardwareModel.HELTEC_V2_1: "HELTEC_V2_1.webp",
    HardwareModel.HELTEC_V3: "HELTEC_V3.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER: "HELTEC_WIRELESS_PAPER.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER: "HELTEC_WIRELESS_TRACKER.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER_V1_0: "HELTEC_WIRELESS_TRACKER_V1_0.webp",
    HardwareModel.HELTEC_WSL_V3: "HELTEC_WSL_V3.webp",
    HardwareModel.LILYGO_TBEAM_S3_CORE: "LILYGO_TBEAM_S3_CORE.webp",
    HardwareModel.NANO_G1_EXPLORER: "NANO_G1_EXPLORER.webp",
    HardwareModel.NANO_G2_ULTRA: "NANO_G2_ULTRA.webp",
    HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    HardwareModel.RAK11310: "RAK11310.webp",
    HardwareModel.RAK4631: "RAK4631.webp",
    HardwareModel.RP2040_LORA: "RP2040_LORA.webp",
    HardwareModel.RPI_PICO: "RPI_PICO.webp",
    HardwareModel.TBEAM: "TBEAM.webp",
    HardwareModel.TLORA_T3_S3: "TLORA_T3_S3.webp",
    HardwareModel.TLORA_V2_1_1P6: "TLORA_V2_1_1P6.webp",
    HardwareModel.T_DECK: "T_DECK.webp",
    HardwareModel.T_ECHO: "T_ECHO.webp",
    HardwareModel.T_WATCH_S3: "T_WATCH_S3.webp",
    HardwareModel.PRIVATE_HW: "PRIVATE_HW.webp",
    HardwareModel.PORTDUINO: "PORTDUINO.webp",
    HardwareModel.SEEED_XIAO_S3: "SEEED_XIAO_S3.webp",
    HardwareModel.TBEAM_V0P7: "TBEAM_V0P7.webp",
    HardwareModel.HELTEC_MESH_NODE_T114: "HELTEC_MESH_NODE_T114.webp",
    HardwareModel.HELTEC_CAPSULE_SENSOR_V3: "HELTEC_CAPSULE_SENSOR_V3.webp",
    HardwareModel.TRACKER_T1000_E: "TRACKER_T1000_E.webp",
    HardwareModel.RPI_PICO2: "RPI_PICO.webp",
    HardwareModel.NRF52840DK: "NRF52840DK.webp",
    # Placeholders for all other models:
    # HardwareModel.UNSET: "UNSET.webp",
    HardwareModel.TLORA_V2: "TLORA_V2.webp",
    HardwareModel.TLORA_V1: "TLORA_V1.webp",
    HardwareModel.TLORA_V1_1P3: "TLORA_V1_1P3.webp",
    HardwareModel.TLORA_V2_1_1P8: "TLORA_V2_1_1P8.webp",
    HardwareModel.RAK11200: "RAK11200.webp",
    HardwareModel.NANO_G1: "NANO_G1.webp",
    HardwareModel.LORA_TYPE: "LORA_TYPE.webp",
    HardwareModel.WIPHONE: "WIPHONE.webp",
    HardwareModel.WIO_WM1110: "WIO_WM1110.webp",
    HardwareModel.RAK2560: "RAK2560.webp",
    HardwareModel.HELTEC_HRU_3601: "HELTEC_HRU_3601.webp",
    HardwareModel.HELTEC_WIRELESS_BRIDGE: "HELTEC_WIRELESS_BRIDGE.webp",
    HardwareModel.STATION_G1: "STATION_G1.webp",
    ## HardwareModel.SENSELORA_RP2040: "SENSELORA_RP2040.webp",
    HardwareModel.SENSELORA_S3: "SENSELORA_S3.webp",
    HardwareModel.CANARYONE: "CANARYONE.webp",
    HardwareModel.STATION_G2: "STATION_G2.webp",
    HardwareModel.LORA_RELAY_V1: "LORA_RELAY_V1.webp",
    ## HardwareModel.PPR: "PPR.webp",
    ## HardwareModel.GENIEBLOCKS: "GENIEBLOCKS.webp",
    ## HardwareModel.NRF52_UNKNOWN: "NRF52_UNKNOWN.webp",
    ## HardwareModel.ANDROID_SIM: "ANDROID_SIM.webp",
    ## HardwareModel.DIY_V1: "DIY_V1.webp",
    HardwareModel.NRF52840_PCA10059: "NRF52840_PCA10059.webp",
    ## HardwareModel.DR_DEV: "DR_DEV.webp",
    ## HardwareModel.M5STACK: "M5STACK.webp",
    ## HardwareModel.BETAFPV_2400_TX: "BETAFPV_2400_TX.webp",
    ## HardwareModel.BETAFPV_900_NANO_TX: "BETAFPV_900_NANO_TX.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.UNPHONE: "UNPHONE.webp",
    ## HardwareModel.TD_LORAC: "TD_LORAC.webp",
    # HardwareModel.CDEBYTE_EORA_S3: "CDEBYTE_EORA_S3.webp",
    ## HardwareModel.TWC_MESH_V4: "TWC_MESH_V4.webp",
    ## HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    # HardwareModel.RADIOMASTER_900_BANDIT_NANO: "RADIOMASTER_900_BANDIT_NANO.webp",
    HardwareModel.HELTEC_VISION_MASTER_T190: "HELTEC_VISION_MASTER_T190.webp",
    HardwareModel.HELTEC_VISION_MASTER_E213: "HELTEC_VISION_MASTER_E213.webp",
    HardwareModel.HELTEC_VISION_MASTER_E290: "HELTEC_VISION_MASTER_E290.webp",
    HardwareModel.SENSECAP_INDICATOR: "SENSECAP_INDICATOR.webp",
    HardwareModel.RAK3172: "RAK3172.webp",
    HardwareModel.WIO_E5: "WIO_E5.webp",
    ## HardwareModel.RADIOMASTER_900_BANDIT: "RADIOMASTER_900_BANDIT.webp",
    HardwareModel.ME25LS01_4Y10TD: "ME25LS01_4Y10TD.webp",
    HardwareModel.RP2040_FEATHER_RFM95: "RP2040_FEATHER_RFM95.webp",
    HardwareModel.M5STACK_COREBASIC: "M5STACK_COREBASIC.webp",
    HardwareModel.M5STACK_CORE2: "M5STACK_CORE2.webp",
    HardwareModel.M5STACK_CORES3: "M5STACK_CORES3.webp",
    HardwareModel.MS24SF1: "MS24SF1.webp",
    HardwareModel.TLORA_C6: "TLORA_C6.webp",
    HardwareModel.WISMESH_TAP: "WISMESH_TAP.webp",
    HardwareModel.ROUTASTIC: "ROUTASTIC.webp",
    ## HardwareModel.MESH_TAB: "MESH_TAB.webp",
    ## HardwareModel.MESHLINK: "MESHLINK.webp",
    HardwareModel.XIAO_NRF52_KIT: "XIAO_NRF52_KIT.webp",
    HardwareModel.THINKNODE_M1: "THINKNODE_M1.webp",
    HardwareModel.THINKNODE_M2: "THINKNODE_M2.webp",
    HardwareModel.T_ETH_ELITE: "T_ETH_ELITE.webp",
    HardwareModel.HELTEC_SENSOR_HUB: "HELTEC_SENSOR_HUB.webp",
    HardwareModel.RESERVED_FRIED_CHICKEN: "RESERVED_FRIED_CHICKEN.webp",
    HardwareModel.HELTEC_MESH_POCKET: "HELTEC_MESH_POCKET.webp",
    HardwareModel.HELTEC_HT62: "HELTEC_HT62.webp",
    HardwareModel.HELTEC_V2_0: "HELTEC_V2_0.webp",
    HardwareModel.HELTEC_V2_1: "HELTEC_V2_1.webp",
    HardwareModel.HELTEC_V3: "HELTEC_V3.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER: "HELTEC_WIRELESS_PAPER.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER: "HELTEC_WIRELESS_TRACKER.webp",
    HardwareModel.HELTEC_WIRELESS_TRACKER_V1_0: "HELTEC_WIRELESS_TRACKER_V1_0.webp",
    HardwareModel.HELTEC_WSL_V3: "HELTEC_WSL_V3.webp",
    HardwareModel.LILYGO_TBEAM_S3_CORE: "LILYGO_TBEAM_S3_CORE.webp",
    HardwareModel.NANO_G1_EXPLORER: "NANO_G1_EXPLORER.webp",
    HardwareModel.NANO_G2_ULTRA: "NANO_G2_ULTRA.webp",
    HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    HardwareModel.RAK11310: "RAK11310.webp",
    HardwareModel.RAK4631: "RAK4631.webp",
    HardwareModel.RP2040_LORA: "RP2040_LORA.webp",
    HardwareModel.RPI_PICO: "RPI_PICO.webp",
    HardwareModel.TBEAM: "TBEAM.webp",
    HardwareModel.TLORA_T3_S3: "TLORA_T3_S3.webp",
    HardwareModel.TLORA_V2_1_1P6: "TLORA_V2_1_1P6.webp",
    HardwareModel.T_DECK: "T_DECK.webp",
    HardwareModel.T_ECHO: "T_ECHO.webp",
    HardwareModel.T_WATCH_S3: "T_WATCH_S3.webp",
    HardwareModel.PRIVATE_HW: "PRIVATE_HW.webp",
    HardwareModel.PORTDUINO: "PORTDUINO.webp",
    HardwareModel.SEEED_XIAO_S3: "SEEED_XIAO_S3.webp",
    HardwareModel.TBEAM_V0P7: "TBEAM_V0P7.webp",
    HardwareModel.HELTEC_MESH_NODE_T114: "HELTEC_MESH_NODE_T114.webp",
    HardwareModel.HELTEC_CAPSULE_SENSOR_V3: "HELTEC_CAPSULE_SENSOR_V3.webp",
    HardwareModel.TRACKER_T1000_E: "TRACKER_T1000_E.webp",
    HardwareModel.RPI_PICO2: "RPI_PICO.webp",
    HardwareModel.NRF52840DK: "NRF52840DK.webp",
    # Placeholders for all other models:
    # HardwareModel.UNSET: "UNSET.webp",
    HardwareModel.TLORA_V2: "TLORA_V2.webp",
    HardwareModel.TLORA_V1: "TLORA_V1.webp",
    HardwareModel.TLORA_V1_1P3: "TLORA_V1_1P3.webp",
    HardwareModel.TLORA_V2_1_1P8: "TLORA_V2_1_1P8.webp",
    HardwareModel.RAK11200: "RAK11200.webp",
    HardwareModel.NANO_G1: "NANO_G1.webp",
    HardwareModel.LORA_TYPE: "LORA_TYPE.webp",
    HardwareModel.WIPHONE: "WIPHONE.webp",
    HardwareModel.WIO_WM1110: "WIO_WM1110.webp",
    HardwareModel.RAK2560: "RAK2560.webp",
    HardwareModel.HELTEC_HRU_3601: "HELTEC_HRU_3601.webp",
    HardwareModel.HELTEC_WIRELESS_BRIDGE: "HELTEC_WIRELESS_BRIDGE.webp",
    HardwareModel.STATION_G1: "STATION_G1.webp",
    ## HardwareModel.SENSELORA_RP2040: "SENSELORA_RP2040.webp",
    HardwareModel.SENSELORA_S3: "SENSELORA_S3.webp",
    HardwareModel.CANARYONE: "CANARYONE.webp",
    HardwareModel.STATION_G2: "STATION_G2.webp",
    HardwareModel.LORA_RELAY_V1: "LORA_RELAY_V1.webp",
    ## HardwareModel.PPR: "PPR.webp",
    ## HardwareModel.GENIEBLOCKS: "GENIEBLOCKS.webp",
    ## HardwareModel.NRF52_UNKNOWN: "NRF52_UNKNOWN.webp",
    ## HardwareModel.ANDROID_SIM: "ANDROID_SIM.webp",
    ## HardwareModel.DIY_V1: "DIY_V1.webp",
    HardwareModel.NRF52840_PCA10059: "NRF52840_PCA10059.webp",
    ## HardwareModel.DR_DEV: "DR_DEV.webp",
    ## HardwareModel.M5STACK: "M5STACK.webp",
    ## HardwareModel.BETAFPV_2400_TX: "BETAFPV_2400_TX.webp",
    ## HardwareModel.BETAFPV_900_NANO_TX: "BETAFPV_900_NANO_TX.webp",
    HardwareModel.HELTEC_WIRELESS_PAPER_V1_0: "HELTEC_WIRELESS_PAPER_V1_0.webp",
    HardwareModel.UNPHONE: "UNPHONE.webp",
    ## HardwareModel.TD_LORAC: "TD_LORAC.webp",
    HardwareModel.CDEBYTE_EORA_S3: "CDEBYTE_EORA_S3.webp",
    ## HardwareModel.TWC_MESH_V4: "TWC_MESH_V4.webp",
    ## HardwareModel.NRF52_PROMICRO_DIY: "NRF52_PROMICRO_DIY.webp",
    # HardwareModel.RADIOMASTER_900_BANDIT_NANO: "RADIOMASTER_900_BANDIT_NANO.webp",
    HardwareModel.HELTEC_VISION_MASTER_T190: "HELTEC_VISION_MASTER_T190.webp",
    HardwareModel.HELTEC_VISION_MASTER_E213: "HELTEC_VISION_MASTER_E213.webp",
    HardwareModel.HELTEC_VISION_MASTER_E290: "HELTEC_VISION_MASTER_E290.webp",
    HardwareModel.SENSECAP_INDICATOR: "SENSECAP_INDICATOR.webp",
    HardwareModel.RAK3172: "RAK3172.webp",
    HardwareModel.WIO_E5: "WIO_E5.webp",
    ## HardwareModel.RADIOMASTER_900_BANDIT: "RADIOMASTER_900_BANDIT.webp",
    HardwareModel.ME25LS01_4Y10TD: "ME25LS01_4Y10TD.webp",
    HardwareModel.RP2040_FEATHER_RFM95: "RP2040_FEATHER_RFM95.webp",
    HardwareModel.M5STACK_COREBASIC: "M5STACK_COREBASIC.webp",
    HardwareModel.M5STACK_CORE2: "M5STACK_CORE2.webp",
    HardwareModel.M5STACK_CORES3: "M5STACK_CORES3.webp",
    HardwareModel.MS24SF1: "MS24SF1.webp",
    HardwareModel.TLORA_C6: "TLORA_C6.webp",
    HardwareModel.WISMESH_TAP: "WISMESH_TAP.webp",
    HardwareModel.ROUTASTIC: "ROUTASTIC.webp",
    ## HardwareModel.MESH_TAB: "MESH_TAB.webp",
    ## HardwareModel.MESHLINK: "MESHLINK.webp",
    HardwareModel.XIAO_NRF52_KIT: "XIAO_NRF52_KIT.webp",
    HardwareModel.THINKNODE_M1: "THINKNODE_M1.webp",
    HardwareModel.THINKNODE_M2: "THINKNODE_M2.webp",
    HardwareModel.T_ETH_ELITE: "T_ETH_ELITE.webp",
    HardwareModel.HELTEC_SENSOR_HUB: "HELTEC_SENSOR_HUB.webp",
    HardwareModel.RESERVED_FRIED_CHICKEN: "RESERVED_FRIED_CHICKEN.webp",
    HardwareModel.HELTEC_MESH_POCKET: "HELTEC_MESH_POCKET.webp",
    HardwareModel.SEEED_SOLAR_NODE: "SEEED_SOLAR_NODE.webp",
    HardwareModel.NOMADSTAR_METEOR_PRO: "NOMADSTAR_METEOR_PRO.webp",
    # HardwareModel.CROWPANEL: "CROWPANEL.webp",
    ## HardwareModel.LINK_32: "LINK_32.webp",
    HardwareModel.SEEED_WIO_TRACKER_L1: "SEEED_WIO_TRACKER_L1.webp",
    ## HardwareModel.SEEED_WIO_TRACKER_L1_EINK: "SEEED_WIO_TRACKER_L1_EINK.webp",
    ## HardwareModel.QWANTZ_TINY_ARMS: "QWANTZ_TINY_ARMS.webp",
    HardwareModel.T_DECK_PRO: "T_DECK_PRO.webp",
    HardwareModel.T_LORA_PAGER: "T_LORA_PAGER.webp",
    ## HardwareModel.GAT562_MESH_TRIAL_TRACKER: "GAT562_MESH_TRIAL_TRACKER.webp",
}

def validate_hardware_model(hw_model_value):
    """
    Strictly validate a hardware model value against the HardwareModel enum.
    
    Args:
        hw_model_value: The numeric hardware model value
        
    Returns:
        The matching HardwareModel enum value
        
    Raises:
        ValueError: If the hardware model value is not in the enum
    """
    if hw_model_value is None:
        raise ValueError("Hardware model value cannot be None")
    
    for model in HardwareModel:
        if model.value == hw_model_value:
            return model
    
    raise ValueError(f"Invalid hardware model value: {hw_model_value}")

def get_hardware_model_name(hw_model_value):
    """
    Convert a hardware model value to a human-readable name.
    
    Args:
        hw_model_value: The numeric hardware model value
        
    Returns:
        A human-readable hardware model name or "Unknown (value)" if not recognized
    """
    try:
        model = validate_hardware_model(hw_model_value)
        return model.name.replace('_', ' ')
    except ValueError:
        return f"Unknown ({hw_model_value})"


def get_modem_preset_name(modem_preset_value):
    """
    Convert a modem preset value to a human-readable name.
    
    Args:
        modem_preset_value: The numeric modem preset value
        
    Returns:
        A human-readable modem preset name or "Unknown (value)" if not recognized
    """
    if modem_preset_value is None:
        return "Unknown"
    
    try:
        for preset in ModemPreset:
            if preset.value == modem_preset_value:
                # Convert the enum name to a more readable format
                words = preset.name.split('_')
                formatted_words = [word.capitalize() for word in words]
                return ' '.join(formatted_words)
        
        # If not found in our enum, return unknown with the value
        return f"Unknown ({modem_preset_value})"
    except Exception:
        return f"Unknown ({modem_preset_value})"

def get_routing_error_name(error_value):
    """
    Convert a routing error value to a human-readable name.
    
    Args:
        error_value: The numeric routing error value
        
    Returns:
        A human-readable routing error name or "Unknown (value)" if not recognized
    """
    if error_value is None:
        return "None"
    
    try:
        for error in RoutingError:
            if error.value == error_value:
                return error.name
        return f"Unknown ({error_value})"
    except Exception:
        return f"Unknown ({error_value})"

def get_routing_error_description(error_value):
    """
    Get a human-readable description of a routing error.
    
    Args:
        error_value: The numeric routing error value
        
    Returns:
        A human-readable description of the routing error
    """
    if error_value is None:
        return "No error"
    
    error_descriptions = {
        RoutingError.NONE: "Message sent successfully",
        RoutingError.NO_ROUTE: "No path available to reach the destination",
        RoutingError.GOT_NAK: "Message was rejected by a relay node",
        RoutingError.TIMEOUT: "Message timed out during transmission",
        RoutingError.NO_INTERFACE: "No communication interface available for delivery",
        RoutingError.MAX_RETRANSMIT: "Maximum retry attempts exceeded",
        RoutingError.NO_CHANNEL: "Requested channel is not available or disabled",
        RoutingError.TOO_LARGE: "Message is too large to send",
        RoutingError.NO_RESPONSE: "Destination received the message but no service responded",
        RoutingError.DUTY_CYCLE_LIMIT: "Cannot send due to radio duty cycle restrictions",
        RoutingError.BAD_REQUEST: "Destination received the message but considered it invalid",
        RoutingError.NOT_AUTHORIZED: "Message sent on wrong channel or lacks proper authorization",
        RoutingError.PKI_FAILED: "Encrypted transport failed - message not sent",
        RoutingError.PKI_UNKNOWN_PUBKEY: "Destination has no encryption key available",
        RoutingError.ADMIN_BAD_SESSION_KEY: "Admin message uses invalid or expired session key",
        RoutingError.ADMIN_PUBLIC_KEY_UNAUTHORIZED: "Admin message from unauthorized sender",
        RoutingError.RATE_LIMIT_EXCEEDED: "Message blocked by airtime fairness limits"
    }
    
    try:
        for error in RoutingError:
            if error.value == error_value:
                return error_descriptions.get(error, f"Unknown error ({error_value})")
        return f"Unknown error ({error_value})"
    except Exception:
        return f"Unknown error ({error_value})"

def get_rebroadcast_mode_name(rebroadcast_mode_value):
    """
    Convert a rebroadcast mode value to a human-readable name.
    
    Args:
        rebroadcast_mode_value: The numeric rebroadcast mode value
        
    Returns:
        A human-readable rebroadcast mode name or "Unknown (value)" if not recognized
    """
    if rebroadcast_mode_value is None:
        return "Unknown"
    
    try:
        for mode in RebroadcastMode:
            if mode.value == rebroadcast_mode_value:
                # Convert the enum name to a more readable format
                words = mode.name.split('_')
                formatted_words = [word.capitalize() for word in words]
                return ' '.join(formatted_words)
        
        # If not found in our enum, return unknown with the value
        return f"Unknown ({rebroadcast_mode_value})"
    except Exception:
        return f"Unknown ({rebroadcast_mode_value})"

def get_buzzer_mode_name(buzzer_mode_value):
    """
    Convert a buzzer mode value to a human-readable name.
    
    Args:
        buzzer_mode_value: The numeric buzzer mode value
        
    Returns:
        A human-readable buzzer mode name or "Unknown (value)" if not recognized
    """
    if buzzer_mode_value is None:
        return "Unknown"
    
    try:
        for mode in BuzzerMode:
            if mode.value == buzzer_mode_value:
                # Convert the enum name to a more readable format
                words = mode.name.split('_')
                formatted_words = [word.capitalize() for word in words]
                return ' '.join(formatted_words)
        
        # If not found in our enum, return unknown with the value
        return f"Unknown ({buzzer_mode_value})"
    except Exception:
        return f"Unknown ({buzzer_mode_value})"
