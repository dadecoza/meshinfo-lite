#!/usr/bin/env python3

import datetime
from datetime import timedelta
import requests
import time
from math import asin, cos, radians, sin, sqrt
import string
import random
import bcrypt
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import configparser
import logging
from meshtastic_support import Role, Channel, ShortChannel
import hashlib


def distance_between_two_points(lat1, lon1, lat2, lon2):
    """
    Calculate the Haversine distance between two latitude/longitude points.
    """
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlon = lon2 - lon1
    dlat = lat2 - lat1
    a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    c = 2 * asin(sqrt(a))
    radius = 6371  # Radius of Earth in kilometers
    return radius * c


def calculate_distance_between_nodes(node1, node2):
    """Calculate distance between two nodes in kilometers."""
    # Handle both dictionary and object access
    pos1 = node1.get("position") if isinstance(node1, dict) else node1.position
    pos2 = node2.get("position") if isinstance(node2, dict) else node2.position
    
    if not pos1 or not pos2:
        return None
        
    # Handle both dictionary and object access for latitude_i and longitude_i
    lat1 = pos1.get("latitude_i") if isinstance(pos1, dict) else pos1.latitude_i
    lon1 = pos1.get("longitude_i") if isinstance(pos1, dict) else pos1.longitude_i
    lat2 = pos2.get("latitude_i") if isinstance(pos2, dict) else pos2.latitude_i
    lon2 = pos2.get("longitude_i") if isinstance(pos2, dict) else pos2.longitude_i
    
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return None

    return distance_between_two_points(
        lat1 / 1e7,
        lon1 / 1e7,
        lat2 / 1e7,
        lon2 / 1e7
    )


def convert_node_id_from_int_to_hex(node_id: int):
    """Convert an integer node ID to a hexadecimal string."""
    return f"{node_id:08x}"


def convert_node_id_from_hex_to_int(node_id: str):
    """Convert a hexadecimal node ID to an integer."""
    return int(node_id.lstrip("!"), 16)


def days_since_datetime(dt):
    """Return the number of days since a given UTC datetime."""
    now = datetime.datetime.now(datetime.timezone.utc)
    if isinstance(dt, str):
        dt = datetime.datetime.fromisoformat(dt)
    return (now - dt).days


def geocode_position(api_key: str, latitude: float, longitude: float):
    """Retrieve geolocation data using an API."""
    if latitude is None or longitude is None:
        return None
    
    # Try the paid service first if API key is provided
    if api_key and api_key != 'YOUR_KEY_HERE':
        try:
            url = f"https://geocode.maps.co/reverse" + \
                f"?lat={latitude}&lon={longitude}&api_key={api_key}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logging.warning(f"Paid geocoding service failed: {e}")
    
    # Fallback to Nominatim (free, no API key required)
    try:
        url = f"https://nominatim.openstreetmap.org/reverse" + \
            f"?format=json&lat={latitude}&lon={longitude}&zoom=10"
        headers = {
            'User-Agent': 'MeshInfo/1.0 (https://github.com/meshinfo-lite)'
        }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logging.warning(f"Nominatim geocoding service failed: {e}")
    
    return None


def latlon_to_grid(lat, lon):
    """Convert latitude and longitude to Maidenhead grid locator."""
    lon += 180
    lat += 90
    return (
        chr(int(lon / 20) + ord("A"))
        + chr(int(lat / 10) + ord("A"))
        + str(int((lon % 20) / 2))
        + str(int((lat % 10) / 1))
        + chr(int((lon % 2) * 12) + ord("a"))
        + chr(int((lat % 1) * 24) + ord("a"))
    )


def graph_icon(name):
    """Return the appropriate icon for a given node name."""
    icons = {
        "qth": "house",
        "home": "house",
        "base": "house",
        "main": "house",
        "mobile": "car",
        " hs": "tower",
        "router": "tower",
        "edc": "heltec",
        "mqtt": "computer",
        "bridge": "computer",
        "gateway": "computer",
        "meshtastic": "meshtastic",
        "bbs": "bbs",
        "narf": "narf"
    }
    for key, icon in icons.items():
        if key in name.lower():
            return f"/images/icons/{icon}.png"
    return "/images/icons/radio.png"


def filter_dict(data, whitelist):
    """Recursively filter a dictionary to only include whitelisted keys."""
    if isinstance(data, dict):
        return {
            key: filter_dict(data[key], whitelist[key])
            if isinstance(data[key], (dict, list))
            else data[key]
            for key in whitelist if key in data
        }
    if isinstance(data, list):
        return [
            filter_dict(item, whitelist) if isinstance(item, dict) else item
            for item in data
        ]
    return data


def time_since_bak(epoch_timestamp):
    """Convert an epoch timestamp to a human-readable duration."""
    elapsed_seconds = int(time.time()) - epoch_timestamp
    if elapsed_seconds < 0:
        return "The timestamp is in the future!"
    time_units = [
        ("day", elapsed_seconds // 86400),
        ("hour", (elapsed_seconds % 86400) // 3600),
        ("minute", (elapsed_seconds % 3600) // 60),
        ("second", elapsed_seconds % 60),
    ]
    return ", ".join(
        f"{int(value)} {unit}{'s' if value > 1 else ''}"
        for unit, value in time_units if value > 0
    ) or "Just now"


def time_since(epoch_timestamp):
    diff = epoch_timestamp - time.time()  # Calculate the difference
    sign = "-" if diff < 0 else ""
    diff = abs(diff)  # Work with absolute difference
    td = timedelta(seconds=diff)

    total_seconds = int(td.total_seconds())
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    formatted_diff = f"{sign}{hours:02}:{minutes:02}:{seconds:02}"
    return formatted_diff


def active_nodes(nodes):
    return {
        node: nodes[node]  # Return reference instead of copying
        for node in nodes if nodes[node]["active"]
    }

def get_role_name(role_value):
    """
    Get the human-readable name for a role value.
    
    Args:
        role_value (int): The numeric role value from the database
        
    Returns:
        str: The human-readable role name or "Unknown (value)" if not recognized
    """
    if role_value is None:
        return "Client"
    
    # Special display name mappings for user-friendly names
    role_display_names = {
        7: "TAK",  # TAK enum
        10: "TAK Tracker",  # TAK_TRACKER enum
    }
    
    if role_value in role_display_names:
        return role_display_names[role_value]
    
    try:
        # Get the role name, replace underscores with spaces, and capitalize each word
        role_name = Role(role_value).name.replace('_', ' ')
        return ' '.join(word.capitalize() for word in role_name.split())
    except (ValueError, AttributeError):
        return f"Unknown ({role_value})"

def get_owner_nodes(nodes, owner):
    return {
        node: nodes[node]  # Return reference instead of copying
        for node in nodes if nodes[node]["owner"] == owner
    }


def generate_random_code(length=6):
    characters = string.ascii_letters
    return ''.join(random.choices(characters, k=length))


def generate_random_otp(length=4):
    characters = string.digits
    return ''.join(random.choices(characters, k=length))


def hash_password(password: str) -> str:
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def check_password(password: str, hashed_password: str) -> bool:
    """Checks if a password matches its hashed version."""
    return bcrypt.checkpw(password.encode(), hashed_password)


def send_email(recipient_email, subject, message):
    config = configparser.ConfigParser()
    config.read('config.ini')
    try:
        # Set up the SMTP server (Gmail SMTP)
        smtp_server = config["smtp"]["server"]
        smtp_port = int(config["smtp"]["port"])
        sender_email = config["smtp"]["email"]
        sender_password = config["smtp"]["password"]

        # Create message
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        # Connect to SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)  # Login to your email
        server.send_message(msg)  # Send email
        server.quit()  # Close connection

        logging.info("Email sent successfully!")

    except Exception as e:
        logging.error(str(e))


def get_channel_name(channel_value, use_short_names=False):
    """Convert a channel number to its human-readable name."""
    if channel_value is None:
        return "Unknown"
    try:
        if use_short_names:
            channel_name = ShortChannel(channel_value).name
            return channel_name
        else:
            channel_name = Channel(channel_value).name
            # Keep the underscores but capitalize each word
            words = channel_name.split('_')
            formatted_words = [word.capitalize() for word in words]
            return ''.join(formatted_words)
    except (ValueError, TypeError):
        return f"Unknown ({channel_value})"


def get_channel_color(channel_value):
    """
    Generate a consistent, visually pleasing color for a channel.
    
    Args:
        channel_value: The numeric channel value
        
    Returns:
        A hex color code (e.g., "#FF5733")
    """
    if channel_value is None:
        return "#808080"  # Gray for unknown channels
    
    # Define a set of visually pleasing colors for known channels
    channel_colors = {
        8: "#4CAF50",    # Green for LongFast
        24: "#9C27B0",   # Purple for MediumSlow
        31: "#2196F3",   # Blue for MediumFast
        112: "#FF9800",  # Orange for ShortFast
        # Add more channels as they are discovered
    }
    
    # If we have a predefined color for this channel, use it
    if channel_value in channel_colors:
        return channel_colors[channel_value]
    
    # For unknown channels, generate a consistent color based on the channel value
    # Using a hash function to convert the channel value to a color
    
    # Create a hash of the channel value
    hash_object = hashlib.md5(str(channel_value).encode())
    hex_dig = hash_object.hexdigest()
    
    # Use the first 6 characters of the hash as the color
    # This ensures the same channel always gets the same color
    color = f"#{hex_dig[:6]}"
    
    # Adjust the color to ensure it's visually pleasing
    # Convert to RGB, adjust saturation and brightness, then back to hex
    r = int(color[1:3], 16)
    g = int(color[3:5], 16)
    b = int(color[5:7], 16)
    
    # Increase saturation and brightness
    max_val = max(r, g, b)
    min_val = min(r, g, b)
    
    # If the color is too dark, lighten it
    if max_val < 100:
        r = min(255, r + 100)
        g = min(255, g + 100)
        b = min(255, b + 100)
    
    # If the color is too light, darken it slightly
    if min_val > 200:
        r = max(0, r - 50)
        g = max(0, g - 50)
        b = max(0, b - 50)
    
    # Convert back to hex
    return f"#{r:02x}{g:02x}{b:02x}"


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
        from meshtastic_support import ModemPreset
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
