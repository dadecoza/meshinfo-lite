from datetime import datetime, timedelta
import pytz
import configparser

def get_timezone():
    """Get timezone from config.ini file, defaulting to UTC if not specified"""
    config = configparser.ConfigParser()
    config.read('config.ini')
    
    if 'server' in config and 'timezone' in config['server']:
        return config['server']['timezone']
    return 'UTC'  # Default to UTC if not specified

def convert_to_local(timestamp):
    """Convert a UTC timestamp to local time based on config.ini timezone"""
    if timestamp is None:
        return None
        
    if isinstance(timestamp, (int, float)):
        utc_dt = datetime.fromtimestamp(timestamp, pytz.UTC)
    else:
        utc_dt = timestamp.replace(tzinfo=pytz.UTC)
    
    local_tz = pytz.timezone(get_timezone())
    return utc_dt.astimezone(local_tz)

def format_timestamp(timestamp, format='%Y-%m-%d %H:%M:%S %Z'):
    """Format a timestamp using the configured timezone"""
    local_time = convert_to_local(timestamp)
    if local_time is None:
        return ''
    return local_time.strftime(format)

def time_ago(timestamp):
    """
    Convert timestamp to a readable "time ago" format
    Example outputs: "2 minutes ago", "3 hours, 5 minutes ago", "2 days, 4 hours ago"
    """
    if timestamp is None:
        return "unknown"
    
    if isinstance(timestamp, (int, float)):
        timestamp_dt = datetime.fromtimestamp(timestamp, pytz.UTC)
    else:
        timestamp_dt = timestamp.replace(tzinfo=pytz.UTC)
    
    # Get current time in UTC
    now = datetime.now(pytz.UTC)
    
    # Calculate the time difference
    diff = now - timestamp_dt
    
    # Calculate days, hours, minutes, seconds
    days = diff.days
    hours, remainder = divmod(diff.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    # Format the time difference in a human-readable way
    if days > 0:
        if hours > 0:
            return f"{days} {'day' if days == 1 else 'days'}, {hours} {'hour' if hours == 1 else 'hours'} ago"
        return f"{days} {'day' if days == 1 else 'days'} ago"
    elif hours > 0:
        if minutes > 0:
            return f"{hours} {'hour' if hours == 1 else 'hours'}, {minutes} {'minute' if minutes == 1 else 'minutes'} ago"
        return f"{hours} {'hour' if hours == 1 else 'hours'} ago"
    elif minutes > 0:
        return f"{minutes} {'minute' if minutes == 1 else 'minutes'} ago"
    else:
        return f"{seconds} {'second' if seconds == 1 else 'seconds'} ago"