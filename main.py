import threading
import logging
import colorlog
import configparser
import time
import sys
import os
import atexit
import signal


def setup_logger():
    config = configparser.ConfigParser()
    config.read('config.ini')
    log_level = logging.DEBUG if config["server"]["debug"] == "true" \
        else logging.INFO
    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)  # Set to lowest level to capture all logs

    # Create a console handler
    handler = logging.StreamHandler()
    handler.setLevel(log_level)

    # Define a formatter with colors
    formatter = colorlog.ColoredFormatter(
        "%(log_color)s%(asctime)s - %(levelname)s - [%(name)s] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'bold_red',
        }
    )

    # Set the formatter for the handler
    handler.setFormatter(formatter)

    # Avoid duplicate handlers
    if not logger.hasHandlers():
        logger.addHandler(handler)

    return logger

logger = setup_logger()

import meshinfo_web
import meshinfo_mqtt
from meshdata import MeshData, create_database

def check_pid(pid):
    """Check if the process with the given PID is running and is our process."""
    try:
        # Check if process exists
        os.kill(pid, 0)
        # Check if it's our process by reading /proc/<pid>/cmdline
        try:
            with open(f'/proc/{pid}/cmdline', 'rb') as f:
                cmdline = f.read().decode('utf-8', errors='ignore')
                return 'python' in cmdline and 'main.py' in cmdline
        except (IOError, PermissionError):
            return False
    except OSError:
        return False

def cleanup_pidfile():
    """Remove the PID file on exit."""
    try:
        if os.path.exists(pidfile):
            os.remove(pidfile)
            logger.info("Cleaned up PID file")
    except Exception as e:
        logger.error(f"Error cleaning up PID file: {e}")

def handle_signal(signum, frame):
    """Handle termination signals gracefully."""
    logger.info(f"Received signal {signum}, cleaning up...")
    cleanup_pidfile()
    sys.exit(0)

def threadwrap(threadfunc):
    def wrapper():
        while True:
            try:
                threadfunc()
            except BaseException as e:
                logger.error('{!r}; restarting thread'.format(e))
            else:
                logger.error('exited normally, bad thread; restarting')
    return wrapper

pidfile = "meshinfo.pid"
pid = None

# Register signal handlers
signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)

# Register cleanup function
atexit.register(cleanup_pidfile)

try:
    if os.path.exists(pidfile):
        with open(pidfile, "r") as fh:
            pid = int(fh.read().strip())
            if check_pid(pid):
                logger.info("Process already running with PID %d", pid)
                sys.exit(0)
            else:
                logger.warning("Found stale PID file, removing it")
                os.remove(pidfile)
except Exception as e:
    logger.warning(f"Error reading PID file: {e}")

# Write our PID
try:
    with open(pidfile, "w") as fh:
        fh.write(str(os.getpid()))
    logger.info("Wrote PID file")
except Exception as e:
    logger.error(f"Error writing PID file: {e}")
    sys.exit(1)

config_file = "config.ini"

if not os.path.isfile(config_file):
    logger.error(f"Error: Configuration file '{config_file}' not found!")
    sys.exit(1)

try:
    with open("banner", "r") as fh:
        logger.info(fh.read())
except Exception as e:
    logger.warning(f"Error reading banner file: {e}")

logger.info("Setting up database")
db_connected = False
for i in range(10):
    try:
        md = MeshData()
        md.setup_database()
        db_connected = True
        break
    except Exception as e:
        logger.warning(f"Waiting for database to become ready.")
        logger.error(str(e))
        time.sleep(10)
if not db_connected:
    logger.error("Giving up. Bye.")
    sys.exit(1)

thread_mqtt = threading.Thread(target=threadwrap(meshinfo_mqtt.run))
thread_web = threading.Thread(target=threadwrap(meshinfo_web.run))

thread_mqtt.start()
thread_web.start()

thread_mqtt.join()
thread_web.join()
