'''
File Preprocessor Script V1.1
This script monitors a specified directory for incoming JSON files,
processes them, and handles corrupted files by moving them to a separate directory.

Author: Jordan Lanham
Date: 2025-11-18
'''

import json
import os
import time
import threading
import logging
import shutil

PCAP_PREFIX = "x_"
PCAP_WATCH_DIR = "./PCAP"
PCAP_NAS_DIR = "/mnt/nas"
WATCH_DIR = "./REPORTS"
PROCESSED_DIR = "./processed"
CORRUPTED_DIR = "./corrupted"

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def ensure_directories():
    """Create all required directories if they don't exist."""
    directories = [PROCESSED_DIR, CORRUPTED_DIR, PCAP_WATCH_DIR, PCAP_NAS_DIR]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Directory ensured: {directory}")

def process_file(file_path):
    """Process JSON files and move them to appropriate directories."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        logger.info(f"Processing file: {file_path}")
        time.sleep(1)
        processed_path = os.path.join(PROCESSED_DIR, os.path.basename(file_path))
        shutil.move(file_path, processed_path)
        logger.info(f"File processed and moved to: {processed_path}")

    except json.JSONDecodeError:
        corrupted_path = os.path.join(CORRUPTED_DIR, os.path.basename(file_path))
        shutil.move(file_path, corrupted_path)
        logger.warning(f"File is corrupted and moved to: {corrupted_path}")
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {e}")

def process_pcap_file(file_path):
    """Process PCAP files and move them to NAS storage if they match the prefix."""
    try:
        filename = os.path.basename(file_path)
        if filename.startswith(PCAP_PREFIX):
            nas_path = os.path.join(PCAP_NAS_DIR, filename)
            
            # Handle potential filename conflicts
            counter = 1
            original_nas_path = nas_path
            while os.path.exists(nas_path):
                name, ext = os.path.splitext(original_nas_path)
                nas_path = f"{name}_{counter}{ext}"
                counter += 1
            
            shutil.move(file_path, nas_path)
            logger.info(f"PCAP file moved to NAS storage: {nas_path}")
        else:
            logger.info(f"PCAP file '{filename}' does not match prefix '{PCAP_PREFIX}', ignoring.")
    except Exception as e:
        logger.error(f"Error processing PCAP file {file_path}: {e}")

def watch_directory():
    """Monitor the main watch directory for JSON files."""
    logger.info(f"Started watching directory: {WATCH_DIR}")
    while True:
        try:
            if os.path.exists(WATCH_DIR):
                for filename in os.listdir(WATCH_DIR):
                    file_path = os.path.join(WATCH_DIR, filename)
                    if os.path.isfile(file_path) and filename.endswith('.json'):
                        process_file(file_path)
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error in watch_directory: {e}")
            time.sleep(5)

def watch_pcap_directory():
    """Monitor the PCAP watch directory for PCAP files."""
    logger.info(f"Started watching PCAP directory: {PCAP_WATCH_DIR}")
    while True:
        try:
            if os.path.exists(PCAP_WATCH_DIR):
                for filename in os.listdir(PCAP_WATCH_DIR):
                    file_path = os.path.join(PCAP_WATCH_DIR, filename)
                    if os.path.isfile(file_path) and (filename.endswith('.pcap') or filename.endswith('.cap')):
                        process_pcap_file(file_path)
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error in watch_pcap_directory: {e}")
            time.sleep(5)

def main():
    """Main function that starts both watchers using threading."""
    ensure_directories()
    
    # Create threads for both watchers
    json_watcher_thread = threading.Thread(target=watch_directory, name="JSONWatcher", daemon=True)
    pcap_watcher_thread = threading.Thread(target=watch_pcap_directory, name="PCAPWatcher", daemon=True)
    
    # Start both threads
    json_watcher_thread.start()
    pcap_watcher_thread.start()
    
    logger.info("Both watchers started. Press Ctrl+C to stop.")
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutdown requested by user")
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}")

if __name__ == "__main__":
    # Start a small TCP health listener for the pre-processor (default 9002)
    try:
        from health_endpoint import start_tcp_listener, start_http_status
    except Exception:
        from .health_endpoint import start_tcp_listener, start_http_status

    hp = int(os.environ.get('HEALTH_PORT', '9002'))
    ht = os.environ.get('HEALTH_TYPE', 'tcp')
    if ht.lower() == 'http':
        start_http_status(hp, path=os.environ.get('HEALTH_PATH', '/status'), name='pre-processor')
    else:
        start_tcp_listener(hp, name='pre-processor')

    main()
