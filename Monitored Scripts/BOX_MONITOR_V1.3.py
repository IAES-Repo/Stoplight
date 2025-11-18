"""
Box Monitor Script V 1.2
Monitors a directory for new files and automatically uploads them to Box.

Author: Jordan Lanham
Date: 2025-11-18
"""


import os
import sys
import time
import random
from datetime import datetime
from threading import Thread, Event, Lock
from boxsdk import JWTAuth, Client
from boxsdk.exception import BoxAPIException
from requests.exceptions import SSLError, ConnectionError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


VERSION = "1.2"

BOX_CLIENT_ID = "o0lou4tt9xpasafmmkj6vu41a65einp6"
BOX_CLIENT_SECRET = "AGBAsAh8zFTCmFCYybkkcE8B9Z93lGkR"
BOX_ENTERPRISE_ID = "396196"
BOX_JWT_PUBLIC_KEY_ID = "eh81osx8"
BOX_JWT_PRIVATE_KEY = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI2Z63gYQJcwECAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECFR5i21zy4AmBIIEyK2GUvoNWb8+
G/4rUhGGttzRwQITyP6mxS3GNSE7MEotOYHwYoeF/1oj2dqRENlg9SZSEkRcCoZP
io3CT2oj9UeLLEEDjbWsk/UwDTPSkIjs6wl70gb90WabMx71UOJqMXH/+GxA5rTR
xIjGGL2qznuKda/CnadVaArmq7ZYAslCYgL62BJkcCgRYTPLigdMhWWD970ZLh27
+ISQMM9p9WjGJ4e0a1qfjP9CRNs1IkOGHQ2bFgjHizh0g3OXcXYfj60mD3Kkz0Me
GqGzD3iJ8yQDx16fx6HL7NRP+sDULBa8y9zG/Lgh2kOKmWmUjnLoZWXPzg2UJaeS
O3XA0lad+a+deXCuc9TBCEiPu5+2kMiWRZrCKsdB3a0jHbid+bz91sEq+apPb8bX
aDMR/1JzZt8Wn+sdaWVKhdTOX277WyFJwRl0LEE7pJFncCn2umMhTUAuU0mHzwYX
96B717btWzXJ8bgtFyxa+Ti3U9ZYwUvrEjj7zE4Bm33/mUC+4VzofBUJ2I2sgwIr
bkuSx1IwbExCFzVQac9zlLEgEBgXhg4N3GvujWw6NZIQoZreeoUkZ77msc5bK7YK
KDCZMdYqJqf8nyu+8qeg1mCv6FKgr2amMtCpc/1rMqVF+aqhPpTT/tKprYCPCheJ
+/H7/d0Pf6H+rimgXYokxL7GqXSbQk88bkqwzyi98YqpXGH1nvCBSRIXd0cpQFQi
kXjubN5ZY4+VBjh8e2YkZ2JjwBbK8qlqF9HFZ7pzd8Uq1ljrRO4vHyme/NT1mncx
7FWm0qjLUoSSt02LNFdMxXeB/rZfnewP3I49+bwzpiM3Beqwhxt1Mf+U+FUaF7CH
1SspPhy6jNTiWJsjyI0Irj+81SXWTycWFcZ8PpQ2xq8Ifw5EXZ+VqZgIfqRm7E3g
Ya68cloNXl2XX7VTFvV1prZbxJDs4vlnhEVrVchT5AeEmaeg60txFl0obnQydcQF
YEAWpRKHnRuj/vXB2Sdw2LFCVkI9icn86qNvbR9vsTmYQKs7HdHrXTdLQpnJgV3H
4XeS0Ot8KqtpqfTt1on4lxoMSMIhUIcmZgSz6Yzz0/+GAkj2xsWOsZrgSi/FEhq8
kkbFIXQ9/Sh0zp6RHdWYKWA1OK0bBXESOD7+pOO3QSMGhIFf1J8xhU5+GCTPkavm
AnNFI68G9Vc9D7zzsgegjy6YJgxU1JO2/qoLJi+PYMVDR8mIHqtc1JgVm6KQniRo
m2lBH6fXDMis62ovTiLrePSdphSkFtEFvbTVKrS2WGZSol1o66OSSD2Pn0jAMNIx
q4h0PTD3M+SuyFhVoOxmiyGI6gGTP7KNzsYUhBr4ggr6K5iGAdXU7W8krrC99X/Q
26LGkG4QUIGXBtQyriY0M9/W4wO9mM4eSgcTR6Slhx5L4Uh1zLOnPUNmItVjCTzi
jC5lhVaojTYTpm7MVKFdqW5KA1EPn+3XmlR17Ei5k3A30YxWLP1t7voiBWuIWlFK
YeyzrhP3uW3a2u7XWGSY6nQ7E13GnmPqJEBQffB1QYKi/USFcNiCmFvhXy68nJo5
AzHH61kCpOlGreHgH5oFeNFVtD6MFaFG78fT2G5ZB1kxhlvoFl5bW9Q+0tLzX3tX
ErrxLt5aPSyKj/yN0FB2TA==
-----END ENCRYPTED PRIVATE KEY-----"""
BOX_JWT_PASSPHRASE = "e43a27339b21ca1448fd43d47919ccb9"

BOX_DECAP_FOLDER_ID = "315181091837"

FOLDER_MAP = {
    "/home/iaes/DiodeSensor/processed": BOX_DECAP_FOLDER_ID,
}


STATUS_INTERVAL_SEC = 600          
FILE_STABLE_WINDOW_SEC = 2.5        
FILE_CHECK_INTERVAL_SEC = 0.5
FILE_READY_TIMEOUT_SEC = 45
MAX_CACHED_DAY_FOLDERS = 30
MAX_UPLOAD_RETRIES = 3
RETRY_BASE_DELAY = 1.0  
RETRY_MAX_DELAY = 8.0

def _ts():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def info(msg, *a):
    print(f"{_ts()} [INFO] " + (msg % a if a else msg))

def warn(msg, *a):
    print(f"{_ts()} [WARN] " + (msg % a if a else msg))

def error(msg, *a):
    print(f"{_ts()} [ERROR] " + (msg % a if a else msg))

def debug(msg, *a):
    print(f"{_ts()} [DEBUG] " + (msg % a if a else msg)) #Feel free to comment for less output

def critical(msg, *a):
    print(f"{_ts()} [CRITICAL] " + (msg % a if a else msg))

stats_ok = 0
stats_fail = 0
stats_last_time = None
stats_total_bytes = 0
stats_lock = Lock()
day_folder_cache = {}  
box_client = None

def init_box_client():
    global box_client
    missing_folder_ids = [k for k, v in FOLDER_MAP.items() if not v]
    if missing_folder_ids:
        raise RuntimeError(f"Missing folder IDs for: {', '.join(missing_folder_ids)}")
    required_consts = {
        'BOX_CLIENT_ID': BOX_CLIENT_ID,
        'BOX_CLIENT_SECRET': BOX_CLIENT_SECRET,
        'BOX_ENTERPRISE_ID': BOX_ENTERPRISE_ID,
        'BOX_JWT_PUBLIC_KEY_ID': BOX_JWT_PUBLIC_KEY_ID,
        'BOX_JWT_PRIVATE_KEY': BOX_JWT_PRIVATE_KEY,
        'BOX_JWT_PASSPHRASE': BOX_JWT_PASSPHRASE,
    }
    missing = [k for k,v in required_consts.items() if not v or 'YOUR_' in str(v)]
    if missing:
        raise RuntimeError(f"Configure constants (replace placeholders) for: {', '.join(missing)}")
    try:
        auth = JWTAuth(
            client_id=BOX_CLIENT_ID,
            client_secret=BOX_CLIENT_SECRET,
            enterprise_id=BOX_ENTERPRISE_ID,
            jwt_key_id=BOX_JWT_PUBLIC_KEY_ID,
            rsa_private_key_data=BOX_JWT_PRIVATE_KEY,
            rsa_private_key_passphrase=BOX_JWT_PASSPHRASE.encode()
        )
        box_client = Client(auth)
        auth.authenticate_instance()
        info("Authenticated with Box API")
    except Exception as e:
        error("Failed to initialize Box client: %s: %s", type(e).__name__, e)
        raise

def record_stat(size, success):
    global stats_ok, stats_fail, stats_last_time, stats_total_bytes
    with stats_lock:
        if success:
            stats_ok += 1
            stats_total_bytes += size
            stats_last_time = datetime.now()
        else:
            stats_fail += 1

def status_report():
    now = datetime.now()
    with stats_lock:
        last = "Never" if not stats_last_time else f"{(now - stats_last_time)}".split('.')[0]
        avg = (stats_total_bytes / stats_ok) if stats_ok else 0
        total_ops = stats_ok + stats_fail
        rate = (stats_ok / total_ops * 100) if total_ops else 0
    return (
        f"=== WatchTower Status (v{VERSION}) ===\n"
        f"Timestamp: {now:%Y-%m-%d %H:%M:%S}\n"
        f"Files OK: {stats_ok}  |  Failed: {stats_fail}  |  Success Rate: {rate:.1f}%\n"
        f"Last Upload: {last} ago\n"
        f"Average Size: {avg/1024:.2f} KB\n"
        f"Total Uploaded: {stats_total_bytes/1024:.1f} KB\n"
        f"=============================="
    )

def get_day_folder(parent_id, date_str):
    global day_folder_cache, box_client
    key = (parent_id, date_str)
    if key in day_folder_cache:
        return day_folder_cache[key]
    if len(day_folder_cache) > MAX_CACHED_DAY_FOLDERS:
        day_folder_cache.clear()
    parent = box_client.folder(parent_id)
    try:
        for item in parent.get_items(limit=200):
            if item.type == 'folder' and item.name == date_str:
                day_folder_cache[key] = item
                return item
    except BoxAPIException as e:
        warn("Failed listing folder %s: %s", parent_id, e)
    try:
        new_folder = parent.create_subfolder(date_str)
        day_folder_cache[key] = new_folder
        info("Created day folder %s under %s", date_str, parent_id)
        return new_folder
    except BoxAPIException as e:
        if e.status == 409: 
            debug("Folder already exists (race) %s under %s", date_str, parent_id)
            for item in parent.get_items(limit=200):
                if item.type == 'folder' and item.name == date_str:
                    day_folder_cache[key] = item
                    return item
        raise

def is_retryable(exc):
    if isinstance(exc, (BoxAPIException, OSError, SSLError, ConnectionError)):
        if isinstance(exc, BoxAPIException) and 400 <= exc.status < 500 and exc.status not in (408, 429):
            return False  
        return True
    return False

def safe_upload_stream(target_folder, local_path, name):
    attempt = 0
    while True:
        attempt += 1
        try:
            with open(local_path, "rb") as f:
                uploaded = target_folder.upload_stream(f, name)
            if uploaded.size == 0:
                raise RuntimeError("Uploaded size reported 0")
            return uploaded
        except Exception as e:
            retry = attempt < MAX_UPLOAD_RETRIES and is_retryable(e)
            warn("Stream upload attempt %d/%d failed for %s: %s: %s%s", attempt, MAX_UPLOAD_RETRIES, name, type(e).__name__, e, " (retrying)" if retry else "")
            if not retry:
                raise
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 0.25), RETRY_MAX_DELAY)
            time.sleep(delay)

def upload_file(local_path, parent_id):
    name = os.path.basename(local_path)
    attempt = 0
    while True:
        attempt += 1
        try:
            date_str = datetime.now().strftime("%Y-%m-%d")
            target_folder = get_day_folder(parent_id, date_str)
            file_size = os.path.getsize(local_path)
            if file_size == 0:
                raise ValueError("File is empty")
            uploaded = safe_upload_stream(target_folder, local_path, name)
            return uploaded.size
        except Exception as e:
            retry = attempt < MAX_UPLOAD_RETRIES and is_retryable(e)
            warn("Upload attempt %d/%d failed for %s: %s: %s%s", attempt, MAX_UPLOAD_RETRIES, name, type(e).__name__, e, " (will retry)" if retry else "")
            if not retry:
                raise
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)) + random.uniform(0, 0.25), RETRY_MAX_DELAY)
            time.sleep(delay)

def wait_file_stable(path):
    start = time.time()
    last_size = -1
    stable_since = None
    while time.time() - start < FILE_READY_TIMEOUT_SEC:
        if not os.path.exists(path):
            return False
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size == last_size and size > 0:
            if stable_since is None:
                stable_since = time.time()
            if time.time() - stable_since >= FILE_STABLE_WINDOW_SEC:
                return True
        else:
            stable_since = None
        last_size = size
        time.sleep(FILE_CHECK_INTERVAL_SEC)
    return False

def handle_created(event):
    if event.is_directory:
        return
    local_path = event.src_path
    directory = os.path.dirname(local_path)
    parent_id = FOLDER_MAP.get(directory)
    if not parent_id:
        print(f"[Skip] Unmapped dir: {directory}")
        return
    info("New file %s", local_path)
    if not wait_file_stable(local_path):
        error("Not stable or timeout: %s", local_path)
        record_stat(0, False)
        return
    try:
        size = upload_file(local_path, parent_id)
        os.remove(local_path)
        info("Uploaded %s (%d bytes) -> %s", os.path.basename(local_path), size, parent_id)
        record_stat(size, True)
    except Exception as e:
        error("Upload failed %s: %s: %s", local_path, type(e).__name__, e)
        record_stat(0, False)

def status_loop(stop_evt):
    while not stop_evt.wait(STATUS_INTERVAL_SEC):
        info("\n%s", status_report())

def main():
    info("=== IAES WatchTower v%s ===", VERSION)
    try:
        init_box_client()
    except Exception:
        critical("Initialization failed. Exiting.")
        sys.exit(2)

    for p in list(FOLDER_MAP.keys()):
        try:
            if not os.path.isdir(p):
                os.makedirs(p, exist_ok=True)
                warn("Created missing watch directory: %s", p)
        except Exception as e:
            error("Failed ensuring directory %s: %s", p, e)
            del FOLDER_MAP[p]

    observer = Observer()
    for path in FOLDER_MAP.keys():
        event_handler = FileSystemEventHandler()
        event_handler.on_created = handle_created
        observer.schedule(event_handler, path, recursive=False)
        info("Watching %s", path)

    stop_evt = Event()
    t = Thread(target=status_loop, args=(stop_evt,), daemon=True)
    t.start()

    observer.start()
    info("Running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        info("Shutdown signal received. Stopping observer...")
    finally:
        stop_evt.set()
        observer.stop()
        observer.join()
        info("Final status:\n%s", status_report())

if __name__ == "__main__":
    # Start a small HTTP health endpoint to integrate with the health monitor.
    try:
        from health_endpoint import start_http_status, start_tcp_listener
    except Exception:
        from .health_endpoint import start_http_status, start_tcp_listener

    # Defaults: HTTP on 8085, path /status (matches health-monitor.js)
    hp = int(os.environ.get('HEALTH_PORT', '8085'))
    ht = os.environ.get('HEALTH_TYPE', 'http')
    hpath = os.environ.get('HEALTH_PATH', '/status')
    if ht.lower() == 'http':
        start_http_status(hp, path=hpath, name='box-monitor')
    else:
        start_tcp_listener(hp, name='box-monitor')

    main()
