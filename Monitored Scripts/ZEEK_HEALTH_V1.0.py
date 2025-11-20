"""
Small HTTP health-sidecar for Zeek host.

Run this on the host that runs Zeek. It exposes an HTTP GET /status endpoint
that returns JSON {status: 'up'|'down', name, timestamp} and reports 'up' when
a process matching the configured name is present in the output of `ps`.

Configuration via environment variables:
- ZEEK_PROCESS_NAME (default: 'zeek')
- HEALTH_BIND (default: '0.0.0.0')
- HEALTH_PORT (default: 8089)
- HEALTH_PATH (default: '/status')

Author: Jordan Lanham
Date: 2025-11-18
"""
import os
import json
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

BIND = os.environ.get('HEALTH_BIND', '0.0.0.0')
PORT = int(os.environ.get('HEALTH_PORT', '47760'))
PATH = os.environ.get('HEALTH_PATH', '/status')
CHECK_TIMEOUT = float(os.environ.get('HEALTH_CHECK_TIMEOUT', '2.0'))


PROCESS_NAME = os.environ.get('ZEEK_PROCESS_NAME', 'zeek')


def process_running(name):
    """Return True if `ps aux` output contains a process matching `name` (case-insensitive).

    We run `ps aux` and scan the output in Python instead of using a shell pipeline.
    """
    try:
        res = subprocess.run(['ps', 'aux'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=CHECK_TIMEOUT, text=True)
        out = (res.stdout or '').splitlines()
        low = name.lower()
        for line in out:
            if low in line.lower():
                return True
        return False
    except Exception:
        return False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != PATH:
            self.send_response(404)
            self.end_headers()
            return

        up = process_running(PROCESS_NAME)
        payload = {
            'status': 'up' if up else 'down',
            'name': PROCESS_NAME,
            'timestamp': int(time.time())
        }
        body = json.dumps(payload).encode('utf-8')
        self.send_response(200 if up else 503)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def main():
    server = HTTPServer((BIND, PORT), _Handler)
    print(f"zeek health endpoint listening on {BIND}:{PORT}{PATH} (monitoring process '{PROCESS_NAME}')")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
