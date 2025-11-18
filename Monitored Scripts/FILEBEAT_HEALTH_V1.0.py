"""
Small HTTP health-sidecar for Filebeat host.

Run this on the host that runs the Filebeat Docker container. It exposes
an HTTP GET /status endpoint that returns JSON {status: 'up'|'down', name, timestamp}
and reports 'up' when a container matching the configured name or image is running.

Configuration via environment variables:
- FILEBEAT_CONTAINER_NAME (default: 'filebeat')
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

CONTAINER_NAME = os.environ.get('FILEBEAT_CONTAINER_NAME', 'filebeat')
BIND = os.environ.get('HEALTH_BIND', '0.0.0.0')
PORT = int(os.environ.get('HEALTH_PORT', '8089'))
PATH = os.environ.get('HEALTH_PATH', '/status')
CHECK_TIMEOUT = float(os.environ.get('HEALTH_CHECK_TIMEOUT', '2.0'))


def container_running(name):
    """Return True if `docker ps` shows a running container matching name (by name or ancestor)."""
    try:
        # First try by container name
        res = subprocess.run(['docker', 'ps', '--filter', f'name={name}', '--format', '{{.Names}}'],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=CHECK_TIMEOUT, text=True)
        out = (res.stdout or '').strip()
        if out:
            return True

        # Fallback: check by ancestor image
        res2 = subprocess.run(['docker', 'ps', '--filter', f'ancestor={name}', '--format', '{{.Names}}'],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=CHECK_TIMEOUT, text=True)
        out2 = (res2.stdout or '').strip()
        return bool(out2)
    except Exception:
        return False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != PATH:
            self.send_response(404)
            self.end_headers()
            return

        up = container_running(CONTAINER_NAME)
        payload = {
            'status': 'up' if up else 'down',
            'name': CONTAINER_NAME,
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
    print(f"filebeat health endpoint listening on {BIND}:{PORT}{PATH} (monitoring container '{CONTAINER_NAME}')")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
