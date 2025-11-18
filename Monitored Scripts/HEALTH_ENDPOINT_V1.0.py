"""
Lightweight health endpoint helpers used by monitored scripts.

Provides:
- start_http_status(port, path, name) -> starts a tiny HTTP server that responds 200/JSON
- start_tcp_listener(port, name) -> starts a TCP acceptor (connect succeeds, handler closes)

Uses only Python stdlib so no extra dependencies.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import socket
import os


class _StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if getattr(self.server, 'status_path', '/') and self.path != self.server.status_path:
            self.send_response(404)
            self.end_headers()
            return
        payload = {
            'status': 'ok',
            'name': getattr(self.server, 'service_name', 'monitored-script'),
            'timestamp': int(__import__('time').time())
        }
        body = json.dumps(payload).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Silence default logging to keep output clean; callers can enable if desired
        return


def start_http_status(port=8085, path='/status', name='monitored-script'):
    """Start a background HTTP server that serves a simple /status JSON payload.

    Returns the threading.Thread instance running the server.
    """
    server = HTTPServer(('0.0.0.0', int(port)), _StatusHandler)
    server.status_path = path or '/'
    server.service_name = name

    def _serve():
        try:
            server.serve_forever()
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True, name=f"health-http-{name}-{port}")
    t.start()
    print(f"[health] HTTP status endpoint started on 0.0.0.0:{port}{path} for '{name}'")
    return t


def start_tcp_listener(port=9001, name='monitored-script'):
    """Start a simple TCP listener that accepts and immediately closes connections.

    The health monitor detects TCP services by successfully connecting to the port.
    Returns the thread instance for the server loop.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', int(port)))
        s.listen(5)
    except Exception as e:
        print(f"[health] Failed to bind TCP health port {port} for {name}: {e}")
        s.close()
        return None

    def _loop():
        try:
            while True:
                try:
                    conn, addr = s.accept()
                    # Immediately close - presence of listener is enough for a TCP health check
                    conn.close()
                except Exception:
                    break
        finally:
            try:
                s.close()
            except Exception:
                pass

    t = threading.Thread(target=_loop, daemon=True, name=f"health-tcp-{name}-{port}")
    t.start()
    print(f"[health] TCP health listener started on 0.0.0.0:{port} for '{name}'")
    return t
