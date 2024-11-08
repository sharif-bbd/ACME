from http.server import BaseHTTPRequestHandler
import os

class ShutdownHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/shutdown":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Shutting down")
            os._exit(0)
        else:
            self.send_response(404)
            self.end_headers()