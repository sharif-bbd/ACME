from http.server import BaseHTTPRequestHandler

class CertificatHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        