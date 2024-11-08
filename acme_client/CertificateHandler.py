from http.server import BaseHTTPRequestHandler

class CertificateHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        return