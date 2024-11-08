from http.server import BaseHTTPRequestHandler

class HTTP01Handler(BaseHTTPRequestHandler):
    challenges = {}

    @classmethod
    def set_challenge(cls, token, key):
        challenges[token] = key

    def do_GET(self):
        path = self.path.split("/")[-1]  
        if path in self.challenges:
            self.send_response(200)
            self.send_header("Content-type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(self.challenges[token].encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


