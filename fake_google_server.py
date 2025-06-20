from http.server import BaseHTTPRequestHandler, HTTPServer

class SpoofedHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host = self.headers.get('Host')
        print(f"[+] Got request with Host: {host}")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>This is a spoofed Google page!</h1>")

    def log_message(self, format, *args):
        return  # Optional: silence logging

# Run the server on all interfaces (including 50.50.50.50)
server = HTTPServer(('0.0.0.0', 80), SpoofedHandler)
print("[*] Fake server running on 50.50.50.50:80")
server.serve_forever()