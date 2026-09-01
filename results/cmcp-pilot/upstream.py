import json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n=int(self.headers.get("Content-Length",0)); msg=json.loads(self.rfile.read(n) or "{}")
        body=json.dumps({"jsonrpc":"2.0","id":msg.get("id"),
                         "result":{"content":[{"type":"text","text":"EXECUTED"}]}}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
HTTPServer(("127.0.0.1",9001),H).serve_forever()
