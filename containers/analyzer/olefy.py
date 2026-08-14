from http.server import BaseHTTPRequestHandler, HTTPServer
import subprocess
class Handler(BaseHTTPRequestHandler):
 def do_POST(self):
  n=int(self.headers.get('Content-Length','0'))
  if n < 0 or n > 52428800: self.send_error(413); return
  data=self.rfile.read(n)
  p=subprocess.run(['olevba','-'],input=data,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30)
  self.send_response(200); self.send_header('Content-Type','text/plain'); self.end_headers(); self.wfile.write(p.stdout[:65536])
 def log_message(self,*args): pass
HTTPServer(('0.0.0.0',10050),Handler).serve_forever()
