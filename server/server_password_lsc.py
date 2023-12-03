import http.server
import socketserver
import socket
import ssl
from os import path

my_port = 8443

routes = {
  "/main.shtm" : "main.shtm",
  }

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):

  def do_HEAD(self):
    return
    
  def do_GET(self):
    self.respond()
    
  def do_POST(self):
    self.send_response(200)
    length_datagram = int(self.headers.get('Content-Length'))
    self.send_header('Content-typ', 'text/html')
    self.end_headers()
    feedback = self.rfile.read(length_datagram)
    print(feedback)
    # if feedback is UAMCHAL (first step)
    if feedback[3] == 67:
      print('>>> Send 700,0,0 to User')
      self.wfile.write(bytes("700,0,0", "UTF-8"))
    # record response
    if feedback[3] == 76:
      f = open('pwcrc.txt','w')
      f.writelines(feedback.decode("utf-8"))
      f.close()
    return 
    
  def handle_http(self, status, content_type):
    self.send_response(status)
    self.send_header('Content-typ', content_type)
    self.end_headers()
    response_content = open(routes[self.path])
    response_content = response_content.read()
    return bytes(response_content, "UTF-8")

  def respond(self):
    content = self.handle_http(200, 'text/html')
    self.wfile.write(content)

my_handler = MyHttpRequestHandler

with socketserver.TCPServer(("", my_port), my_handler) as httpd:
    httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile="prkey.pem", 
        certfile="mycert.crt", server_side=True)
    print("Http Server Serving at port", my_port)
    httpd.serve_forever()
