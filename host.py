from http.server import HTTPServer, SimpleHTTPRequestHandler
from ssl import SSLContext, PROTOCOL_TLS_SERVER
from urllib.parse import urlparse


class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if urlparse(self.path).path != '/log':
            self.send_error(404)
            return

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'replace') if length else ''
        for line in body.splitlines():
            if line:
                print(f'[exploit] {line}', flush=True)

        self.send_response(204)
        self.end_headers()


context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain('localhost.pem')
httpd = HTTPServer(('0.0.0.0', 443), Handler)
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
print('running server !!', flush=True)
httpd.serve_forever()
