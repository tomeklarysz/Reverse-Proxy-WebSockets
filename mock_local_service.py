import http.server
import socketserver
import datetime
from html import escape

PORT = 3000

class SimpleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""
        <!doctype html>
        <html lang="en">
        <head><meta charset="utf-8"><title>Local service</title></head>
        <body>
            <h1>Local service is working</h1>
            <p>Port: {PORT}</p>
            <p>Path: {escape(self.path)}</p>
            <p>Time: {now}</p>
        </body>
        </html>
        """
        self.wfile.write(html.encode("utf-8"))

def run():
    with socketserver.TCPServer(("127.0.0.1", PORT), SimpleHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()

if __name__ == "__main__":
    run()
