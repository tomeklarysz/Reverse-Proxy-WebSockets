import argparse
import http.server
import mimetypes
import os
import socketserver

PHOTOS_DIR = os.path.join(os.path.dirname(__file__), "photos")

def get_html():
    files = sorted([f for f in os.listdir(PHOTOS_DIR) if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))])
    items = []
    for f in files:
        size_kb = os.path.getsize(os.path.join(PHOTOS_DIR, f)) / 1024
        label = f.replace("_", " ").replace(".jpg", "").replace(".png", "").capitalize()
        items.append(f"""
        <figure class="item">
            <img src="/photos/{f}" alt="{label}" loading="lazy">
            <figcaption>
                <span class="title">{label}</span>
                <span class="meta">{size_kb:.1f} KB</span>
            </figcaption>
        </figure>
        """)

    return f"""<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Fotografia | Serwis Lokalny</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #ffffff;
            color: #111111;
            padding: 48px 32px;
            max-width: 1040px;
            margin: 0 auto;
        }}
        header {{
            margin-bottom: 40px;
            border-bottom: 1px solid #eaeaea;
            padding-bottom: 20px;
        }}
        h1 {{
            font-size: 22px;
            font-weight: 600;
            letter-spacing: -0.02em;
        }}
        p.desc {{
            color: #666666;
            font-size: 14px;
            margin-top: 4px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 28px;
        }}
        .item {{
            margin: 0;
            display: flex;
            flex-direction: column;
        }}
        .item img {{
            width: 100%;
            aspect-ratio: 4 / 3;
            object-fit: cover;
            border-radius: 4px;
            background: #f0f0f0;
            display: block;
        }}
        figcaption {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-top: 10px;
            font-size: 13px;
        }}
        .title {{
            font-weight: 500;
            color: #222222;
        }}
        .meta {{
            color: #888888;
            font-variant-numeric: tabular-nums;
        }}
    </style>
</head>
<body>
    <header>
        <h1>Lokalne Archiwum Fotografii</h1>
        <p class="desc">Zasób lokalny serwowany przez tunel zwrotny</p>
    </header>
    <main class="grid">
        {"".join(items)}
    </main>
</body>
</html>
"""

class GalleryHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            content = get_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif self.path.startswith("/photos/"):
            filename = os.path.basename(self.path)
            filepath = os.path.join(PHOTOS_DIR, filename)
            if os.path.isfile(filepath):
                mime, _ = mimetypes.guess_type(filepath)
                content_type = mime or "application/octet-stream"
                size = os.path.getsize(filepath)
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(size))
                self.end_headers()
                with open(filepath, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def run():
    parser = argparse.ArgumentParser(description="Local Photo Gallery Service")
    parser.add_argument("--port", type=int, default=3000, help="Port to listen on")
    args = parser.parse_args()

    with socketserver.TCPServer(("127.0.0.1", args.port), GalleryHandler) as httpd:
        print(f"[*] Gallery service listening on http://127.0.0.1:{args.port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    run()
