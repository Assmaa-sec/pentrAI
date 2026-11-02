"""Exercise the packaged ZAP scanner against a fixed localhost page."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import threading


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = b"<!doctype html><title>ZAP fixture</title><p>Local test page</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 8766), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = subprocess.run(
            ["zaproxy", "-cmd", "-quickurl", "http://127.0.0.1:8766/"],
            capture_output=True, text=True, timeout=120,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0 or "No space left on device" in output:
            raise RuntimeError(f"ZAP scan failed ({result.returncode}): {output[-4000:]}")
        print("ZAP localhost scan completed")
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
