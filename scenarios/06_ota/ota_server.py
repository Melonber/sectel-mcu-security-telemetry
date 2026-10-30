#!/usr/bin/env python3
"""HTTPS file server for OTA images (lab only).

Serves ./images over HTTPS with the broker certificate from ../../pki, whose SAN
contains the Mac IP, so the device can verify it with the embedded project CA.

Usage (from this folder):  python3 ota_server.py [port]   (default 8443)
"""
import functools
import http.server
import ssl
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKI = HERE.parents[1] / "pki"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443

handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                            directory=str(HERE / "images"))
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(PKI / "broker.crt", PKI / "broker.key")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f"Serving {HERE / 'images'} on https://0.0.0.0:{PORT}  (Ctrl+C to stop)")
httpd.serve_forever()
