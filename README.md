# GCTFtoflag

One-shot flag extraction for **GCTF Servers**.

> **The PoC has been taken down.** After a long chat with my lecturer about "responsible
> disclosure" I've removed it from this repo. The writeup stays.

## How it works

GCTF Servers ship with a debug handshake that hands the flag to any client that knows the
build key:

1. `GET /gctf/hello` gives you a nonce.
2. `POST /gctf/toflag` with `{"nonce": ..., "proof": HMAC-SHA256(key, nonce)}`.
3. Flag.

The key is the same on every build. That's the bug.

## Finding targets

You don't need to scan for GCTF Servers yourself. Someone already has, and they never
forget a banner. One query and you have every target on the internet.

(Query removed, obviously.)
