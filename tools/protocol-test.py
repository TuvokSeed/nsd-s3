#!/usr/bin/env python3
"""Exercise the nostr-signer-s3 serial protocol from the host.

Usage:  python3 tools/protocol-test.py [/dev/ttyACM0]

Read-only commands run automatically; the sign tests wait for a button
press on the device (top = approve, bottom = reject).
Needs pyserial:  pip install pyserial
"""
import json
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial missing:  pip install pyserial")

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"


def main():
    s = serial.Serial(PORT, 115200, timeout=2)
    time.sleep(0.5)
    s.reset_input_buffer()

    def cmd(line, wait=5):
        print(f">>> {line[:100]}{'...' if len(line) > 100 else ''}")
        s.write((line + "\n").encode())
        deadline = time.time() + wait
        while time.time() < deadline:
            resp = s.readline().decode(errors="replace").strip()
            if resp:
                print(f"<<< {resp[:160]}")
                return resp
        print("<<< (no reply)")
        return ""

    cmd("/ping", wait=1)                      # no reply expected (buffer flush)
    cmd("/ping protocol-test.local")          # -> /ping 0 nsd-s3-...
    cmd("/version")
    pub = cmd("/public-key").split(" ", 1)[1]
    cmd("/npub")

    assert len(pub) == 64, f"bad pubkey: {pub}"

    # NIP-04 shared secret against a fixed test key
    # (sec 0000...0002 -> pub x||y below); expected x-only ECDH can be
    # cross-checked with nostr-tools if needed
    # v0.0.9+: gated behind a physical ALLOW/DENY on a "SHARE SECRET?"
    # screen, same as signing -- no longer an instant reply.
    peer_xy = (
        "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
        "1ae168fee52a219163e650a729656c88bd52c7bebd0c9f6f9beb1d1a3f5e1c8a"
    )
    print("\n--- /shared-secret: press TOP (ALLOW) or BOTTOM (DENY) ---")
    cmd("/shared-secret " + peer_xy, wait=65)

    # digest signing (NSD-compat path) — press a button on the device
    print("\n--- /sign-message: press TOP (approve) or BOTTOM (reject) ---")
    cmd("/sign-message " + "11" * 32, wait=65)

    # event signing (extended path) — device computes the id itself
    print("\n--- /sign-event: check kind + preview on screen, then press a button ---")
    event = {
        "pubkey": pub,
        "created_at": int(time.time()),
        "kind": 1,
        "tags": [["t", "test"]],
        "content": "hello from protocol-test.py ⚡",
    }
    resp = cmd("/sign-event " + json.dumps(event), wait=65)
    if resp.startswith("/sign-event ") and len(resp.split()) == 3:
        _, ev_id, sig = resp.split()
        print(f"\ndevice id:  {ev_id}\nsignature:  {sig}")
        try:
            import hashlib
            ser = json.dumps(
                [0, pub, event["created_at"], 1, event["tags"], event["content"]],
                separators=(",", ":"), ensure_ascii=False,
            ).encode()
            expect = hashlib.sha256(ser).hexdigest()
            print("id check:  ", "OK" if expect == ev_id else f"MISMATCH (host: {expect})")
        except Exception as e:
            print("id check skipped:", e)

    print("\ndone")


if __name__ == "__main__":
    main()
