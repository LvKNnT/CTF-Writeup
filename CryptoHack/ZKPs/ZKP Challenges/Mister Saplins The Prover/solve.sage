#!/usr/bin/env sage
from hashlib import sha256
import builtins
import json
import socket
import sys


HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = builtins.int(sys.argv[2]) if len(sys.argv) > 2 else builtins.int("13432")


def hash256(data):
    return sha256(data).digest()


def merge_nodes(a, b):
    return hash256(a + b)


def to_jsonable(value):
    if isinstance(value, dict):
        return {to_jsonable(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    try:
        if value in ZZ:
            return builtins.int(value)
    except (NameError, TypeError):
        pass
    return value


class Oracle:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.sock.settimeout(5)
        self.buf = b""

    def close(self):
        self.sock.close()

    def _line(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.strip()

    def recv_json(self):
        while True:
            line = self._line()
            if not line:
                continue
            try:
                return json.loads(line.decode())
            except ValueError:
                # The service prints a non-JSON welcome banner first.
                continue

    def query(self, payload):
        self.sock.sendall(json.dumps(to_jsonable(payload)).encode() + b"\n")
        return self.recv_json()


def get_preview(node):
    conn = Oracle(HOST, PORT)
    try:
        res = conn.query({"option": "get_node", "node": node})
        if "msg" not in res:
            raise RuntimeError("get_node(%s) failed: %r" % (node, res))
        return bytes.fromhex(res["msg"])
    finally:
        conn.close()


def main():
    # Leaves 3..7 are entirely flag bytes, so their hashes are stable across
    # fresh connections. Leaves 0..1 and one byte of leaf 2 contain per-session
    # randomness.
    h3, h4, h5, h6, h7 = [get_preview(i) for i in builtins.range(3, 8)]

    l12 = merge_nodes(h4, h5)
    l13 = merge_nodes(h6, h7)
    right_root = merge_nodes(l12, l13)

    conn = Oracle(HOST, PORT)
    try:
        # Negative indexes bypass the preview restriction. On the bottom layer,
        # -1 is the appended copy of nodes[1][0] == H(h0 || h1), exactly the
        # left branch we cannot otherwise learn for this live session.
        res = conn.query({"option": "get_node", "node": -1})
        if "msg" not in res:
            raise RuntimeError("get_node(-1) failed: %r" % (res,))
        l10 = bytes.fromhex(res["msg"])

        for b in builtins.range(256):
            h2 = hash256(bytes([b]) + b"crypto{")
            l11 = merge_nodes(h2, h3)
            left_root = merge_nodes(l10, l11)
            root = merge_nodes(left_root, right_root)

            res = conn.query({"option": "do_proof", "root": root.hex()})
            msg = res.get("msg", "")
            if "crypto{" in msg:
                print(msg)
                return

        raise RuntimeError("all 256 candidates failed")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
