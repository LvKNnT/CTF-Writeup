#!/usr/bin/env sage

from hashlib import sha256
import ast
import json
import socket
import sys


HOST = "socket.cryptohack.org"
PORT = 13414


class JsonLineSocket:
    def __init__(self, host, port):
        self.sock = socket.create_connection((str(host), int(port)))
        self.file = self.sock.makefile("rwb", buffering=0)

    def recvline(self):
        return self.file.readline()

    def recvuntil(self, marker):
        data = b""
        while marker not in data:
            chunk = self.file.read(1)
            if not chunk:
                raise EOFError("connection closed before marker")
            data += chunk
        return data

    def sendline(self, data):
        self.file.write(data + b"\n")

    def close(self):
        self.file.close()
        self.sock.close()


def hash256(data):
    return sha256(data).digest()


def merge_nodes(a, b):
    return hash256(a + b)


def recv_json(io):
    line = io.recvline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.decode())


def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())


def rebuild_root(leaves):
    layer = leaves
    while len(layer) > 1:
        layer = [merge_nodes(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def parse_nodes(response):
    if "error" in response:
        raise RuntimeError(response["error"])

    # The server returns Python's str(list), not JSON.
    raw_layers = ast.literal_eval(response["msg"])
    leaves_hex = raw_layers[0]
    if len(leaves_hex) != 8:
        raise RuntimeError("expected 8 leaf hashes, got %d" % len(leaves_hex))
    return [bytes.fromhex(h) for h in leaves_hex]


def solve(host=HOST, port=PORT):
    io = JsonLineSocket(host, port)
    io.recvuntil(b"Welcome to the saplins previews system implementation!\n")

    # TOCTOU bug: balance_check() starts request_checker() in a thread and
    # returns before it finishes. A huge count keeps the checker busy, while
    # self.nodes[0][:count] still only returns the 8 existing leaves.
    send_json(io, {"option": "get_nodes", "nodes": "0,10000000"})
    leaves = parse_nodes(recv_json(io))

    root = rebuild_root(leaves)
    send_json(io, {"option": "do_proof", "root": root.hex()})

    result = recv_json(io)
    io.close()
    print(result.get("msg", result))


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    solve(host, port)
