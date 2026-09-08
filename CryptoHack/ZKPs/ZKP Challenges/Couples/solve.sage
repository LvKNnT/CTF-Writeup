#!/usr/bin/env sage

import json
import socket
import sys


HOST = "socket.cryptohack.org"
PORT = 13415

p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
G1 = (1, 2, 1)


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


def recv_json(io):
    line = io.recvline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.decode())


def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())


def point_to_server(point):
    return "({}, {}, {})".format(*point)


def solve(host=HOST, port=PORT):
    io = JsonLineSocket(host, port)
    io.recvuntil(b"Welcome! Have fun with this strange implementation...\n")

    # power = p - 5 gives x^(power + 7) - x^3 = x^(p + 2) - x^3 = 0
    # for nonzero x by Fermat. The buggy inverse(0, p) returns 0, so x*z = 0.
    send_json(io, {"option": "set_internal_z", "z": hex(p - 5)})
    response = recv_json(io)
    if "error" in response:
        raise RuntimeError(response["error"])

    send_json(io, {
        "option": "do_proof",
        "G": point_to_server(G1),
        "hsh": "0x1",
    })

    result = recv_json(io)
    io.close()
    print(result.get("msg", result))


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    solve(host, port)
