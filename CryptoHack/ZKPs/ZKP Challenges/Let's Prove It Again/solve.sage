from sage.all import *

import hashlib
import json
import random
import socket
import string
import sys

from Crypto.Util.number import isPrime, long_to_bytes


HOST = "socket.cryptohack.org"
PORT = 13431
BITS = 2 << 9
G = 2
KNOWN_SEEDS = [b"again-one", b"again-two"]


class Remote:
    def __init__(self, host, port):
        self.sock = socket.create_connection((str(host), int(port)))
        self.file = self.sock.makefile("rwb", buffering=0)

    def recvline(self):
        line = self.file.readline()
        if not line:
            raise EOFError("remote closed the connection")
        return line

    def sendline(self, data):
        self.file.write(data + b"\n")

    def close(self):
        self.file.close()
        self.sock.close()


def recv_json(io):
    return json.loads(io.recvline().decode())


def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())


def bytes_to_int(data):
    return int.from_bytes(data, "big")


def int_to_bytes(n, length=None):
    data = int(n).to_bytes((int(n).bit_length() + 7) // 8 or 1, "big")
    if length is not None:
        data = data.rjust(length, b"\x00")
    return data


def get_prime(rng, bits):
    while True:
        p = rng.getrandbits(bits) | 1
        if isPrime(p, randfunc=lambda n: long_to_bytes(rng.getrandbits(n))):
            return p


def xor(a, b):
    assert len(a) == len(b)
    return bytes(x ^^ y for x, y in zip(a, b))


def undo_xor_nonce(masked, nonce):
    return masked[:7] + xor(masked[7:-1], nonce) + masked[-1:]


def clean_flag(flag_with_junk):
    printable = set(bytes(string.printable, "ascii"))
    candidates = []

    for i, b in enumerate(flag_with_junk):
        if b not in printable:
            candidate = flag_with_junk[:i] + flag_with_junk[i + 1 :]
            if candidate.startswith(b"crypto{") and candidate.endswith(b"}"):
                candidates.append(candidate)

    if not candidates:
        for i in range(len(flag_with_junk)):
            candidate = flag_with_junk[:i] + flag_with_junk[i + 1 :]
            if candidate.startswith(b"crypto{") and candidate.endswith(b"}"):
                candidates.append(candidate)

    if len(candidates) != 1:
        raise ValueError(f"could not uniquely remove junk byte: {flag_with_junk!r}")
    return candidates[0]


def challenge_hash(t, y, salt, g=G):
    h_input = int_to_bytes(int(t) ^^ int(y) ^^ int(g) ^^ int(salt))
    return bytes_to_int(hashlib.sha3_256(h_input).digest())


def parse_proof(proof):
    t = int(proof["t"])
    r = int(proof["r"])
    y = int(proof["y"])
    g = int(proof["g"])
    assert g == G
    return t, r, y, g


def possible_linear_terms(p, r):
    a = ZZ(p - 1 - r)

    # r = v - c*x (mod p - 1).  Since c*x and v are much smaller than p, the
    # lifted integer c*x - v is either p - 1 - r or p - 1 - r - (p - 1).
    return [a, a - ZZ(p - 1)]


def recover_flag_int(records):
    (p1, proof1), (p2, proof2) = records
    t1, r1, y1, g1 = parse_proof(proof1)
    t2, r2, y2, g2 = parse_proof(proof2)

    terms1 = possible_linear_terms(p1, r1)
    terms2 = possible_linear_terms(p2, r2)
    hashes1 = [(salt, ZZ(challenge_hash(t1, y1, salt, g1))) for salt in range(2, BITS + 1)]
    hashes2 = [(salt, ZZ(challenge_hash(t2, y2, salt, g2))) for salt in range(2, BITS + 1)]

    for b1 in terms1:
        for b2 in terms2:
            delta_b = ZZ(b1 - b2)
            for salt1, c1 in hashes1:
                for salt2, c2 in hashes2:
                    delta_c = ZZ(c1 - c2)
                    if delta_c == 0 or delta_b % delta_c != 0:
                        continue

                    x = ZZ(delta_b // delta_c)
                    if x <= 0 or x.nbits() > 8 * 39:
                        continue

                    if power_mod(g1, x, p1) == y1 and power_mod(g2, x, p2) == y2:
                        return int(x), (salt1, salt2)

    raise ValueError("failed to recover flag integer from the proof pair")


def get_known_prime_proof(io, nonce, seed):
    send_json(io, {"option": "refresh", "seed": seed.hex()})
    response = recv_json(io)
    if "error" in response:
        raise RuntimeError(response["error"])

    rng = random.Random(nonce + seed)
    p = get_prime(rng, BITS)

    send_json(io, {"option": "get_proof"})
    proof = recv_json(io)
    if "error" in proof:
        raise RuntimeError(proof["error"])

    return p, proof


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    io = Remote(host, port)
    try:
        io.recvline()
        nonce_line = io.recvline().decode().strip()
        nonce = bytes.fromhex(nonce_line.rsplit(":", 1)[1].strip())
        print(f"[+] nonce = {nonce.hex()}")

        # The service only lets us choose a seed after the server has spoken once.
        send_json(io, {"option": "get_proof"})
        first = recv_json(io)
        if "error" in first:
            raise RuntimeError(first["error"])

        records = [get_known_prime_proof(io, nonce, KNOWN_SEEDS[0])]

        # After one chosen-seed proof it is the server's turn again.  This proof
        # uses an unknown PRNG state, but it lets us choose one more seed.
        send_json(io, {"option": "get_proof"})
        filler = recv_json(io)
        if "error" in filler:
            raise RuntimeError(filler["error"])

        records.append(get_known_prime_proof(io, nonce, KNOWN_SEEDS[1]))

        hidden, salts = recover_flag_int(records)
        print(f"[+] recovered hash salts = {salts[0]}, {salts[1]}")

        masked = int_to_bytes(hidden, 39)
        flag_with_junk = undo_xor_nonce(masked, nonce)
        flag = clean_flag(flag_with_junk)
        print(flag.decode())
    finally:
        io.close()


if __name__ == "__main__":
    main()
