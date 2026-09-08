from sage.all import *
from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes, isPrime
import hashlib
import json
import random
import string
import sys


HOST = "socket.cryptohack.org"
PORT = 13430
BITS = 2 << 9
G = 2


def recv_json(io):
    return json.loads(io.recvline().decode())


def send_json(io, obj):
    io.sendline(json.dumps(obj).encode())


def challenge_hash(t, y, g=G):
    h_input = int(t).__xor__(int(y)).__xor__(int(g))
    h = hashlib.sha3_256(long_to_bytes(h_input)).digest()
    return bytes_to_long(h) ** 2


def get_prime(rng, bits):
    while True:
        p = rng.getrandbits(bits) | 1
        if isPrime(p, randfunc=lambda n: long_to_bytes(rng.getrandbits(n))):
            return p


def xor(a, b):
    return bytes(int(x).__xor__(int(y)) for x, y in zip(a, b))


def undo_xor_nonce(s, nonce):
    return s[:7] + xor(s[7:-1], nonce) + s[-1:]


def clean_flag(with_junk):
    printable = set(bytes(string.printable, "ascii"))
    candidates = []

    for i, b in enumerate(with_junk):
        if b not in printable:
            candidate = with_junk[:i] + with_junk[i + 1 :]
            if candidate.startswith(b"crypto{") and candidate.endswith(b"}"):
                candidates.append(candidate)

    if not candidates:
        # Fallback: try deleting every position, useful if the injected byte became
        # printable after a local modification of the challenge.
        for i in range(len(with_junk)):
            candidate = with_junk[:i] + with_junk[i + 1 :]
            if candidate.startswith(b"crypto{") and candidate.endswith(b"}"):
                candidates.append(candidate)

    if len(candidates) != 1:
        raise ValueError("could not uniquely remove the inserted junk byte")
    return candidates[0]


def recover_flag_int(p, proof):
    t = int(proof["t"])
    r = int(proof["r"])
    y = int(proof["y"])
    g = int(proof["g"])
    assert g == G

    c = challenge_hash(t, y, g)
    m = p - 1

    # r = v - c*x mod (p - 1), with x = hidden flag integer and 0 <= v < 2^512.
    # Since x is 39 bytes and c is about 512 bits, c*x < p - 1 with overwhelming
    # probability, so c*x + r = p - 1 + v. The unknown v only widens the interval
    # by about one candidate.
    lo = max(0, ceil(ZZ(m - r) / ZZ(c)))
    hi = floor(ZZ(m - r + (1 << (BITS >> 1)) - 1) / ZZ(c))

    for x in range(int(lo), int(hi) + 1):
        if power_mod(g, x, p) == y:
            return x

    raise ValueError(f"no flag candidate found in interval [{lo}, {hi}]")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    io = remote(host, port)
    io.recvline()  # This server is made to share proofs...
    nonce_line = io.recvline().decode().strip()
    nonce = bytes.fromhex(nonce_line.rsplit(":", 1)[1].strip())
    print(f"[+] nonce = {nonce.hex()}")

    # One server proof is needed before the protocol lets us refresh with our seed.
    send_json(io, {"option": "get_proof"})
    recv_json(io)

    seed = b"letsprove"
    send_json(io, {"option": "refresh", "seed": seed.hex()})
    refresh_response = recv_json(io)
    if "error" in refresh_response:
        raise RuntimeError(refresh_response["error"])

    rng = random.Random(nonce + seed)
    p = get_prime(rng, BITS)

    send_json(io, {"option": "get_proof"})
    proof = recv_json(io)
    io.close()

    hidden = recover_flag_int(p, proof)
    padded = long_to_bytes(hidden)
    padded = padded.rjust(39, b"\x00")
    flag_with_junk = undo_xor_nonce(padded, nonce)
    flag = clean_flag(flag_with_junk)

    print(flag.decode())


if __name__ == "__main__":
    main()
