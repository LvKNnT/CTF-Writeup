#!/usr/bin/env sage

import os
import string
from hashlib import md5
from random import SystemRandom
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, getPrime


def main():
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()

    rng = SystemRandom()

    m = 24
    n = 120
    k = 45
    p = getPrime(256)
    mod = p ^ 4

    while True:
        a = rng.randrange(mod)
        Px = bytes_to_long("".join(rng.choice(string.hexdigits.lower()) for _ in range(k)).encode())
        Py = rng.randrange(mod)
        b = (Py ^ 2 - Px ^ 3 - a * Px) % mod
        E = EllipticCurve(Zmod(mod), [a, b])
        if gcd(ZZ(E.discriminant()), p) == 1:
            break

    P = E(Px, Py)
    Q = [rng.randrange(p ^ 3) * P for _ in range(m)]

    c = [os.urandom(m) for _ in range(n)]
    R = [sum([x * y for x, y in zip(ci, Q)]) for ci in c]

    key = md5(str(sum(Q)).encode()).digest()
    aes = AES.new(key=key, mode=AES.MODE_ECB)
    ct = aes.encrypt(pad(flag, 16))

    # os.makedirs("release", exist_ok=True)
    with open("output.txt", "w", encoding="utf-8") as f:
        f.write(str(Px % p) + "\n")
        f.write(str([(int(Ri[0]), int(Ri[1])) for Ri in R]) + "\n")
        f.write(ct.hex() + "\n")


if __name__ == "__main__":
    main()
