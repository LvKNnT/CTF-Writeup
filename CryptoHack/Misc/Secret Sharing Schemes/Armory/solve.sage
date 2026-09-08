#!/usr/bin/env sage

import ast
import hashlib

PRIME = 77793805322526801978326005188088213205424384389488111175220421173086192558047
SHARE_FILE = "share_f6dca6a2f215b12ddebb68a90380542d.txt"


def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % prime
    return accum


with open(SHARE_FILE, "r") as f:
    x, y = ast.literal_eval(f.read().strip())

# In make_deterministic_shares(), the first share has x = coeff[1],
# where coeff[1] = sha256(secret).digest() interpreted as a big-endian int.
c1 = x
c2 = int.from_bytes(hashlib.sha256(c1.to_bytes(32, "big")).digest(), "big")

# For the first share:
#   y = secret + c1*x + c2*x^2 mod PRIME
# and x == c1, so recover the constant term directly.
secret = (y - c1 * x - c2 * x**2) % PRIME
flag = int_to_bytes(secret)

print(flag.decode())

# Sanity checks: the recovered secret hashes to the given x-coordinate and
# regenerates the provided point.
assert int.from_bytes(hashlib.sha256(flag).digest(), "big") == x
assert eval_at([secret, c1, c2], x, PRIME) == y
