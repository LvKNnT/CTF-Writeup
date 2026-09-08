#!/usr/bin/env python

from pathlib import Path
import sys

from py_ecc.optimized_bn128 import FQ, FQ2, FQ12, pairing


def to_g1(point):
    return tuple(FQ(c) for c in point)


def to_g2(point):
    return tuple(FQ2(c) for c in point)


def to_gt(value):
    return FQ12(value)


def is_true_challenge(challenge):
    xG, yG, zG = challenge
    return pairing(to_g2(yG), to_g1(xG)) == to_gt(zG)


base = Path(sys.argv[0]).resolve().parent
output_path = base / "output_2d8920fd1c945fde7ff1ad5fc0810aa7.txt"

bits = []
for line in output_path.read_text().splitlines():
    if line.strip():
        bits.append("1" if is_true_challenge(eval(line)) else "0")

bitstring = "".join(bits)
flag_int = int(bitstring, 2)
flag = flag_int.to_bytes((flag_int.bit_length() + 7) // 8, "big")

print(flag.decode())
