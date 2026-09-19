from PIL import Image
from collections import Counter, defaultdict
import hashlib
import zlib

FILE = "moire.png"

PREVIOUS_FLAG = (
    "Null0rigin{two_cells_of_equal_weight_are_not_equal}"
)

# ---------------------------------------------------------
# Load image
# ---------------------------------------------------------

img = Image.open(FILE).convert("1")

W, H = img.size

assert W % 4 == 0
assert H % 4 == 0

CW = W // 4
CH = H // 4


def get_cell(cx, cy):
    bits = []

    for y in range(cy * 4, cy * 4 + 4):
        for x in range(cx * 4, cx * 4 + 4):
            # Pillow mode "1":
            #   0   = black
            #   255 = white
            bits.append(1 if img.getpixel((x, y)) == 0 else 0)

    return bits


def pattern_value(bits):
    v = 0

    for bit in bits:
        v = (v << 1) | bit

    return v


# ---------------------------------------------------------
# Determine all patterns for each weight
# ---------------------------------------------------------

patterns = defaultdict(Counter)
cells = {}

for cy in range(CH):
    for cx in range(CW):

        bits = get_cell(cx, cy)

        weight = sum(bits)
        pattern = pattern_value(bits)

        patterns[weight][pattern] += 1
        cells[(cx, cy)] = (weight, pattern)


print("[+] pattern counts")

for weight in sorted(patterns):
    print(
        weight,
        "cells =", sum(patterns[weight].values()),
        "patterns =", len(patterns[weight])
    )


# Only weights having exactly two settings can encode bits
usable_weights = sorted(
    weight
    for weight in patterns
    if len(patterns[weight]) == 2
)

print("[+] usable:", usable_weights)

# Expected:
#
# [5, 6, 7, 8, 9, 10, 11]


# Give the two patterns an arbitrary initial ordering.
#
# We'll brute-force which orientation corresponds to bit 0/1.
pairs = {
    weight: sorted(patterns[weight])
    for weight in usable_weights
}


# ---------------------------------------------------------
# Read cells boustrophedon / ox-plough order
#
# row 0:  ---->
# row 1:  <----
# row 2:  ---->
# ...
# ---------------------------------------------------------

symbols = []

for cy in range(CH):

    if cy % 2 == 0:
        xs = range(CW)
    else:
        xs = range(CW - 1, -1, -1)

    for cx in xs:

        weight, pattern = cells[(cx, cy)]

        if weight not in pairs:
            continue

        a, b = pairs[weight]

        if pattern == a:
            setting = 0
        elif pattern == b:
            setting = 1
        else:
            raise RuntimeError("unexpected cell pattern")

        symbols.append((weight, setting))


print("[+] encoded cells:", len(symbols))


# ---------------------------------------------------------
# Key schedule
# ---------------------------------------------------------

k = hashlib.sha256(
    PREVIOUS_FLAG.encode()
).digest()

print("[+] k =", k.hex())


def keystream(length):

    result = bytearray()
    counter = 0

    while len(result) < length:

        block = hashlib.sha256(
            k + counter.to_bytes(4, "big")
        ).digest()

        result.extend(block)

        counter += 1

    return bytes(result[:length])


# ---------------------------------------------------------
# Bits -> bytes, MSB first
# ---------------------------------------------------------

def pack_bits(bits):

    output = bytearray()

    for i in range(0, len(bits) - 7, 8):

        value = 0

        for bit in bits[i:i + 8]:
            value = (value << 1) | bit

        output.append(value)

    return bytes(output)


# ---------------------------------------------------------
# Try the 2^7 interpretations of the two cell settings
# ---------------------------------------------------------

for mask in range(1 << len(usable_weights)):

    bits = []

    for weight, setting in symbols:

        index = usable_weights.index(weight)

        # Decide whether this weight's two patterns
        # need their meanings reversed.
        flip = (mask >> index) & 1

        bit = setting ^ flip

        bits.append(bit)

    ciphertext = pack_bits(bits)

    stream = keystream(len(ciphertext))

    plaintext = bytes(
        a ^ b
        for a, b in zip(ciphertext, stream)
    )

    # -----------------------------------------------------
    # PL8 validation
    # -----------------------------------------------------

    if plaintext[:3] != b"PL8":
        continue

    issue = plaintext[3]

    length = int.from_bytes(
        plaintext[4:6],
        "little"
    )

    expected_crc = int.from_bytes(
        plaintext[6:10],
        "little"
    )

    if 10 + length > len(plaintext):
        continue

    payload = plaintext[10:10 + length]

    actual_crc = zlib.crc32(payload) & 0xffffffff

    if actual_crc != expected_crc:
        continue

    print()
    print("[+] VALID WORKS ENTRY")
    print("mask       =", mask)
    print("issue      =", issue)
    print("length     =", length)
    print("expected   =", hex(expected_crc))
    print("actual     =", hex(actual_crc))
    print("payload    =", payload)

    # Extract flag
    start = payload.find(b"Null0rigin{")

    if start != -1:
        end = payload.find(b"}", start)

        if end != -1:
            flag = payload[start:end + 1]
            print()
            print("[+] FLAG:", flag.decode())