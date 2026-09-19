import hashlib
import struct
import zlib

PNG = "quietus.png"

PREV_FLAG = (
    b"Null0rigin{he_set_two_sorts_where_one_would_do}"
)

# ============================================================
# Extract IDAT
# ============================================================

png = open(PNG, "rb").read()

assert png[:8] == b"\x89PNG\r\n\x1a\n"

pos = 8
idat = bytearray()

while pos < len(png):
    n = int.from_bytes(png[pos:pos+4], "big")
    typ = png[pos+4:pos+8]
    body = png[pos+8:pos+8+n]

    if typ == b"IDAT":
        idat += body

    pos += 12 + n

    if typ == b"IEND":
        break


# ============================================================
# Bit reader
# ============================================================

class BitReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        v = 0

        for i in range(n):
            b = (
                self.data[self.pos >> 3]
                >> (self.pos & 7)
            ) & 1

            v |= b << i
            self.pos += 1

        return v


def reverse_bits(x, n):
    r = 0

    for _ in range(n):
        r = (r << 1) | (x & 1)
        x >>= 1

    return r


# ============================================================
# Huffman decoder
# ============================================================

class Huffman:
    def __init__(self, lengths):
        maxbits = max(lengths)

        counts = [0] * (maxbits + 1)

        for n in lengths:
            if n:
                counts[n] += 1

        next_code = [0] * (maxbits + 1)

        code = 0

        for bits in range(1, maxbits + 1):
            code = (
                code + counts[bits - 1]
            ) << 1

            next_code[bits] = code

        self.table = {}
        self.maxbits = maxbits

        for symbol, bits in enumerate(lengths):
            if not bits:
                continue

            code = next_code[bits]
            next_code[bits] += 1

            # DEFLATE transmits Huffman codes LSB first.
            code = reverse_bits(code, bits)

            self.table[(code, bits)] = symbol

    def decode(self, br):
        code = 0

        for bits in range(1, self.maxbits + 1):
            code |= br.read(1) << (bits - 1)

            key = (code, bits)

            if key in self.table:
                return self.table[key]

        raise RuntimeError("bad Huffman code")


# Fixed DEFLATE Huffman tables

lit_lengths = [0] * 288

for i in range(0, 144):
    lit_lengths[i] = 8

for i in range(144, 256):
    lit_lengths[i] = 9

for i in range(256, 280):
    lit_lengths[i] = 7

for i in range(280, 288):
    lit_lengths[i] = 8

LIT = Huffman(lit_lengths)
DIST = Huffman([5] * 32)


LENGTH_BASE = [
    3, 4, 5, 6, 7, 8, 9, 10,
    11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258
]

LENGTH_EXTRA = [
    0,0,0,0,0,0,0,0,
    1,1,1,1,2,2,2,2,
    3,3,3,3,4,4,4,4,
    5,5,5,5,0
]

DIST_BASE = [
    1,2,3,4,5,7,9,13,
    17,25,33,49,65,97,129,193,
    257,385,513,769,1025,1537,
    2049,3073,4097,6145,8193,12289,
    16385,24577
]

DIST_EXTRA = [
    0,0,0,0,1,1,2,2,
    3,3,4,4,5,5,6,6,
    7,7,8,8,9,9,10,10,
    11,11,12,12,13,13
]


# ============================================================
# Parse the DEFLATE token stream
# ============================================================

# Remove:
#   first 2 bytes = zlib header
#   last 4 bytes  = Adler32

br = BitReader(idat[2:-4])

BFINAL = br.read(1)
BTYPE = br.read(2)

assert BFINAL == 1

# This carrier deliberately uses fixed Huffman codes.
assert BTYPE == 1

output = bytearray()

# Each element:
#
#   (output_position, "literal", byte)
#
# or
#
#   (output_position, "match", (length, distance))

tokens = []

while True:
    symbol = LIT.decode(br)

    # Literal
    if symbol < 256:
        p = len(output)

        output.append(symbol)

        tokens.append(
            (p, "literal", symbol)
        )

        continue

    # End block
    if symbol == 256:
        break

    # Length
    li = symbol - 257

    length = LENGTH_BASE[li]

    extra = LENGTH_EXTRA[li]

    if extra:
        length += br.read(extra)

    # Distance
    ds = DIST.decode(br)

    distance = DIST_BASE[ds]

    extra = DIST_EXTRA[ds]

    if extra:
        distance += br.read(extra)

    p = len(output)

    # DEFLATE permits overlapping copy.
    for _ in range(length):
        output.append(
            output[-distance]
        )

    tokens.append(
        (
            p,
            "match",
            (length, distance)
        )
    )


print("[+] output bytes :", len(output))
print("[+] tokens       :", len(tokens))

matches = [
    t
    for t in tokens
    if t[1] == "match"
]

print("[+] matches      :", len(matches))

assert all(
    t[2][0] == 3
    for t in matches
)


# ============================================================
# Determine the nearest possible 3-byte match at every position
# ============================================================

raw = bytes(output)

# Most nearest matches can be found by remembering the most
# recent occurrence of each three-byte sequence.
#
# Distances 1 and 2 require special treatment because DEFLATE
# permits overlapping copies.

latest = {}
nearest = {}

for p in range(len(raw) - 2):

    target = raw[p:p+3]

    best = None

    # Overlapping matches.
    for d in (1, 2):
        if (
            p >= d
            and raw[p-d:p-d+3] == target
        ):
            best = d
            break

    if best is None and target in latest:
        d = p - latest[target]

        # Maximum DEFLATE window.
        if d <= 32768:
            best = d

    nearest[p] = best
    latest[target] = p


# ============================================================
# Recover compositor choices
# ============================================================

bits = []

for p, kind, value in tokens:

    distance = nearest.get(p)

    # No choice existed here.
    if distance is None:
        continue

    if kind == "match":

        length, actual_distance = value

        assert length == 3

        # "He always reached for the nearest one."
        assert actual_distance == distance

        bits.append(1)

    else:

        # He could have reached back but chose to set fresh.
        bits.append(0)


print("[+] choice bits:", len(bits))

# 38423


# ============================================================
# Pack complete bytes, MSB first
# ============================================================

ciphertext = bytearray()

for i in range(0, len(bits) - 7, 8):

    value = 0

    for bit in bits[i:i+8]:
        value = (value << 1) | bit

    ciphertext.append(value)


print(
    "[+] ciphertext bytes:",
    len(ciphertext)
)

print(
    "[+] ciphertext prefix:",
    ciphertext[:16].hex()
)


# ============================================================
# Card key
# ============================================================

k = hashlib.sha256(
    PREV_FLAG
).digest()


def make_stream(length):
    out = bytearray()
    counter = 0

    while len(out) < length:

        out += hashlib.sha256(
            k
            + counter.to_bytes(4, "big")
        ).digest()

        counter += 1

    return bytes(out[:length])


ks = make_stream(
    len(ciphertext)
)

plaintext = bytes(
    a ^ b
    for a, b in zip(
        ciphertext,
        ks
    )
)


# ============================================================
# Validate PL8
# ============================================================

assert plaintext[:3] == b"PL8"

issue = plaintext[3]

length = int.from_bytes(
    plaintext[4:6],
    "little"
)

expected_crc = int.from_bytes(
    plaintext[6:10],
    "little"
)

payload = plaintext[
    10:10+length
]

actual_crc = (
    zlib.crc32(payload)
    & 0xffffffff
)


print()
print("[+] WORKS ENTRY")
print("issue        =", issue)
print("length       =", length)
print(
    "expected CRC =",
    hex(expected_crc)
)
print(
    "actual CRC   =",
    hex(actual_crc)
)
print("payload      =", payload)


assert actual_crc == expected_crc