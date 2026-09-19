import hashlib
import struct
import zlib

PNG = "mordant.png"

PREVIOUS_FLAG = (
    b"Null0rigin{nothing_takes_until_it_is_fixed}"
)

SHARES = [
    bytes.fromhex("9e4c1af0d3b27651"),
    bytes.fromhex("2a77be05c4198d3f"),
    bytes.fromhex("f10983dd6b5ec4a2"),
    bytes.fromhex("55c2e79140ab3d08"),
    bytes.fromhex("bd3f60a8e2749c15"),
    bytes.fromhex("07e5cb3219d6f48b"),
]


# ------------------------------------------------------------
# Parse PNG
# ------------------------------------------------------------

data = open(PNG, "rb").read()

assert data[:8] == b"\x89PNG\r\n\x1a\n"

pos = 8
idat = bytearray()

while pos < len(data):

    length = int.from_bytes(
        data[pos:pos+4],
        "big"
    )

    typ = data[pos+4:pos+8]
    payload = data[pos+8:pos+8+length]

    if typ == b"IHDR":
        width, height, bitdepth, colortype, \
        compression, filter_method, interlace = \
            struct.unpack(">IIBBBBB", payload)

        print("[+] size:", width, height)

        assert bitdepth == 8
        assert colortype == 0
        assert interlace == 0

    elif typ == b"IDAT":
        idat += payload

    elif typ == b"IEND":
        break

    pos += 12 + length


# ------------------------------------------------------------
# Decompress PNG scanlines
# grayscale 8-bit => width bytes per row + one filter byte
# ------------------------------------------------------------

raw = zlib.decompress(bytes(idat))

stride = width + 1

assert len(raw) == stride * height


filters = [
    raw[y * stride]
    for y in range(height)
]


from collections import Counter

print("[+] filters:", Counter(filters))


# ------------------------------------------------------------
# Filter types -> 2-bit symbols
#
# 0 and 4 deliberately represent the same value
# ------------------------------------------------------------

def filter_symbol(f):

    if f == 0 or f == 4:
        return 0

    if f == 1:
        return 1

    if f == 2:
        return 2

    if f == 3:
        return 3

    raise ValueError(f"bad filter {f}")


symbols = [
    filter_symbol(f)
    for f in filters
]


# ------------------------------------------------------------
# Four 2-bit symbols -> one byte
# ------------------------------------------------------------

page_cipher = bytearray()

for i in range(0, len(symbols), 4):

    chunk = symbols[i:i+4]

    if len(chunk) < 4:
        break

    b = (
        (chunk[0] << 6)
        | (chunk[1] << 4)
        | (chunk[2] << 2)
        | chunk[3]
    )

    page_cipher.append(b)


print("[+] page bytes:", len(page_cipher))
print("[+] prefix:", page_cipher[:16].hex())


# ------------------------------------------------------------
# Card stream helper
# ------------------------------------------------------------

def make_stream(key, length):

    out = bytearray()
    counter = 0

    while len(out) < length:

        out += hashlib.sha256(
            key
            + counter.to_bytes(4, "big")
        ).digest()

        counter += 1

    return bytes(out[:length])


# ------------------------------------------------------------
# Layer 1: previous-stage card key
# ------------------------------------------------------------

card_key = hashlib.sha256(
    PREVIOUS_FLAG
).digest()

stream1 = make_stream(
    card_key,
    len(page_cipher)
)

intermediate = bytes(
    a ^ b
    for a, b in zip(
        page_cipher,
        stream1
    )
)


# ------------------------------------------------------------
# Layer 2: the six mordants
# ------------------------------------------------------------

mordant_material = b"".join(SHARES)

mordant_key = hashlib.sha256(
    mordant_material
).digest()

print("[+] mordant key:", mordant_key.hex())


stream2 = make_stream(
    mordant_key,
    len(intermediate)
)

plain = bytes(
    a ^ b
    for a, b in zip(
        intermediate,
        stream2
    )
)


print("[+] decrypted:", plain[:80])


# ------------------------------------------------------------
# PL8 validation
# ------------------------------------------------------------

assert plain[:3] == b"PL8"

issue = plain[3]

length = int.from_bytes(
    plain[4:6],
    "little"
)

expected_crc = int.from_bytes(
    plain[6:10],
    "little"
)

payload = plain[
    10:10 + length
]

actual_crc = zlib.crc32(payload) & 0xffffffff


print()
print("[+] WORKS ENTRY")
print("issue        =", issue)
print("length       =", length)
print("expected CRC =", hex(expected_crc))
print("actual CRC   =", hex(actual_crc))
print("payload      =", payload)

assert actual_crc == expected_crc


# ------------------------------------------------------------
# Flag
# ------------------------------------------------------------

start = payload.find(b"Null0rigin{")
end = payload.find(b"}", start)

flag = payload[start:end+1]

print()
print("[+] FLAG:", flag.decode())