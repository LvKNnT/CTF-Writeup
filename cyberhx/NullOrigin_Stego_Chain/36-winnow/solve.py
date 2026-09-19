from PIL import Image
import hashlib
import zlib


IMAGE = "sheet.png"

PREVIOUS_FLAG = (
    b"Null0rigin{keep_the_grain_and_burn_the_chaff}"
)

FRAME_W = 32
FRAME_H = 32


# ------------------------------------------------------------
# Key
# ------------------------------------------------------------

k = hashlib.sha256(PREVIOUS_FLAG).digest()

print("[+] k =", k.hex())


# ------------------------------------------------------------
# Load sheet
# ------------------------------------------------------------

img = Image.open(IMAGE).convert("L")

W, H = img.size

assert W == 2048
assert H == 1024

frames_x = W // FRAME_W
frames_y = H // FRAME_H

assert frames_x == 64
assert frames_y == 32

print("[+] frames:", frames_x * frames_y)


# ------------------------------------------------------------
# Extract bit + seal from one frame
#
# first 17 pixels, raster order:
#
#   first bit   = data bit
#   next 16     = seal
# ------------------------------------------------------------

def get_frame_payload(frame_no):

    fx = frame_no % frames_x
    fy = frame_no // frames_x

    x0 = fx * FRAME_W
    y0 = fy * FRAME_H

    bits = []

    # First 17 pixels of frame
    for i in range(17):

        x = x0 + i
        y = y0

        value = img.getpixel((x, y))

        bits.append(value & 1)

    data_bit = bits[0]

    seal_bits = bits[1:17]

    seal = bytearray()

    for i in range(0, 16, 8):

        value = 0

        for bit in seal_bits[i:i + 8]:
            value = (value << 1) | bit

        seal.append(value)

    return data_bit, bytes(seal)


# ------------------------------------------------------------
# Calculate genuine seal
# ------------------------------------------------------------

def expected_seal(frame_no, bit):

    material = (
        k
        + frame_no.to_bytes(2, "big")
        + bytes([bit])
    )

    return hashlib.sha256(material).digest()[:2]


# ------------------------------------------------------------
# Winnow grain from chaff
# ------------------------------------------------------------

selected_bits = []

valid_frames = []


for pair in range(1024):

    n0 = pair * 2
    n1 = n0 + 1

    candidates = []

    for n in (n0, n1):

        bit, stored = get_frame_payload(n)

        expected = expected_seal(n, bit)

        if stored == expected:
            candidates.append((n, bit))

    # Real data-bearing pair
    if len(candidates) == 1:

        n, bit = candidates[0]

        selected_bits.append(bit)
        valid_frames.append(n)

    elif len(candidates) > 1:

        raise RuntimeError(
            f"pair {pair}: multiple valid frames"
        )


print("[+] authenticated bits:", len(selected_bits))
print("[+] authenticated frames:", len(valid_frames))

# Expected:
# 496 bits


# ------------------------------------------------------------
# Pack bits MSB-first
# ------------------------------------------------------------

def pack_bits(bits):

    assert len(bits) % 8 == 0

    output = bytearray()

    for i in range(0, len(bits), 8):

        value = 0

        for bit in bits[i:i + 8]:
            value = (value << 1) | bit

        output.append(value)

    return bytes(output)


ciphertext = pack_bits(selected_bits)

print("[+] ciphertext length:", len(ciphertext))
print("[+] ciphertext:", ciphertext.hex())


# ------------------------------------------------------------
# Card stream
#
# SHA256(k || counter_be32)
# ------------------------------------------------------------

def make_stream(length):

    out = bytearray()
    counter = 0

    while len(out) < length:

        out += hashlib.sha256(
            k + counter.to_bytes(4, "big")
        ).digest()

        counter += 1

    return bytes(out[:length])


stream = make_stream(len(ciphertext))


plaintext = bytes(
    a ^ b
    for a, b in zip(ciphertext, stream)
)


print("[+] plaintext:", plaintext)
print("[+] plaintext hex:", plaintext.hex())


# ------------------------------------------------------------
# PL8 validation
# ------------------------------------------------------------

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

assert start != -1
assert end != -1

flag = payload[start:end + 1]

print()
print("[+] FLAG:", flag.decode())