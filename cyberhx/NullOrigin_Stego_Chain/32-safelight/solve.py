from PIL import Image
import hashlib
import zlib

PREV_FLAG = b"Null0rigin{what_the_negative_kept_from_the_print}"

neg = Image.open("negative.png").convert("L")
prt = Image.open("print.png").convert("L")

w, h = neg.size

# ------------------------------------------------------------
# 1. Find ±1 cells
# ------------------------------------------------------------

bits = []

for y in range(h):
    for x in range(w):
        n = neg.getpixel((x, y))
        p = prt.getpixel((x, y))

        d = p - (255 - n)

        if abs(d) == 1:
            bits.append(1 if d == 1 else 0)

print("bits:", len(bits))

# ------------------------------------------------------------
# 2. Pack MSB-first
# ------------------------------------------------------------

ciphertext = bytearray()

for i in range(0, len(bits), 8):
    chunk = bits[i:i+8]

    if len(chunk) < 8:
        break

    b = 0
    for bit in chunk:
        b = (b << 1) | bit

    ciphertext.append(b)

print("ciphertext:", ciphertext.hex())

# ------------------------------------------------------------
# 3. Derive key from previous flag
# ------------------------------------------------------------

k = hashlib.sha256(PREV_FLAG).digest()

def make_stream(length):
    out = bytearray()
    counter = 0

    while len(out) < length:
        block = hashlib.sha256(
            k + counter.to_bytes(4, "big")
        ).digest()

        out.extend(block)
        counter += 1

    return bytes(out[:length])

stream = make_stream(len(ciphertext))

# ------------------------------------------------------------
# 4. XOR
# ------------------------------------------------------------

plain = bytes(
    a ^ b
    for a, b in zip(ciphertext, stream)
)

print("decrypted:", plain)

# ------------------------------------------------------------
# 5. Parse PL8
# ------------------------------------------------------------

assert plain[:3] == b"PL8"

issue = plain[3]
length = int.from_bytes(plain[4:6], "little")
expected_crc = int.from_bytes(plain[6:10], "little")

payload = plain[10:10 + length]

actual_crc = zlib.crc32(payload) & 0xffffffff

print("issue:", issue)
print("length:", length)
print("expected crc:", hex(expected_crc))
print("actual crc:  ", hex(actual_crc))
print("payload:", payload)

assert actual_crc == expected_crc