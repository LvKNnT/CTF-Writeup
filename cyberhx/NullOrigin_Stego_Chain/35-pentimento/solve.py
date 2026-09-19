import hashlib
import struct
import zlib


GIF = "pentimento.gif"

PREVIOUS_FLAG = (
    b"Null0rigin{the_order_of_the_colours_is_the_message}"
)


# ------------------------------------------------------------
# Parse raw GIF and collect every local color table.
# We do this ourselves so Pillow does not normalize palettes.
# ------------------------------------------------------------

data = open(GIF, "rb").read()

assert data[:6] in (b"GIF87a", b"GIF89a")

pos = 6

width, height, packed, bg, aspect = struct.unpack_from(
    "<HHBBB", data, pos
)
pos += 7


# Global color table, if present
gct_flag = (packed >> 7) & 1

if gct_flag:
    size = 2 ** ((packed & 7) + 1)
    pos += size * 3


palettes = []


while pos < len(data):

    marker = data[pos]
    pos += 1

    # GIF trailer
    if marker == 0x3B:
        break

    # Extension
    if marker == 0x21:

        label = data[pos]
        pos += 1

        while True:
            n = data[pos]
            pos += 1

            if n == 0:
                break

            pos += n

        continue

    # Image descriptor
    if marker != 0x2C:
        raise ValueError(
            f"Unexpected marker {marker:#x}"
        )

    left, top, w, h, image_packed = struct.unpack_from(
        "<HHHHB", data, pos
    )
    pos += 9

    local_flag = (image_packed >> 7) & 1

    if not local_flag:
        raise ValueError(
            "Expected a local palette on every frame"
        )

    palette_size = 2 ** (
        (image_packed & 7) + 1
    )

    raw_palette = data[
        pos : pos + palette_size * 3
    ]

    pos += palette_size * 3

    palette = [
        tuple(raw_palette[i:i + 3])
        for i in range(
            0,
            len(raw_palette),
            3
        )
    ]

    palettes.append(palette)

    # LZW minimum code size
    pos += 1

    # Skip compressed image sub-blocks
    while True:

        n = data[pos]
        pos += 1

        if n == 0:
            break

        pos += n


print("[+] frames:", len(palettes))

assert len(palettes) == 11


# ------------------------------------------------------------
# Extract palette-order bits
# ------------------------------------------------------------

bits = []

for frame_no, palette in enumerate(palettes):

    assert len(palette) == 256
    assert len(set(palette)) == 256

    # "darkest to lightest, red before green before blue"
    canonical = sorted(
        palette,
        key=lambda rgb: (
            sum(rgb),
            rgb[0],
            rgb[1],
            rgb[2]
        )
    )

    frame_bits = []

    for i in range(0, 256, 2):

        actual = palette[i:i + 2]
        expected = canonical[i:i + 2]

        if actual == expected:

            bit = 0

        elif actual == expected[::-1]:

            bit = 1

        else:

            raise ValueError(
                f"Frame {frame_no}, "
                f"pair {i // 2}: "
                "not a simple pair swap"
            )

        frame_bits.append(bit)

    bits.extend(frame_bits)

    print(
        f"[+] frame {frame_no:02}: "
        f"{sum(frame_bits)} swapped pairs"
    )


print("[+] total bits:", len(bits))

assert len(bits) == 1408


# ------------------------------------------------------------
# Bits -> bytes, MSB first
# ------------------------------------------------------------

ciphertext = bytearray()

for i in range(0, len(bits), 8):

    value = 0

    for bit in bits[i:i + 8]:
        value = (value << 1) | bit

    ciphertext.append(value)


print(
    "[+] ciphertext:",
    bytes(ciphertext[:16]).hex()
)


# ------------------------------------------------------------
# Previous-stage key schedule
# ------------------------------------------------------------

k = hashlib.sha256(
    PREVIOUS_FLAG
).digest()

print("[+] k:", k.hex())


def make_stream(length):

    output = bytearray()
    counter = 0

    while len(output) < length:

        output += hashlib.sha256(
            k +
            counter.to_bytes(4, "big")
        ).digest()

        counter += 1

    return bytes(output[:length])


stream = make_stream(
    len(ciphertext)
)


plaintext = bytes(
    a ^ b
    for a, b in zip(
        ciphertext,
        stream
    )
)


print(
    "[+] decrypted prefix:",
    plaintext[:32]
)


# ------------------------------------------------------------
# Parse PL8 entry
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
    10 : 10 + length
]

actual_crc = (
    zlib.crc32(payload)
    & 0xffffffff
)


print()
print("[+] PL8")
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


# ------------------------------------------------------------
# Find flag
# ------------------------------------------------------------

start = payload.find(
    b"Null0rigin{"
)

end = payload.find(
    b"}",
    start
)

flag = payload[
    start : end + 1
]

print()
print(
    "[+] FLAG:",
    flag.decode()
)