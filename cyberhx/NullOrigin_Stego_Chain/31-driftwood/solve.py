from PIL import Image
import struct
import zlib

img = Image.open("driftwood.png").convert("RGBA")

# First column, top -> bottom
bits = [(img.getpixel((0, y))[3] & 1) for y in range(img.height)]

data = bytes(
    sum(bits[i + j] << (7 - j) for j in range(8))
    for i in range(0, len(bits) - 7, 8)
)

assert data[:3] == b"PL8"

issue = data[3]
length = struct.unpack("<H", data[4:6])[0]
expected_crc = struct.unpack("<I", data[6:10])[0]

payload = data[10:10 + length]

assert zlib.crc32(payload) & 0xffffffff == expected_crc

print(payload)