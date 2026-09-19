import hashlib
import zlib

import numpy as np
from scipy.io import wavfile


BLOCK = 2048

PREVIOUS_FLAG = (
    b"Null0rigin{a_carrier_laid_across_the_whole_room}"
)


# ----------------------------------------------------------
# Card key schedule
# ----------------------------------------------------------

def card_stream(key_string: bytes, nbytes: int) -> bytes:
    k = hashlib.sha256(key_string).digest()

    out = bytearray()
    counter = 0

    while len(out) < nbytes:
        out += hashlib.sha256(
            k + counter.to_bytes(4, "big")
        ).digest()

        counter += 1

    return bytes(out[:nbytes])


# ----------------------------------------------------------
# Decode spread-spectrum audio
# ----------------------------------------------------------

def decode_audio(filename, key_string):
    sr, audio = wavfile.read(filename)

    print("[+] sample rate:", sr)
    print("[+] shape:", audio.shape)

    # Left channel only
    left = audio[:, 0].astype(np.float64)

    # Number of complete 2048-sample symbols
    nbits = len(left) // BLOCK
    nsamples = nbits * BLOCK

    print("[+] encoded bits:", nbits)

    # Need one pseudorandom bit for every audio sample.
    #
    # Therefore:
    #     nsamples bits
    #       =
    #     ceil(nsamples / 8) stream bytes
    #
    ks = card_stream(
        key_string,
        (nsamples + 7) // 8
    )

    stream_bits = np.unpackbits(
        np.frombuffer(ks, dtype=np.uint8),
        bitorder="big"
    )[:nsamples]

    # 0 -> -1
    # 1 -> +1
    chips = np.where(
        stream_bits == 1,
        1.0,
        -1.0
    )

    # Matched filter / correlation
    correlation = (
        left[:nsamples] * chips
    ).reshape(nbits, BLOCK).sum(axis=1)

    # Positive correlation = 1
    # Negative correlation = 0
    bits = (correlation > 0).astype(np.uint8)

    # Only complete bytes
    bits = bits[:len(bits) // 8 * 8]

    data = np.packbits(
        bits,
        bitorder="big"
    ).tobytes()

    return data, correlation


# ----------------------------------------------------------
# First: verify technique against known LINETEST
# ----------------------------------------------------------

test_data, test_corr = decode_audio(
    "linetest.wav",
    b"LINE TEST"
)

print()
print("[+] LINETEST:")
print(test_data[:50])

# Should begin:
#
# b'PL8\x01\x1b\x00}\x01O\xc1'
# b'NULL0RIGIN LINE TEST 1 OF 1'


# ----------------------------------------------------------
# Decode real stage
# ----------------------------------------------------------

data, corr = decode_audio(
    "undertone.wav",
    PREVIOUS_FLAG
)

print()
print("[+] first bytes:", data[:80])
print("[+] hex:", data[:80].hex())


# ----------------------------------------------------------
# Parse PL8 works entry
# ----------------------------------------------------------

assert data[:3] == b"PL8"

issue = data[3]

length = int.from_bytes(
    data[4:6],
    "little"
)

expected_crc = int.from_bytes(
    data[6:10],
    "little"
)

payload = data[10:10 + length]

actual_crc = zlib.crc32(payload) & 0xffffffff


print()
print("[+] WORKS ENTRY")
print("issue        :", issue)
print("length       :", length)
print("expected CRC :", hex(expected_crc))
print("actual CRC   :", hex(actual_crc))
print("payload      :", payload)

assert actual_crc == expected_crc


# ----------------------------------------------------------
# Extract flag
# ----------------------------------------------------------

start = payload.find(b"Null0rigin{")

if start != -1:
    end = payload.find(b"}", start)

    if end != -1:
        flag = payload[start:end + 1]

        print()
        print("[+] FLAG:", flag.decode())