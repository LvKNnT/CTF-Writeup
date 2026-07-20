#!/usr/bin/env python3
# Harvest many connections; each leaks 0+ flag chunks where the XOR key cancels.
# Assemble the 64-byte flag body from the most common printable decoding per chunk.
from pwn import *
import re, time, collections, string

HOST = "chall.blackpinker.com"
PORT = 20231
N    = 80
context.log_level = "error"

PRINT = set(bytes(string.printable[:-5], "ascii"))   # printable, no weird whitespace

def get_flag():
    io = remote(HOST, PORT, timeout=8)
    try:
        io.recvline()
        io.sendline(b"PARAMS")
        time.sleep(0.4)
        r = io.recv(timeout=4).decode(errors="replace")
        for _ in range(3):
            if "Encrypted flag:" in r:
                break
            r += io.recv(timeout=2).decode(errors="replace")
        m = re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", r)
        return m.group(1) if m else None
    finally:
        io.close()

# chunk -> Counter of decoded 16-byte strings that are fully printable
chunks = [collections.Counter() for _ in range(4)]
seen = 0
for i in range(N):
    try:
        fh = get_flag()
    except Exception as e:
        continue
    if not fh or len(fh) != 128:
        continue
    seen += 1
    b = bytes.fromhex(fh)
    for c in range(4):
        block = b[c*16:(c+1)*16]
        if all(x in PRINT for x in block):
            chunks[c][block.decode()] += 1
    if (i+1) % 10 == 0:
        print(f"[{i+1}/{N}] connections sampled ({seen} valid)")

print("\n==== per-chunk printable decodings (value : count) ====")
body = [None]*4
for c in range(4):
    print(f"chunk {c} (bytes {c*16}-{c*16+15}):")
    for val, cnt in chunks[c].most_common(6):
        print(f"    {cnt:3d}  {val!r}")
    if chunks[c]:
        # chunk 3 has random padding in its tail; pick by most common 8-char prefix
        if c == 3:
            pref = collections.Counter(k[:8] for k in chunks[c]).most_common(1)[0][0]
            body[c] = pref
        else:
            body[c] = chunks[c].most_common(1)[0][0]

print("\n==== assembled ====")
if all(body[c] for c in range(3)):
    head = body[0] + body[1] + body[2]
    tail = body[3] if body[3] else "????????"
    print("body[0..47] :", head)
    print("body[48..55]:", tail)
    flag = "HCMUS-CTF{" + head + tail + "}"
    print("\nFLAG:", flag)
else:
    print("Not all chunks leaked yet; raise N and re-run.")
