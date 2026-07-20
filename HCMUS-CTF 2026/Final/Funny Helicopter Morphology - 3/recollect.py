#!/usr/bin/env python3
# Re-collect with a within-connection consistency check (PARAMS twice must match),
# then CHALLENGE. Confirms OTP/flag and S come from the SAME instance.
from pwn import *
import re, json, time

HOST = "chall.blackpinker.com"
PORT = 20231
NUM_SAMPLES = 8
context.log_level = "info"

def parse_ints(s):
    return [int(x) for x in re.findall(r"-?\d+", s)]

def get_params(io):
    io.sendline(b"PARAMS")
    time.sleep(0.6)
    r = io.recv(timeout=4).decode(errors="replace")
    # if response looks short, drain a bit more
    for _ in range(3):
        if "OTP:" in r and r.rstrip().endswith("]"):
            break
        time.sleep(0.3)
        r += io.recv(timeout=2).decode(errors="replace")
    q   = int(re.search(r"q:\s*(\d+)", r).group(1))
    q0  = int(re.search(r"q0:\s*(\d+)", r).group(1))
    nn  = int(re.search(r"n:\s*(\d+)", r).group(1))
    fl  = re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", r).group(1)
    otp = parse_ints(re.search(r"OTP:\s*(\[[^\]]*\])", r).group(1))
    return nn, q, q0, fl, otp

io = remote(HOST, PORT)
io.recvline()

n, q, q0, flag1, otp1 = get_params(io)
_, _, _, flag2, otp2 = get_params(io)

print("[*] within-connection PARAMS stable? flag:", flag1 == flag2, " otp:", otp1 == otp2)
assert flag1 == flag2 and otp1 == otp2, "instance not stable within a connection!"

io.sendline(f"CHALLENGE {NUM_SAMPLES} 0".encode())
chal = io.recvall(timeout=20).decode(errors="replace")
r = int(re.search(r"r:\s*(\d+)", chal).group(1))
samples = []
for block in re.split(r"SAMPLE\s+\d+", chal)[1:]:
    c1 = parse_ints(re.search(r"C1:\s*(\[[^\]]*\])", block).group(1))
    c0 = parse_ints(re.search(r"C0:\s*(\[[^\]]*\])", block).group(1))
    samples.append({"c1": c1, "c0": c0})

data = {"n": n, "q": q, "q0": q0, "flag_hex": flag1, "otp": otp1, "r": r, "samples": samples}
json.dump(data, open("data.json", "w"))
print("[*] saved data.json: n=%d, samples=%d, r=%d" % (n, len(samples), r))
print("[*] flag_hex =", flag1)
