#!/usr/bin/env python3
# Collect one consistent transcript (PARAMS + CHALLENGE) from the live instance.
from pwn import *
import re, json, time, sys

HOST = "chall.blackpinker.com"
PORT = 20231
NUM_SAMPLES = 6          # how many (a, c0) samples to request in the CHALLENGE
context.log_level = "info"

def parse_ints(s):
    return [int(x) for x in re.findall(r"-?\d+", s)]

io = remote(HOST, PORT)
io.recvline()  # banner

# --- PARAMS (does not close the connection) ---
io.sendline(b"PARAMS")
time.sleep(0.6)
params_resp = io.recv(timeout=4).decode(errors="replace")
print("==== PARAMS RESP (head) ====")
print(params_resp[:400])

n   = int(re.search(r"n:\s*(\d+)", params_resp).group(1))
q   = int(re.search(r"q:\s*(\d+)", params_resp).group(1))
q0  = int(re.search(r"q0:\s*(\d+)", params_resp).group(1))
flag_hex = re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", params_resp).group(1)
otp = parse_ints(re.search(r"OTP:\s*(\[[^\]]*\])", params_resp).group(1))

# --- CHALLENGE with message 0 -> m_poly = 0, so C0 = a*S + e*r ; this closes the conn ---
io.sendline(f"CHALLENGE {NUM_SAMPLES} 0".encode())
chal_resp = io.recvall(timeout=15).decode(errors="replace")

r = int(re.search(r"r:\s*(\d+)", chal_resp).group(1))
samples = []
for block in re.split(r"SAMPLE\s+\d+", chal_resp)[1:]:
    c1 = parse_ints(re.search(r"C1:\s*(\[[^\]]*\])", block).group(1))
    c0 = parse_ints(re.search(r"C0:\s*(\[[^\]]*\])", block).group(1))
    samples.append({"c1": c1, "c0": c0})

data = {"n": n, "q": q, "q0": q0, "flag_hex": flag_hex,
        "otp": otp, "r": r, "samples": samples}

with open("data.json", "w") as f:
    json.dump(data, f)

print("\n==== SUMMARY ====")
print("n           =", n)
print("q  bitlen   =", q.bit_length(), " q  =", q)
print("q0 bitlen   =", q0.bit_length(), " q0 =", q0)
print("q / q0..    => remaining primes product bitlen:", (q // q0).bit_length())
print("flag_hex len(chars) =", len(flag_hex), "=> bytes:", len(flag_hex)//2)
print("len(otp)    =", len(otp))
print("r           =", r, " (bitlen", r.bit_length(), ")")
print("num samples =", len(samples), " each c1/c0 len:", len(samples[0]["c1"]), len(samples[0]["c0"]))
print("\nSaved -> data.json")
