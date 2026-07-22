#!/usr/bin/env sage
"""
Funny Helicopter Morphology - 2.

This reuses the "Funny Helicopter Morphology" BFV-ish service from
challenge 1 (server_new.cpp), but exploited via the *no-hint* path: the
server only reveals the EVALSUM auxiliary hint (B_i, S_i samples of the
secret T) if EVALSUM is requested *before* PARAMS. Sending PARAMS first
sets used_params=true, which makes the server silently ignore any later
EVALSUM request and return `encrypted_flag_2` instead of
`encrypted_flag_1` from PARAMS.

Without the hint we only get, from a single CHALLENGE call:
    C1_i (public, ternary "a" poly)
    C0_i = a_i * S + e_i * r + m_poly   (mod q, main ring, dim 16)
where S is the 16-coefficient target-ring polynomial formed by
concatenating the two 8-coefficient auxiliary samples:
    S = (B0*T + K0, B1*T + K1)
r is a random per-connection scalar, e_i is Gaussian, m_poly is the
(chosen, here all-zero) plaintext message polynomial.

Attack:
 1. C1_0 is invertible mod r -> solve for S mod r from the first sample.
 2. Lift S mod r into [0, q) and use the remaining samples (over-
    determined least squares) to filter out the Gaussian noise term
    (e_i*r)/r and recover the *exact* integer S.
 3. S splits into S0 = B0*T + K0 and S1 = B1*T + K1 (each dimension 8,
    negacyclic ring). Both B0, B1 are ternary and small (K0, K1
    Gaussian). Build the ACDP-style lattice
        [ I_8   0   |  Mat(S1) ]
        [ 0    I_8  | -Mat(S0) ]
    and LLL-reduce it: the shortest vector's two 8-blocks are exactly
    (B0, B1) up to sign, because B0*S1 - B1*S0 = B0*K1 - B1*K0 is tiny
    while B0, B1 themselves are ternary (also tiny).
 4. Once B0 is known, T = Mat(B0)^{-1} * S0 (least squares / exact
    solve), rounded to the nearest integer. T should come out sorted
    (the server always sorts T's coefficients before use) - that's a
    correctness check.
 5. The server masks flag bytes by XOR with the little-endian 8-byte
    packing of T's signed coefficients (GetPolyCoefficientsSigned); XOR
    the leaked encrypted_flag_2 bytes with that same keystream to
    recover the flag.

A single run's guessed lattice vector can end up ±1 off on some bytes
(borderline rounding / sign ambiguity), so as in the writeup, running
this against a couple of live transcripts and comparing the recovered
plaintext prefixes (they should agree except for the random padding
suffix) is the reliable way to confirm the flag body.

Usage: sage solve.sage
"""

import struct
from hashlib import md5  # unused, kept for parity with sibling scripts
from pwn import remote

HOST = "chall.blackpinker.com"
PORT = 20799  # NOTE: verify against the live scoreboard; this port was recorded during solving
NUM_SAMPLES = 10  # CHALLENGE <NUM_SAMPLES> 0


def center_mod(val, mod):
    val = val % mod
    if val > mod // 2:
        val -= mod
    return val


def get_convolution_matrix_rows(poly_coeffs):
    """Negacyclic (x^n+1) convolution matrix: M such that M^T * x == poly_coeffs (*) x."""
    n = len(poly_coeffs)
    M = matrix(QQ, n, n)
    for i in range(n):
        for j in range(n):
            k = (j - i) % n
            val = poly_coeffs[k]
            if i + k >= n:
                M[i, j] = -val
            else:
                M[i, j] = val
    return M


def main():
    import ast
    import re

    # ==========================================
    # 1. Connect and collect the no-hint transcript
    # ==========================================
    io = remote(HOST, PORT)
    io.recvline()
    print("[*] Connected, fetching PARAMS (before EVALSUM -> no-hint path)...")

    io.sendline(b"PARAMS")
    params_data = io.recvuntil(b"Encrypted flag: ").decode()
    encrypted_flag_2_hex = io.recvline().decode().strip()

    Q = int(re.search(r"q: (\d+)", params_data).group(1))
    print(f"[+] Found q: {Q}")
    print(f"[+] Found encrypted flag: {encrypted_flag_2_hex[:16]}...")

    print(f"\n[*] Fetching CHALLENGE data ({NUM_SAMPLES} samples)...")
    io.sendline(f"CHALLENGE {NUM_SAMPLES} 0".encode())
    chall_data = io.recvuntil(b"SAMPLE 0\n").decode()
    R = int(re.search(r"r: (\d+)", chall_data).group(1))

    def parse_poly_array(line):
        return ast.literal_eval(line.split(":", 1)[1].strip())

    samples = []
    for i in range(NUM_SAMPLES):
        if i > 0:
            io.recvuntil(f"SAMPLE {i}\n".encode())
        c1_line = io.recvline().decode().strip()
        c0_line = io.recvline().decode().strip()
        samples.append({"C1": parse_poly_array(c1_line), "C0": parse_poly_array(c0_line)})

    print(f"[+] Found r: {R}")
    print(f"[+] Successfully parsed {NUM_SAMPLES} samples.")
    io.close()

    # ==========================================
    # 2. Phase 1: Extract exact S via overdetermined least squares
    # ==========================================
    print("\n[*] Phase 1: Extracting S using overdetermined least squares...")

    C1_0 = samples[0]["C1"]
    C0_0 = [center_mod(c, Q) for c in samples[0]["C0"]]

    M_C1_0 = get_convolution_matrix_rows(C1_0).transpose()
    C0_0_vec = vector(QQ, C0_0)

    S_mod_r = matrix(Zmod(R), M_C1_0).solve_right(vector(Zmod(R), C0_0_vec))
    S_mod_r_lifted = vector(QQ, [int(x) for x in S_mod_r])

    n = NUM_SAMPLES * 16
    M_stack = matrix(QQ, n, 16)
    V_stack = vector(QQ, n)

    for i in range(NUM_SAMPLES):
        C1_i = samples[i]["C1"]
        C0_i = [center_mod(c, Q) for c in samples[i]["C0"]]

        M_i = get_convolution_matrix_rows(C1_i).transpose()
        V_i = (vector(QQ, C0_i) - M_i * S_mod_r_lifted) / R

        for r in range(16):
            V_stack[i * 16 + r] = V_i[r]
            for c in range(16):
                M_stack[i * 16 + r, c] = M_i[r, c]

    print("[*] Solving least squares to filter Gaussian noise...")
    Mt = M_stack.transpose()
    X_approx = (Mt * M_stack).inverse() * Mt * V_stack
    X_exact = vector(ZZ, [round(x) for x in X_approx])

    S_exact = S_mod_r_lifted + R * X_exact
    print(f"[+] Recovered EXACT S (first 4 coeffs): {list(S_exact)[:4]}...")

    # ==========================================
    # 3. Phase 2: ACDP lattice reduction to recover B0, B1
    # ==========================================
    print("\n[*] Phase 2: Building and reducing ACDP lattice...")
    S0 = list(S_exact[:8])
    S1 = list(S_exact[8:])

    M_S0_row = get_convolution_matrix_rows(S0)
    M_S1_row = get_convolution_matrix_rows(S1)

    L = matrix(ZZ, 16, 24)
    for i in range(8):
        L[i, i] = 1
        for j in range(8):
            L[i, 16 + j] = M_S1_row[i, j]

    for i in range(8):
        L[8 + i, 8 + i] = 1
        for j in range(8):
            L[8 + i, 16 + j] = -M_S0_row[i, j]

    print("[*] Running LLL...")
    L_red = L.LLL()

    shortest = L_red[0]
    B0 = list(shortest[:8])
    B1 = list(shortest[8:16])

    print(f"[+] Recovered B0: {B0}")
    print(f"[+] Recovered B1: {B1}")

    # ==========================================
    # 4. Phase 3: Recover T and decrypt
    # ==========================================
    print("\n[*] Phase 3: Recovering T and decrypting...")
    M_B0_col = get_convolution_matrix_rows(B0).transpose()
    S0_vec = vector(QQ, S0)

    T_approx = M_B0_col.solve_right(S0_vec)
    T = [round(x) for x in T_approx]

    print(f"[+] Recovered secret T (first 4 coeffs): {T[:4]}...")

    if T == sorted(T):
        print("[+] Verification passed: T coefficients are sorted.")
    else:
        print("[!] Warning: T coefficients are not sorted! B0/B1 sign may be flipped, try -B0/-B1.")

    key_bytes = b"".join(struct.pack("<q", coeff) for coeff in T)

    enc_bytes = bytes.fromhex(encrypted_flag_2_hex)
    decrypted_flag = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(enc_bytes))

    flag_str = decrypted_flag.decode("utf-8", errors="ignore")
    print(f"\n[+] Decrypted flag body (padded, run a couple more times and compare prefixes): {flag_str}")


if __name__ == "__main__":
    main()
