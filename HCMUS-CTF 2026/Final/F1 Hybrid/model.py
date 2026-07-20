#!/usr/bin/env python3
# Build exact GF(2) affine model of the F1-Hybrid key schedule.
# round_keys[i] = M_i . seed  XOR  c_i   (seed = 48-bit master key)
# Goal: discover structural weakness (rank / collisions).

import random

SIZE = 23738715 // 2          # 11869357
MASK48 = (1 << 48) - 1
CRC_POLY = 0xEDB88320

# ---- GF(2) linear maps represented in COLUMN form ----
# A map is a list `cols` of length n_in; cols[j] = image (as int bitmask) of basis vector e_j.
# Apply map to vector v (int):  result = XOR of cols[j] for set bits j of v.

def apply_map(cols, v):
    r = 0
    while v:
        j = (v & -v).bit_length() - 1
        r ^= cols[j]
        v &= v - 1
    return r

def matmul(A, B):
    # (A . B): columns = A applied to each column of B
    return [apply_map(A, col) for col in B]

def matpow(A, e, n):
    # identity in column form for n-dim
    R = [1 << j for j in range(n)]
    base = A
    while e:
        if e & 1:
            R = matmul(base, R)
        e >>= 1
        if e:
            base = matmul(base, base)
    return R

def build_T(poly):
    # 48-dim LFSR transition. layout: bit j = lfsr state bit j (0..47).
    # next bit (j+1) <- old bit j for j in 0..46 ; new bit0 = parity(state & poly)
    cols = [0] * 48
    for j in range(48):
        c = 0
        if j <= 46:
            c |= 1 << (j + 1)
        if (poly >> j) & 1:
            c |= 1 << 0
        cols[j] = c
    return cols

def build_comb(poly):
    # 80-dim: bits 0..47 lfsr, bits 48..79 crc.
    # per step: b = old lfsr bit47 ; lfsr <- T.lfsr ; crc <- F(crc,b)
    # F(crc,b): t=crc^b(into bit0); lsb=t&1; new = (t>>1) ^ (CRC_POLY if lsb else 0)
    Tcols = build_T(poly)
    cols = [0] * 80
    # lfsr basis e_j (j 0..47): b = (j==47)
    for j in range(48):
        c = Tcols[j]  # lfsr part in bits 0..47
        b = 1 if j == 47 else 0
        # crc contribution with crc_in=0: lsb=b ; new_crc = CRC_POLY if b else 0
        if b:
            c |= CRC_POLY << 48
        cols[j] = c
    # crc basis e_{48+m} (m 0..31): lfsr=0 -> b=0
    for m in range(32):
        # crc has only bit m set. crc0 = (m==0). lsb=crc0.
        # new_crc_k = crc_{k+1}(set if k+1==m) XOR (CRC_POLY_k & lsb)
        nc = 0
        if m >= 1:
            nc |= 1 << (m - 1)
        if m == 0:
            nc ^= CRC_POLY
        cols[48 + m] = nc << 48
    return cols

def build_schedule_model(poly):
    comb = build_comb(poly)
    print("[*] exponentiating combined 80x80 map to SIZE =", SIZE)
    combSIZE = matpow(comb, SIZE, 80)
    Tcols = build_T(poly)
    A = matpow(Tcols, SIZE, 48)     # T^SIZE : advance one rk-worth (lfsr only)
    # Extract B (32x48): crc output from initial lfsr state (crc_in=0)
    #   = high 32 bits of combSIZE columns 0..47
    B = [(combSIZE[j] >> 48) & 0xFFFFFFFF for j in range(48)]
    # Extract D (32x32): crc output from initial crc state
    Dcols = [(combSIZE[48 + m] >> 48) & 0xFFFFFFFF for m in range(32)]
    # const from crc_in = 0xffffffff, then final xor 0xffffffff
    Dconst = apply_map(Dcols, 0xFFFFFFFF)
    rk_const = Dconst ^ 0xFFFFFFFF

    # rk(state) = (B . state) XOR rk_const ; state is a 48-vec (function of seed)
    # Schedule: track state-map S (48 cols, state as func of seed). start S = I.
    S = [1 << j for j in range(48)]
    Mlist = []   # M_i : 32x48 col form, rk_i = M_i.seed XOR rk_const
    for i in range(16):
        # rk[2i] at current S
        Mlist.append(compose_B_S(B, S))
        S = matmul(A, S)            # advance SIZE
        S = matmul(build_T(poly), S)  # skip 1 bit
        Mlist.append(compose_B_S(B, S))
        S = matmul(A, S)            # advance SIZE
    return Mlist, rk_const, A, B

def compose_B_S(B, S):
    # B is 32x48 (cols indexed by state-bit), S is 48x48 (cols indexed by seed-bit, image=state)
    # result M (32x48): M.seed = B.(S.seed). column j (seed bit j) = B applied to S col j
    return [apply_map(B, S[j]) for j in range(48)]

def B_apply(B, v):
    return apply_map(B, v)

# ---------- diagnostics ----------
def rank_gf2(cols, n_rows):
    # cols: list of column ints (each up to n_rows bits). rank over GF(2).
    rows = []
    # convert to row space via the columns as vectors; rank of column space
    basis = []
    for c in cols:
        x = c
        for b in basis:
            x = min(x, x ^ b)
        if x:
            basis.append(x)
            basis.sort(reverse=True)
    return len(basis)

def main():
    random.seed(1234)
    poly = (1 << 47) | random.getrandbits(47)
    print("[*] feedback/poly =", hex(poly))
    Mlist, rk_const, A, B = build_schedule_model(poly)
    print("[*] rk_const =", hex(rk_const))

    # rank of single round-key map B
    print("[*] rank(B) single-rk map (<=32):", rank_gf2(B, 32))

    # Full schedule: stack all M_i columns -> map seed(48) -> 32*32=1024 bits
    # Build combined columns: for seed bit j, the concatenation of all 32 M_i[j] (32 bits each)
    full_cols = []
    for j in range(48):
        v = 0
        for i, M in enumerate(Mlist):
            v |= (M[j] & 0xFFFFFFFF) << (32 * i)
        full_cols.append(v)
    print("[*] rank(full schedule seed->1024) (<=48):", rank_gf2(full_cols, 1024))

    # pairwise equality of round-key MAPS (M_i equal and same const => identical rk always)
    eqs = []
    for i in range(32):
        for k in range(i + 1, 32):
            if Mlist[i] == Mlist[k]:
                eqs.append((i, k))
    print("[*] identical round-key maps (always-equal rk):", eqs)

    # rank of just the FIRST two round keys (64 bits) -> if 48, two rk determine seed
    two = []
    for j in range(48):
        two.append((Mlist[0][j]) | (Mlist[1][j] << 32))
    print("[*] rank(rk0||rk1 -> 64) (<=48):", rank_gf2(two, 64))

    # rank using rk0 and rk31
    two2 = []
    for j in range(48):
        two2.append((Mlist[0][j]) | (Mlist[31][j] << 32))
    print("[*] rank(rk0||rk31 -> 64):", rank_gf2(two2, 64))

if __name__ == "__main__":
    main()
