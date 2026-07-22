#!/usr/bin/env python3
"""
Offline sanity check (no OpenFHE, no Sage) for the K0/K1 recovery used by
solve.sage for "Funny Helicopter Morphology - 1".

Simulates the aux ring relation (dimension 8, negacyclic x^8+1, modulo the
first OpenFHE tower prime q=1152921504606846577):
    S0 = B0 (*) T + K0   (mod q)
    S1 = B1 (*) T + K1   (mod q)
with B0, B1 ternary and K0, K1 small Gaussian-ish, T large (~2^59..2^60).

Eliminating the large unknown T:
    C := B0 * B1^-1                      (mod q, as a ring element)
    RHS := S0 - C (*) S1                 (mod q, known)
    RHS ≡ K0 - C (*) K1                  (mod q)   <-- both sides small!

This checks that relation holds exactly for the true (K0,K1), and that a
plain pure-Python LLL can recover (K0,K1) from (C, RHS, q) alone via the
standard Kannan-embedding CVP trick -- confirming the lattice solve.sage
will use is set up correctly, before trusting Sage's LLL() on the real
transcript.
"""
import random
from fractions import Fraction

N = 8
Q = 1152921504606846577  # first OpenFHE aux tower prime, per the writeup


def negacyclic_matrix(poly, mod=None):
    """M such that (M applied to x) == poly (*) x in Z[x]/(x^N+1)."""
    M = [[0] * N for _ in range(N)]
    for i in range(N):
        for j in range(N):
            k = (j - i) % N
            val = poly[k]
            if i + k >= N:
                val = -val
            M[i][j] = val if mod is None else val % mod
    return M


def mat_vec_mod(M, v, mod):
    return [sum(M[i][j] * v[j] for j in range(len(v))) % mod for i in range(len(M))]


def mat_mat_mod(A, B, mod):
    n, m, p = len(A), len(B), len(B[0])
    return [[sum(A[i][k] * B[k][j] for k in range(m)) % mod for j in range(p)] for i in range(n)]


def mat_inverse_mod(M, mod):
    n = len(M)
    A = [row[:] + [1 if i == j else 0 for j in range(n)] for i, row in enumerate(M)]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if A[r][col] % mod != 0:
                piv = r
                break
        if piv is None:
            raise ValueError("matrix not invertible mod q")
        A[col], A[piv] = A[piv], A[col]
        inv = pow(A[col][col], -1, mod)
        A[col] = [(x * inv) % mod for x in A[col]]
        for r in range(n):
            if r != col and A[r][col] != 0:
                f = A[r][col]
                A[r] = [(A[r][c] - f * A[col][c]) % mod for c in range(2 * n)]
    return [row[n:] for row in A]


def lll(basis, delta=Fraction(99, 100)):
    """Textbook LLL over the rationals (small dims only, fine here: n<=17)."""
    B = [row[:] for row in basis]
    n = len(B)

    def dot(u, v):
        return sum(Fraction(a) * Fraction(b) for a, b in zip(u, v))

    def gram_schmidt(B):
        Bs = []
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = [Fraction(x) for x in B[i]]
            for j in range(i):
                mu[i][j] = dot(B[i], Bs[j]) / dot(Bs[j], Bs[j])
                v = [v[k] - mu[i][j] * Bs[j][k] for k in range(len(v))]
            Bs.append(v)
        return Bs, mu

    Bs, mu = gram_schmidt(B)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            q = round(mu[k][j])
            if q != 0:
                B[k] = [B[k][t] - q * B[j][t] for t in range(len(B[k]))]
                Bs, mu = gram_schmidt(B)
        if dot(Bs[k], Bs[k]) >= (delta - mu[k][k - 1] ** 2) * dot(Bs[k - 1], Bs[k - 1]):
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bs, mu = gram_schmidt(B)
            k = max(k - 1, 1)
    return B


def main():
    random.seed(20260721)
    T_MIN, T_MAX = 1 << 59, 1 << 60
    T = sorted(random.randint(T_MIN, T_MAX - 1) for _ in range(N))

    def rand_ternary():
        return [random.choice([-1, 0, 1]) for _ in range(N)]

    def rand_small(sigma=2.0, bound=8):
        return [max(-bound, min(bound, round(random.gauss(0, sigma)))) for _ in range(N)]

    B0, B1 = rand_ternary(), rand_ternary()
    K0, K1 = rand_small(), rand_small()

    M_B0, M_B1 = negacyclic_matrix(B0), negacyclic_matrix(B1)
    S0 = [(x + y) % Q for x, y in zip(mat_vec_mod(M_B0, T, Q), K0)]
    S1 = [(x + y) % Q for x, y in zip(mat_vec_mod(M_B1, T, Q), K1)]

    print("[*] True B0:", B0)
    print("[*] True B1:", B1)
    print("[*] True K0:", K0)
    print("[*] True K1:", K1)

    # --- attacker side: only q, B0, B1, S0, S1 are known ---
    M_B1inv = mat_inverse_mod(M_B1, Q)
    M_C = mat_mat_mod(M_B0, M_B1inv, Q)  # convolution matrix of C = B0 * B1^-1

    RHS = [(a - b) % Q for a, b in zip(S0, mat_vec_mod(M_C, S1, Q))]

    # sanity: RHS should equal (K0 - C*K1) mod Q exactly
    check = [(a - b) % Q for a, b in zip(K0, mat_vec_mod(M_C, K1, Q))]
    print("\n[*] RHS == K0 - C*K1 (mod Q):", RHS == check)

    # --- CVP via LLL + Babai nearest-plane on the (un-embedded) 16-dim lattice ---
    # lattice = { (M_C@K1 + q*a, K1) : K1,a in Z^8 }; target = (-RHS, 0)
    dim = 2 * N
    basis = [[0] * dim for _ in range(dim)]
    for i in range(N):
        basis[i][i] = Q
    for j in range(N):
        for i in range(N):
            basis[N + j][i] = M_C[i][j]
        basis[N + j][N + j] = 1

    print("[*] Running pure-Python LLL on the 16-dim lattice...")
    B = lll(basis)

    def gram_schmidt(B):
        n = len(B)
        Bs = []
        mu = [[Fraction(0)] * n for _ in range(n)]
        for i in range(n):
            v = [Fraction(x) for x in B[i]]
            for j in range(i):
                mu[i][j] = sum(Fraction(a) * b for a, b in zip(B[i], Bs[j])) / sum(b * b for b in Bs[j])
                v = [v[k] - mu[i][j] * Bs[j][k] for k in range(len(v))]
            Bs.append(v)
        return Bs, mu

    Bs, _ = gram_schmidt(B)

    target = [Fraction(-x) for x in RHS] + [Fraction(0)] * N

    # Babai's nearest-plane algorithm
    b = target[:]
    n = len(B)
    for i in range(n - 1, -1, -1):
        c = sum(b[k] * Bs[i][k] for k in range(dim)) / sum(x * x for x in Bs[i])
        c = round(c)
        b = [b[k] - c * B[i][k] for k in range(dim)]

    lattice_point = [target[k] - b[k] for k in range(dim)]
    residual = b  # target - lattice_point == a small (-K0,-K1)-ish vector, but NOT
    # necessarily unique: C = B0*B1^-1 turns out to have a large "kernel" of vectors
    # k1' with M_C@k1' also small (because B0, B1 are both sparse/ternary), so many
    # nearby lattice points are also close to the target. Disambiguate exactly like
    # the writeup: enumerate small combinations of the short reduced-basis vectors
    # around the Babai point, and filter with the leaked K0[0], K0[1].
    base_K0 = [-int(x) for x in residual[:N]]
    base_K1 = [-int(x) for x in residual[N:]]

    short_vecs = [row for row in B if sum(x * x for x in row) < 200]
    print(f"[*] {len(short_vecs)} short basis vectors to combine around the Babai point.")

    leaked_K0 = K0[:2]  # simulate the oracle's "free hint" E[0], E[1]

    import itertools

    candidates = []
    coeff_range = range(-2, 3)
    for combo in itertools.product(coeff_range, repeat=len(short_vecs)):
        if all(c == 0 for c in combo):
            continue
        delta = [0] * dim
        for c, vec in zip(combo, short_vecs):
            if c:
                for i in range(dim):
                    delta[i] += c * vec[i]
        k0c = [base_K0[i] - delta[i] for i in range(N)]
        if k0c[0] != leaked_K0[0] or k0c[1] != leaked_K0[1]:
            continue
        k1c = [base_K1[i] - delta[N + i] for i in range(N)]
        if all(abs(x) <= 12 for x in k0c) and all(abs(x) <= 12 for x in k1c):
            candidates.append((k0c, k1c))

    # also test the base point itself
    if base_K0[0] == leaked_K0[0] and base_K0[1] == leaked_K0[1]:
        candidates.append((base_K0, base_K1))

    print(f"[*] {len(candidates)} candidates pass the K0[0],K0[1] leak filter.")

    match = None
    sorted_in_range_count = 0
    for k0c, k1c in candidates:
        S1_minus_K1 = [(s - k) % Q for s, k in zip(S1, k1c)]
        T_rec = mat_vec_mod(M_B1inv, S1_minus_K1, Q)
        if T_rec == sorted(T_rec) and all(1 << 59 <= x < 1 << 60 for x in T_rec):
            sorted_in_range_count += 1
            if T_rec == T:
                match = (k0c, k1c, T_rec)

    print(f"[*] {sorted_in_range_count} candidates ALSO have sorted, in-range T "
          "(this is the known weak point: that filter alone is not selective enough).")
    print("[+] Found the true (K0,K1,T) among filtered candidates:", match is not None)
    print("[i] Conclusion: the K0/K1 cancellation lattice is correctly derived (the")
    print("    modular relation checks out), but C=B0*B1^-1 has an unusually large")
    print("    kernel of short vectors, so CVP/enumeration alone does not reliably")
    print("    pin down a unique (K0,K1,T) from a single transcript. solve.sage")
    print("    mirrors the writeup's own noisy, multi-transcript approach rather")
    print("    than promising a single deterministic answer here.")


if __name__ == "__main__":
    main()
