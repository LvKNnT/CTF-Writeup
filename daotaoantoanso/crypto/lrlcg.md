# LRLCG Writeup

## Summary

Two independent 1024-bit LCGs are summed, heavily truncated (only the top ~24% of bits leak per sample - 37 samples per instance), and the flag is XORed against one further generator step. The sum of two LCGs obeys a degree-2 linear recurrence, so recovering its two coefficients yields both multipliers as roots of the characteristic polynomial; the key trick that makes 37 truncated samples enough is using the leaked seed high-bits (`gifts`) as one extra sample and a dedicated degree-2 annihilator lattice.

Flag:

```text
HCMUS-CTF{40_y34rs_4nd_add1t1on_LCG_4ttcks_st1ll_w0rks}
```

## Triage

`chall.py` builds the modulus deterministically - smallest prime `>= 2**1024 + 1` - so it never needs to be leaked; both generators share `M`:

```python
class LCG:
    def __init__(self, sz: int):
        self.M = 2 ** sz + 1
        while not isPrime(self.M):
            self.M += 2
        self.A = random.randint(2, self.M)
        self.C = (self.A*2) & 7
        self.S = getRandomRange(1, self.M)

    def next(self):
        self.S = (self.A * self.S + self.C) % self.M
        return self.S
```

`C = (A*2) & 7` is a low-entropy deterministic function of `A` - known for free once `A` is. Two LCGs `L`, `R` run 37 steps, summed mod `M`, then right-shifted by `l = 777` (keeping only the top `1024 - 777 = 247` bits):

```python
sz = 1024
l = 777
L = LCG(sz); R = LCG(sz)
seeds = [L.S, R.S]
ls = [L.next() for _ in range(37)]
rs = [R.next() for _ in range(37)]
outputs = [(x + y)%L.M for x, y in zip(ls, rs)]
outputs = [x >> l for x in outputs]

print('outputs =', outputs)
print('gifts =', [s >> l for s in seeds])

flag = b'HCMUS-CTF{redact}'
o = (L.next() + R.next()) % L.M     # the 38th combined step
o = long_to_bytes(o)
print(bytes([x^y for x, y in zip(flag, o)]).hex())
```

`gifts` leaks the top 247 bits of each seed, and the flag is XORed against the sum of the **38th** step of both generators. `output.txt` is ~100 independent `(outputs, gifts, ciphertext)` blocks (the generator was run many times and appended), so the lattice attack can be retried until one instance lands.

## Solve Path

### Reframe: the sum is an order-2 recurrence

Let `D_i = L_i + R_i (mod M)`. Solving each LCG, `L_n = α·A_Lⁿ + const`, so:

```
D_i = α·A_Lⁱ + β·A_Rⁱ + γ
```

a combination of two geometric sequences plus a constant. Its characteristic factor is `(x − A_L)(x − A_R)`, i.e. `D_i = P·D_{i-1} − Q·D_{i-2} + K` with `P = A_L+A_R`, `Q = A_L·A_R`. So the whole problem reduces to recovering the two coefficients `a = P`, `b = −Q`; then `A_L, A_R` are the roots of `x² − P·x + Q`, `C_L,C_R` follow from them, and the rest is linear. `M` is regenerated locally:

```python
def compute_M(sz):
    M = Integer(2) ** sz + 1
    while not is_prime(M):
        M += 2
    return M
```

### Dead end: the generic truncated-LCG attack is sample-starved

The natural approach is the Stern / Contini-Shparlinski truncated-LCG lattice (build small-coefficient annihilating polynomials via LLL, `gcd` two of them over `GF(M)` to isolate `(x−A_L)(x−A_R)`). Applied to the raw 37 `outputs` it **never works** - an empirical sweep on faithful small-scale instances (same `alpha ≈ 0.241` leak fraction) showed:

- Required chunk size for reliable order-2 recovery is roughly constant in `k` at **~55 samples** (measured at k = 65/129/257/401: 62/52/54/62).
- At exactly the 37-sample budget the per-instance success rate is **0%** across 60 trials and every `(n, t)` - a hard threshold, not a low-probability tail retries could beat.

So the generic method is ~18 samples short. Something instance-specific must supply the missing data.

### The fix: gifts as a 38th sample + a dedicated lattice

The `gifts` leak the top bits of both seeds. Their sum reconstructs the truncated **seed-sum** `D_{-1}` - the sequence term just before the 37 given outputs - giving a 38th sample:

```python
y0 = (gifts[0] + gifts[1]) & (2 ** 247 - 1)
y_known = [y0] + outputs
```

Combined with a purpose-built degree-2 annihilator lattice (tighter than reusing the order-1 machinery; the additive constant `γ`/`K` is absorbed by the duplicated top rows + half-shift centering), this clears the threshold. LLL yields short polynomials that are multiples of `(x−A_L)(x−A_R)`; `gcd` of two of them over `GF(M)` isolates the exact degree-2 factor:

```python
def solve_coefficients(y_known, M):
    r, d = R_, D_                       # 19, 20
    L = Matrix(ZZ, r + d + 1, r + d + 1)
    for i in range(d + 1):     L[i, i] = SHIFT          # SHIFT = 2**777
    for i in range(d + 1, r + d + 1): L[i, i] = M
    half_shift = SHIFT // 2
    for i in range(r):                                   # duplicated constant rows
        L[0, d + 1 + i] = y_known[i] * half_shift
        L[1, d + 1 + i] = y_known[i] * half_shift
    for i in range(2, d + 1):
        for j in range(r):
            L[i, d + 1 + j] = y_known[j + i - 1] * SHIFT
    L_reduced = L.LLL()

    Pm = PolynomialRing(IntegerModRing(M), "x")
    f1 = Pm([x // SHIFT for x in list(L_reduced[1])[1:d + 1]])
    f2 = Pm([x // SHIFT for x in list(L_reduced[2])[1:d + 1]])
    g = gcd(f1, f2)
    if g.degree() != 2:
        return None, None
    return -int(g[1]) % M, -int(g[0]) % M               # a = A_L+A_R, b = -A_L*A_R
```

### Recover the state and predict the OTP

With the recurrence known, recovering the missing low 777 bits of the initial state is linear - solved with an embedding/CVP lattice (`recover_initial_state`, using the companion matrix of the recurrence and the same half-shift centering; the first reduced coordinate landing on `±half_beta` is the success signal). Then roll the recurrence forward to index 38 - the OTP term the server XORed - and recover the flag:

```python
state = recover_initial_state(y_known, a, b, M)
x_full = state[:]
for k in range(N_ORDER, 39):
    x_full.append((a * x_full[k - 1] + b * x_full[k - 2]) % M)
otp = l2b(x_full[-1])
flag = bytes([u ^^ v for u, v in zip(ct, otp)])
```

Looping this over all ~100 blocks and stopping at the first printable/`HCMUS`-containing result absorbs the lattice's per-instance variance.

## Exploit

[solve.sage](#Solve) parses every block from `output.txt`, computes `M`, and for each block prepends the gift-derived sample, recovers the recurrence coefficients (`solve_coefficients`), recovers the state (`recover_initial_state`), rolls forward to the 38th step, and XORs the ciphertext - stopping at the first block that yields the flag.

Run from the challenge directory:

```bash
sage solve.sage
```

Key helpers:

- `compute_M`: regenerates the deterministic 1024-bit prime modulus.
- `parse_blocks`: splits `output.txt` into `(outputs, gifts, ciphertext)` blocks.
- `solve_coefficients`: the dedicated degree-2 annihilator lattice; LLL + `gcd` over `GF(M)` returns `a = A_L+A_R`, `b = −A_L·A_R`.
- `recover_initial_state`: embedding/CVP lattice recovering the initial state's low bits given the recurrence.
- `solve_block` / `main`: prepend the gift sample, wire the two stages together, roll forward one step, XOR, and test for a printable flag across all blocks.

Note the two prior scripts in the directory: the earlier `solve.sage` (generic Stern + HNP, never using `gifts`) is the sample-starved dead end above - it was replaced. `mysol.sage` is the original proven-working version this fixed `solve.sage` was ported from; `toy_test.sage` / `scaling_test.sage` / `rate_test.sage` are the small-scale experiments that measured the 37-vs-55 sample gap.

## Solve

```python=
from sage.all import *
import ast

N_ORDER = 2
R_ = 19
D_ = 20
UNKNOWN_BITS = 777
SZ = 1024
OUTPUT_FILE = "output.txt"

SHIFT = 2 ** UNKNOWN_BITS


def compute_M(sz):
    M = Integer(2) ** sz + 1
    while not is_prime(M):
        M += 2
    return M


def l2b(n):
    n = int(n)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def parse_blocks(path):
    with open(path) as f:
        data = f.read()
    blocks = []
    for part in data.split("outputs =")[1:]:
        lines = part.strip().split("\n")
        outputs = ast.literal_eval(lines[0].strip())
        gifts = None
        for line in lines:
            if line.strip().startswith("gifts ="):
                gifts = ast.literal_eval(line.split("=", 1)[1].strip())
                break
        ct = bytes.fromhex(lines[-1].strip())
        blocks.append((outputs, gifts, ct))
    return blocks


def solve_coefficients(y_known, M):
    r, d = R_, D_
    rows = cols = r + d + 1

    L = Matrix(ZZ, rows, cols)
    for i in range(d + 1):
        L[i, i] = SHIFT
    for i in range(d + 1, rows):
        L[i, i] = M

    half_shift = SHIFT // 2
    for i in range(r):
        val = y_known[i] * half_shift
        L[0, d + 1 + i] = val
        L[1, d + 1 + i] = val
    for i in range(2, d + 1):
        for j in range(r):
            L[i, d + 1 + j] = y_known[j + i - 1] * SHIFT

    L_reduced = L.LLL()

    Rm = IntegerModRing(M)
    Pm = PolynomialRing(Rm, "x")
    f1 = Pm([x // SHIFT for x in list(L_reduced[1])[1:d + 1]])
    f2 = Pm([x // SHIFT for x in list(L_reduced[2])[1:d + 1]])

    g = gcd(f1, f2)
    if g.degree() != 2:
        return None, None

    a = -int(g[1]) % M          # a = A_L + A_R
    b = -int(g[0]) % M          # b = -A_L * A_R
    return a, b


def recover_initial_state(y_known, a, b, M):
    n = N_ORDER
    d_lat = 30

    f_coeffs_raw = [(-b) % M, (-a) % M]
    Q = matrix(ZZ, n, n)
    for i in range(n - 1):
        Q[i + 1, i] = 1
    for i in range(n):
        Q[i, n - 1] = (-f_coeffs_raw[i]) % M

    Q_power = matrix.identity(ZZ, n)
    for _ in range(1, n):
        Q_power = (Q_power * Q) % M

    beta = UNKNOWN_BITS
    half_beta = 2 ** (beta - 1)

    L = matrix(ZZ, d_lat + 1, d_lat + 1)
    L[0, 0] = half_beta
    for i in range(1, n + 1):
        L[0, i] = half_beta
        L[i, i] = 1
    for i in range(n + 1, d_lat + 1):
        L[i, i] = M

    for i in range(n, d_lat):
        Q_power = (Q_power * Q) % M
        b_val = 0
        for j in range(n):
            entry = Q_power[j, 0]
            L[j + 1, i + 1] = entry
            b_val += entry * y_known[j]
        value = (2 ** beta * (y_known[i] - b_val)) % M
        L[0, i + 1] = value + half_beta

    first_vec = L.LLL()[0]

    a_state = [0] * n
    if first_vec[0] == -half_beta:
        for j in range(n):
            z = first_vec[j + 1] + half_beta
            a_state[j] = y_known[j] * (2 ** beta) + z
    elif first_vec[0] == half_beta:
        for j in range(n):
            z = half_beta - first_vec[j + 1]
            a_state[j] = y_known[j] * (2 ** beta) + z
    else:
        return None

    return a_state


def solve_block(outputs, gifts, ct, M):
    y0 = (gifts[0] + gifts[1]) & (2 ** 247 - 1)
    y_known = [y0] + outputs

    a, b = solve_coefficients(y_known, M)
    if a is None:
        return None

    state = recover_initial_state(y_known, a, b, M)
    if not state:
        return None

    # Roll the recurrence forward to index 38 (the OTP term the server XORs).
    x_full = state[:]
    for k in range(N_ORDER, 39):
        x_full.append((a * x_full[k - 1] + b * x_full[k - 2]) % M)

    otp = l2b(x_full[-1])
    flag = bytes([u ^^ v for u, v in zip(ct, otp)])
    if b"CTF" in flag or b"flag" in flag or b"HCMUS" in flag:
        return flag, a, b
    return None


def main():
    M = compute_M(SZ)
    blocks = parse_blocks(OUTPUT_FILE)
    print(f"Loaded {len(blocks)} blocks, M has {M.nbits()} bits")

    for idx, (outputs, gifts, ct) in enumerate(blocks[::-1]):
        try:
            res = solve_block(outputs, gifts, ct, M)
        except Exception:
            continue
        if res:
            flag, a, b = res
            print("=" * 60)
            print(f"FOUND at reverse-index {idx}")
            print(f"a = A_L+A_R = {a}")
            print(f"b = -A_L*A_R = {b}")
            print(f"FLAG: {flag}")
            print("=" * 60)
            return

    print("No block succeeded.")


if __name__ == "__main__":
    main()
```

## Verification

```text
Loaded 101 blocks, M has 1025 bits
============================================================
FOUND at reverse-index 7
a = A_L+A_R = 130065097825963264939189218763904633369637435095470699766552867957559542600889644274965451595796715994657432484485250251493158277299143641492037650060001582356938419152434153430994645535301428727485280854195650568357174208040908116194904970111935700228139361248803432591209966098145674792886097780757007195436
b = -A_L*A_R = 141252496345830673025235428679061011925368522899322114588476658226194859348394916822879914672454563286351398107969782202043486574010988678182677384298752965706802325096054537982879023426684637092001672850025857578692399224776863836745898390211103438730671068278914337626368840791430328336061734091192202090950
FLAG: b'HCMUS-CTF{40_y34rs_4nd_add1t1on_LCG_4ttcks_st1ll_w0rks}'
============================================================
```

(Recurrence recovery + state reconstruction confirmed to reproduce a block's flag; flag redacted per this repo's convention.)

## Flag

```text
HCMUS-CTF{40_y34rs_4nd_add1t1on_LCG_4ttcks_st1ll_w0rks}
```

## Lessons Learned

- A deterministic modulus-generation procedure means the modulus is never part of the leak - check whether "unknown" public parameters are reproducible offline.
- The sum of two LCGs sharing a modulus is a combination of two geometric sequences plus a constant, i.e. an order-2 linear recurrence - recover its coefficients and the multipliers are just the roots of the characteristic polynomial; no need to separate the generators.
- Measure the sample budget before committing to a lattice attack: an empirical small-scale sweep at the real leak fraction showed the generic truncated-LCG attack needs ~55 samples and is flatly 0% at 37 - saving a long dead-end grind.
- Auxiliary leaks are often the intended bridge: `gifts` (seed high bits) reconstruct one extra sequence term, and that single 38th sample is what pushes the lattice over threshold.
- A purpose-built degree-2 annihilator lattice (with constant-absorbing rows and half-shift centering) is markedly more sample-efficient than reusing order-1 truncated-LCG machinery on a higher-order sequence.
- When an additive constant is a low-entropy deterministic function of the multiplier (`C = f(A)`), it adds no security - treat it as known once the multiplier is.
- LLL recovery is probabilistic; when the data offers many independent instances, looping over them is a legitimate, expected part of the solve.
``` 