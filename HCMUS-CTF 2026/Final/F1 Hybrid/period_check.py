"""Period-2 detection: feedback gives alternating (k0,k1) schedule iff the LFSR
transition T satisfies T^N = I  (N = 23738715),  iff  x^N == 1 mod c(x),
where c(x) is the LFSR characteristic polynomial.

T is a companion matrix so char poly = min poly:
  recurrence s_t = sum_{j} poly_j s_{t-1-j}  ->  c(x) = x^48 + sum_j poly_j x^{47-j}
  as integer:  c = (1<<48) | bitreverse48(poly).
Cross-checked here against a direct 48x48 matrix power.
"""
N = 23738715
MASK48 = (1 << 48) - 1

def bitrev48(x):
    r = 0
    for i in range(48):
        if (x >> i) & 1:
            r |= 1 << (47 - i)
    return r

def charpoly(feedback):
    return (1 << 48) | bitrev48(feedback & MASK48)

def _reduce(r, c, degc=48):
    rb = r.bit_length() - 1
    while rb >= degc:
        r ^= c << (rb - degc)
        rb = r.bit_length() - 1
    return r

def _mulmod(a, b, c):
    p = 0
    while b:
        if b & 1:
            p ^= a
        b >>= 1
        a <<= 1
    return _reduce(p, c)

def xpow_mod(e, c):
    # x^e mod c(x)
    result = 1
    base = 2  # polynomial x
    while e:
        if e & 1:
            result = _mulmod(result, base, c)
        base = _mulmod(base, base, c)
        e >>= 1
    return result

def is_period2(feedback):
    return xpow_mod(N, charpoly(feedback)) == 1

# ---- cross check against matrix power for a handful of feedbacks ----
def build_T(poly):
    cols = [0] * 48
    for j in range(48):
        c = 0
        if j <= 46:
            c |= 1 << (j + 1)
        if (poly >> j) & 1:
            c |= 1 << 0
        cols[j] = c
    return cols

def apply_map(cols, v):
    r = 0
    while v:
        j = (v & -v).bit_length() - 1
        r ^= cols[j]
        v &= v - 1
    return r

def matmul(A, B):
    return [apply_map(A, col) for col in B]

def matpow(A, e, n):
    R = [1 << j for j in range(n)]
    base = A
    while e:
        if e & 1:
            R = matmul(base, R)
        e >>= 1
        if e:
            base = matmul(base, base)
    return R

if __name__ == "__main__":
    import random
    ident = [1 << j for j in range(48)]
    # verify poly-check agrees with matrix T^N==I on random + crafted feedbacks
    agree = 0
    tested = 0
    random.seed(7)
    for _ in range(60):
        fb = (1 << 47) | random.getrandbits(47)
        poly_says = is_period2(fb)
        mat_says = (matpow(build_T(fb), N, 48) == ident)
        tested += 1
        if poly_says == mat_says:
            agree += 1
        else:
            print("DISAGREE", hex(fb), poly_says, mat_says)
    print(f"poly-check vs matrix T^N=I : {agree}/{tested} agree")

    # how many period-2 windows in a few random 2048-bit seeds?
    def feedback_from_seed(seed, idx):
        value = 0
        for bit in range(47):
            sb = idx + bit
            byte_idx = len(seed) - 1 - (sb // 8)
            bit_idx = sb % 8
            value |= ((seed[byte_idx] >> bit_idx) & 1) << bit
        return (1 << 47) | value
    for t in range(3):
        seed = bytes(random.getrandbits(8) for _ in range(256))
        hits = [i for i in range(0, 2048 - 47 + 1) if is_period2(feedback_from_seed(seed, i))]
        print(f"seed#{t}: period-2 indices found = {len(hits)} {hits[:5]}")
