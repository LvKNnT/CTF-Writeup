# Matrix Mixing Writeup

## Summary

The server hides 32 secret integers on the diagonal of a matrix, then repeatedly conjugates/multiplies it by random orthogonal "mixing" matrices over `GF(p)` before printing the scrambled result - but orthogonal conjugation preserves eigenvalues (up to a shared additive shift), so the eigenvalues of `M*M^T` still encode every secret up to two unknown constants. The challenge awards two separate flags depending on how many guess attempts are used, so this writeup has two parts.

Flag (Part 1):

```text
HCMUS-CTF{15_tHI5_cOVARiaNC3_m4tRIx?}
```

Flag (Part 2):

```text
HCMUS-CTF{5iN6UL4r_va1u3_dEc0MPOSiTION_4Nd_L4t7Ic3_rEduct1On_4R3_w3irD}
```

## Triage

`chal.py` (the deployed version; `chal.sage` is an earlier prototype of the same math without the interactive guess/flag logic) builds `n = 32` secrets, a 256-bit prime `p = 4k+3` (chosen so modular square roots are `pow(x, (p+1)//4, p)`), and starts from a diagonal matrix of the secrets:

```python
n = 32
secret = [randint(1,2**100 - 1) for _ in range(n)]
secret.sort()

p = get_prime(256)
mat = get_diag(secret)
idmat = get_idmat(n)

for _ in range(64):
    mixer = gen_mix(n, p)
    mat = mat_add(mat_mul_3(mixer, mat, transpose(mixer), p=p), get_diag([randint(1, p - 1)] * n), p)
for _ in range(64):
    mat = mat_mul_3(gen_mix(n, p), mat, gen_mix(n, p), p=p)
mat = mat_scale(mat, randint(1, p - 1), p)
```

`gen_mix` builds a Givens-rotation-style orthogonal matrix (`c^2 + s^2 = 1 mod p`, embedded as identity except at two rows/columns):

```python
def gen_mix(n: int, p: int) -> Matrix:
    while True:
        c = randint(1, p - 1)
        s2 = (1 - c ** 2) % p
        if pow(s2, (p-1)//2, p) != 1:
            continue
        s = pow(s2, (p+1)//4, p)
        break
    mix = get_idmat(n)
    i = randint(0, n - 1)
    j = randint(0, n - 2)
    j += j >= i
    mix[i][i] = mix[j][j] = c
    mix[i][j] = -s
    mix[j][i] = s
    return mix
```

The server prints `p`, `secret[0]` ("a little hint"), and the final scrambled matrix, then asks for a guess of the full secret vector:

```python
print(p)
print(secret[0])
print_mat(mat)

def guess():
    your_guess = list(map(int, input("Gimme your guess: ").split(',')))
    return len(your_guess) == len(secret) and all(a == b for a, b in zip(your_guess, secret))

if guess():
    # flag_2.txt
else:
    print(secret[1])  # second hint
    if guess():
        # flag_1.txt
```

Guessing correctly on the very first try (using only `secret[0]`) yields `flag_2.txt`; guessing correctly on the second try (after the `secret[1]` hint is revealed) yields `flag_1.txt`. So the harder, single-hint path is the bonus flag.

## Solve Path

Phase 1 conjugates the diagonal matrix by an orthogonal `mixer` (`mixer^T == mixer^-1`) and adds `r*I` for a random `r` each round - orthogonal similarity preserves eigenvalues, and each round shifts every eigenvalue by the same scalar. So after phase 1, the matrix is symmetric with eigenvalues `secret_k + R`, where `R` is the sum of all 64 random shifts. Phase 2 replaces conjugation with independent left/right orthogonal multiplication (`U * D * V`), which does not preserve the eigenvalues of `D` itself, but does preserve the eigenvalues of `D*D^T` up to conjugation:

```text
(U D V)(U D V)^T = U D (V V^T) D^T U^T = U D^2 U^-1
```

since `D` is symmetric and `V V^T = U^T U = I`. The same argument extends across all 64 rounds (products of orthogonal matrices stay orthogonal) and through the final scalar multiply. So the 32 eigenvalues of `M*M^T` are exactly:

```text
e_k = scale^2 * (secret_k + R)^2   (mod p)
```

for unknown `scale`, `R`. Both parts start identically - compute `S = M*M^T` and its characteristic polynomial's roots:

```python
Fp = GF(p)
M = Matrix(Fp, n, n, rows)
S = M * M.transpose()

charpoly = S.characteristic_polynomial()
roots = charpoly.roots(multiplicities=True)
evs = []
for r, mult in roots:
    evs.extend([r] * mult)
assert len(evs) == n
```

### Part 1: two known secrets (`secret[0]` and `secret[1]`)

`solve.sage` burns the first guess deliberately to unlock the `secret[1]` hint, then has two knowns against two unknowns (`A = scale^2`, `R`). For a guessed pairing `(e_i -> secret[0], e_j -> secret[1])`, `e_i = A*(s0+R)^2` and `e_j = A*(s1+R)^2` combine into a single quadratic in `R`:

```python
a_coef = ei - ej
b_coef = 2 * (ei * s1 - ej * s0)
c_coef = ei * s1 * s1 - ej * s0 * s0
disc = b_coef * b_coef - 4 * a_coef * c_coef
if disc.is_square():
    sq = disc.sqrt()
    R_candidates = [(-b_coef + sq) / (2 * a_coef), (-b_coef - sq) / (2 * a_coef)]
```

For each candidate `R`, `A = e_i / (s0+R)^2` is fixed, and every other eigenvalue is inverted back to a secret by taking a square root and picking whichever of `+-sqrt(e_k/A) - R` lands in `[1, 2^100)`:

```python
for ek in evs:
    val = ek / A
    if not val.is_square():
        ok = False; break
    sq_val = val.sqrt()
    valid = [Integer(c) for c in (sq_val - R, -sq_val - R) if 1 <= Integer(c) < 2**100]
    if len(valid) != 1:
        ok = False; break
    secrets_found.append(valid[0])
```

The full 32-secret vector is only accepted once it self-consistently reproduces both `secret[0]` and `secret[1]` - brute-forcing `(i, j)` over `32*31` pairs is cheap and the smallness check disambiguates false candidates.

### Part 2: only `secret[0]` known, must guess correctly on the first try

`solve_flag2.sage` cannot burn a guess for a second hint, so it needs another trick to pin down `R` from a single known secret. Guessing which eigenvalue `e_{i0}` maps to `secret[0]`, every other eigenvalue's ratio to `e_{i0}` is a perfect square `t_k^2` (since both are of the form `A*(x+R)^2`), giving a relation linear in the single shared unknown `R`:

```text
secret_k + R = +-t_k * (secret[0] + R)
=> secret_k = (+-t_k)*secret[0] + ((+-t_k) - 1) * R        (*)
```

Two such relations for two other indices `k1, k2` (each with a guessed sign) eliminate `R` by cross-multiplication, collapsing to one linear congruence in the two small unknowns `secret_k1, secret_k2`:

```python
K = m2 * c1 - m1 * c2
A1 = m1 / m2
A0 = K / m2
```

This is solved as a small-solution-to-a-linear-congruence problem via 2D lattice reduction plus Babai rounding around a small neighborhood (not just the single nearest point):

```python
B = Matrix(ZZ, [[1, Integer(A1)], [0, Integer(p)]])
Bred = B.LLL()
target = vector(QQ, [0, -Integer(A0)])
coeffs = target * Bred.change_ring(QQ).inverse()
base = [round(c) for c in coeffs]
for d0 in range(-radius, radius + 1):
    for d1 in range(-radius, radius + 1):
        c = vector(ZZ, [base[0] + d0, base[1] + d1])
        v = c * Bred + shift
        ...
```

`debug_flag2.sage` explains why a plain nearest-point Babai rounding was not enough: the relation has a built-in spurious solution at `x1 = x2 = secret[0]` (forcing `R = -secret[0]`, which trivially satisfies the equation for *any* `t_k`), and since `secret[0]` is the smallest of the 32 secrets, that trivial point often sits closer to the origin than the true `(secret_k1, secret_k2)` point - the diagnostic script confirmed the true point is only a handful of reduced-basis steps away from the naive rounding, motivating the neighborhood search used in the final solve. Every `(i0, k1, k2, sign)` guess (`~60k` combinations) is only expensive-verified across all 32 secrets once its cheap 2-unknown step already looks plausible, so a wrong guess just wastes time rather than producing a false positive.

## Exploit

[solve.sage](#Solve-1) recovers the flag that requires two guesses: it connects to the service, deliberately submits a wrong first guess to unlock `secret[1]`, computes the eigenvalues of `M*M^T`, brute-forces the `(A, R)` quadratic over eigenvalue pairs, inverts every eigenvalue back to a secret, and sends the recovered vector as the second guess.

[solve_flag2.sage](#Solve-2) recovers the bonus flag that requires a correct answer on the very first guess: same eigenvalue setup, but it brute-forces `(i0, k1, k2, sign)` combinations, solves a 2D lattice/CVP problem for `R`, verifies the full 32-secret candidate, and sends it as the first (and only) guess.

Run:

```bash
sage solve.sage
sage solve_flag2.sage
```

Key helpers:

- `recv_matrix`: parses `p`, `secret[0]`, and the 32x32 matrix rows from the socket.
- `recover_secrets` (`solve.sage`): brute-forces `(i, j)` eigenvalue pairings, solves the `R` quadratic from `secret[0]`/`secret[1]`, and inverts every eigenvalue.
- `sqrt_mod` (`solve.sage`): `p % 4 == 3` fast modular square root.
- `recover_secrets_single_hint` (`solve_flag2.sage`): brute-forces `(i0, k1, k2, sign)` and drives the single-hint recovery.
- `solve_small_pair_candidates` (`solve_flag2.sage`): 2D lattice-reduction + Babai-neighborhood search for the small `(secret_k1, secret_k2)` solution.
- `verify_full` (`solve_flag2.sage`): reconstructs and validates the entire 32-secret candidate before trusting it.

## Solve 1

```python=
from pwn import *

context.log_level = "error"

HOST = ???
PORT = ???

n = 32


def recv_matrix(io):
    p = int(io.recvline())
    s0 = int(io.recvline())
    rows = []
    for _ in range(n):
        line = io.recvline().decode().strip()
        rows.append([int(x) for x in line.split(',')])
    return p, s0, rows


def sqrt_mod(val, p):
    # p % 4 == 3, so square roots (when they exist) are val^((p+1)/4)
    r = pow(int(val), (int(p) + 1) // 4, int(p))
    if (r * r) % int(p) != int(val) % int(p):
        return None
    return r


def recover_secrets(evs, p, s0, s1):
    Fp = GF(p)
    evs = [Fp(e) for e in evs]
    s0, s1 = Fp(s0), Fp(s1)

    for i in range(len(evs)):
        for j in range(len(evs)):
            if i == j:
                continue
            ei, ej = evs[i], evs[j]

            a_coef = ei - ej
            b_coef = 2 * (ei * s1 - ej * s0)
            c_coef = ei * s1 * s1 - ej * s0 * s0

            if a_coef == 0:
                if b_coef == 0:
                    continue
                R_candidates = [-c_coef / b_coef]
            else:
                disc = b_coef * b_coef - 4 * a_coef * c_coef
                if not disc.is_square():
                    continue
                sq = disc.sqrt()
                R_candidates = [(-b_coef + sq) / (2 * a_coef),
                                (-b_coef - sq) / (2 * a_coef)]

            for R in R_candidates:
                denom = s0 + R
                if denom == 0:
                    continue
                A = ei / (denom * denom)
                if A == 0:
                    continue

                secrets_found = []
                ok = True
                for ek in evs:
                    val = ek / A
                    if not val.is_square():
                        ok = False
                        break
                    sq_val = val.sqrt()

                    valid = []
                    for cand in (sq_val - R, -sq_val - R):
                        ci = Integer(cand)
                        if 1 <= ci < 2**100:
                            valid.append(ci)
                    if len(valid) != 1:
                        ok = False
                        break
                    secrets_found.append(valid[0])

                if not ok or len(secrets_found) != n:
                    continue

                secrets_found.sort()
                if secrets_found[0] == Integer(s0) and secrets_found[1] == Integer(s1):
                    return secrets_found

    return None


def main():
    io = remote(HOST, PORT)

    p, s0, rows = recv_matrix(io)
    print("p =", p)
    print("secret[0] =", s0)

    Fp = GF(p)
    M = Matrix(Fp, n, n, rows)
    S = M * M.transpose()

    charpoly = S.characteristic_polynomial()
    roots = charpoly.roots(multiplicities=True)
    evs = []
    for r, mult in roots:
        evs.extend([r] * mult)
    assert len(evs) == n, f"expected {n} eigenvalues in GF(p), got {len(evs)}"

    io.recvuntil(b"Gimme your guess: ")
    io.sendline(','.join(['1'] * n).encode())

    io.recvline()  
    s1 = int(io.recvline())
    print("secret[1] =", s1)

    secrets = recover_secrets(evs, p, s0, s1)
    if secrets is None:
        print("failed to recover secrets")
        print(io.recvall(timeout=5).decode(errors="replace"))
        return

    print("recovered secrets:", secrets)

    io.recvuntil(b"Gimme your guess: ")
    io.sendline(','.join(str(x) for x in secrets).encode())

    print(io.recvall(timeout=5).decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## Solve 2
```python=
from pwn import *

context.log_level = "error"

HOST = ???
PORT = ???

n = 32
BOUND = 2**100


def recv_matrix(io):
    p = int(io.recvline())
    s0 = int(io.recvline())
    rows = []
    for _ in range(n):
        line = io.recvline().decode().strip()
        rows.append([int(x) for x in line.split(',')])
    return p, s0, rows


def recover_secrets_two_hint(evs, p, s0, s1):
    Fp = GF(p)
    evs = [Fp(e) for e in evs]
    s0f, s1f = Fp(s0), Fp(s1)

    for i in range(len(evs)):
        for j in range(len(evs)):
            if i == j:
                continue
            ei, ej = evs[i], evs[j]
            a_coef = ei - ej
            b_coef = 2 * (ei * s1f - ej * s0f)
            c_coef = ei * s1f * s1f - ej * s0f * s0f

            if a_coef == 0:
                if b_coef == 0:
                    continue
                R_candidates = [-c_coef / b_coef]
            else:
                disc = b_coef * b_coef - 4 * a_coef * c_coef
                if not disc.is_square():
                    continue
                sq = disc.sqrt()
                R_candidates = [(-b_coef + sq) / (2 * a_coef),
                                (-b_coef - sq) / (2 * a_coef)]

            for R in R_candidates:
                denom = s0f + R
                if denom == 0:
                    continue
                A = ei / (denom * denom)
                if A == 0:
                    continue

                secrets_found = []
                ok = True
                for ek in evs:
                    val = ek / A
                    if not val.is_square():
                        ok = False
                        break
                    sq_val = val.sqrt()
                    valid = []
                    for cand in (sq_val - R, -sq_val - R):
                        ci = Integer(cand)
                        if 1 <= ci < BOUND:
                            valid.append(ci)
                    if len(valid) != 1:
                        ok = False
                        break
                    secrets_found.append(valid[0])

                if not ok or len(secrets_found) != n:
                    continue

                if Integer(s0) in secrets_found and Integer(s1) in secrets_found:
                    return secrets_found, R, A

    return None, None, None


def closest_lattice_point(Bred, target):
    Bq = Bred.change_ring(QQ)
    coeffs = target * Bq.inverse()
    rounded = vector(ZZ, [round(c) for c in coeffs])
    return rounded * Bred, coeffs


def solve_small_pair(A1, A0, p):
    B = Matrix(ZZ, [[1, Integer(A1)], [0, Integer(p)]])
    Bred = B.LLL()
    target = vector(QQ, [0, -Integer(A0)])
    w, coeffs = closest_lattice_point(Bred, target)
    v = w + vector(ZZ, [0, Integer(A0)])
    return int(v[0]), int(v[1]), Bred, coeffs


def exact_coeffs_for_point(Bred, A0, x2_true, x1_true):
    w_true = vector(QQ, [x2_true, x1_true - Integer(A0)])
    Bq = Bred.change_ring(QQ)
    coeffs_true = w_true * Bq.inverse()
    return coeffs_true


def solve_small_pair_neighborhood(A1, A0, p, radius, bound):
    B = Matrix(ZZ, [[1, Integer(A1)], [0, Integer(p)]])
    Bred = B.LLL()
    target = vector(QQ, [0, -Integer(A0)])
    Bq = Bred.change_ring(QQ)
    coeffs = target * Bq.inverse()
    base = [round(c) for c in coeffs]

    shift = vector(ZZ, [0, Integer(A0)])
    candidates = []
    for d0 in range(-radius, radius + 1):
        for d1 in range(-radius, radius + 1):
            c = vector(ZZ, [base[0] + d0, base[1] + d1])
            v = c * Bred + shift
            x2, x1 = int(v[0]), int(v[1])
            if -bound < x1 < bound and -bound < x2 < bound:
                candidates.append((x2, x1))
    return candidates


def main():
    io = remote(HOST, PORT)

    p, s0, rows = recv_matrix(io)
    print("p =", p)
    print("secret[0] =", s0)

    Fp = GF(p)
    M = Matrix(Fp, n, n, rows)
    S = M * M.transpose()

    charpoly = S.characteristic_polynomial()
    roots = charpoly.roots(multiplicities=True)
    evs_elems = []
    for r, mult in roots:
        evs_elems.extend([r] * mult)
    print("num eigenvalues in GF(p):", len(evs_elems))
    assert len(evs_elems) == n

    io.recvuntil(b"Gimme your guess: ")
    io.sendline(','.join(['1'] * n).encode())
    io.recvline()
    s1 = int(io.recvline())
    print("secret[1] =", s1)

    secrets_true, R_true, A_true = recover_secrets_two_hint(evs_elems, p, s0, s1)
    if secrets_true is None:
        print("ground-truth double-hint recovery FAILED -- something else is wrong")
        io.close()
        return

    print("ground truth R =", R_true)
    print("ground truth A =", A_true)
    print("ground truth secrets (sorted):", sorted(int(x) for x in secrets_true))

    # step 1: sanity check e_k == A*(secret_k+R)^2 for all k, and find each
    # secret's position in evs_elems (evs_elems is NOT in secret order)
    Fp_R, Fp_A = R_true, A_true
    pos_of_value = {}
    for idx, ek in enumerate(evs_elems):
        val = ek / Fp_A
        assert val.is_square(), f"idx {idx}: e_k/A is not a square!"
        sq_val = val.sqrt()
        cands = []
        for cand in (sq_val - Fp_R, -sq_val - Fp_R):
            ci = Integer(cand)
            if 1 <= ci < BOUND:
                cands.append(ci)
        assert len(cands) == 1, f"idx {idx}: ambiguous or no small candidate: {cands}"
        pos_of_value[int(cands[0])] = idx
    print("step 1 OK: every eigenvalue maps back to exactly one small secret")

    i0_true = pos_of_value[int(s0)]
    print("i0_true (index of secret[0] in evs_elems) =", i0_true)

    s0f = Fp(s0)
    e_i0 = evs_elems[i0_true]

    # step 2/3: pick two OTHER secret values, find their index, their true
    # sign, and check the linear relation exactly
    other_secret_values = [v for v in secrets_true if v != Integer(s0)][:2]
    print("testing k1,k2 for true secrets:", other_secret_values)

    info = []
    for sv in other_secret_values:
        k = pos_of_value[int(sv)]
        ek = evs_elems[k]
        ratio = ek / e_i0
        is_sq = ratio.is_square()
        print(f"  secret={sv} idx={k} ratio.is_square()={is_sq}")
        if not is_sq:
            print("  !! ratio is not a square -- step 2/3 FAILS here")
            io.close()
            return
        t_k = ratio.sqrt()
        lhs = Fp(sv) + Fp_R
        rhs_plus = t_k * (s0f + Fp_R)
        rhs_minus = -t_k * (s0f + Fp_R)
        if lhs == rhs_plus:
            sign = 1
        elif lhs == rhs_minus:
            sign = -1
        else:
            print("  !! neither sign matches -- relation (*) is WRONG")
            io.close()
            return
        print(f"  sign = {sign} (relation verified exactly)")
        m = sign * t_k - 1
        c = sign * t_k * s0f
        # check secret = c + m*R
        check = c + m * Fp_R
        print(f"  c + m*R == secret ? {check == Fp(sv)}")
        info.append((k, t_k, sign, m, c, sv))

    print("step 2/3 OK: linear relation (*) holds exactly for the true sign")

    # step 3: build the pair congruence from these two TRUE (m,c) and see if
    # solve_small_pair recovers the true (x1,x2)
    (k1, t1, s1sign, m1, c1, sv1) = info[0]
    (k2, t2, s2sign, m2, c2, sv2) = info[1]

    K = m2 * c1 - m1 * c2
    A1 = m1 / m2
    A0 = K / m2

    x2, x1, Bred, coeffs = solve_small_pair(A1, A0, p)
    print(f"solve_small_pair recovered x1={x1}, x2={x2}")
    print(f"true values:            x1={int(sv1)}, x2={int(sv2)}")
    print("MATCH!" if (x1 == int(sv1) and x2 == int(sv2)) else "MISMATCH -- checking why below")

    print("naive rounded coeffs:", [float(c) for c in coeffs])
    coeffs_true = exact_coeffs_for_point(Bred, A0, int(sv2), int(sv1))
    print("EXACT coeffs of true point:", [float(c) for c in coeffs_true])
    print("offset (true - naive rounding):",
          [float(coeffs_true[i] - round(coeffs[i])) for i in range(2)])

    w_triv = vector(QQ, [Integer(s0), Integer(s0) - Integer(A0)])
    Bq = Bred.change_ring(QQ)
    coeffs_triv = w_triv * Bq.inverse()
    print("coeffs of trivial (s0,s0) point:", [float(c) for c in coeffs_triv])

    for radius in (5, 10, 20, 40):
        cands = solve_small_pair_neighborhood(A1, A0, p, radius, BOUND)
        hit = (int(sv2), int(sv1)) in cands
        print(f"radius={radius}: {len(cands)} candidates in bound, "
              f"true pair found = {hit}")
        if hit:
            break

    io.close()


if __name__ == "__main__":
    main()
```

## Verification

### 1
```text
p = 93878836076802123723928272464619466886926053388470353495638928067527834362871
secret[0] = 112393206871753067142146622618
secret[1] = 150651156718611351673780231187
recovered secrets: [112393206871753067142146622618, 150651156718611351673780231187, 161938505202297335555912455442, 167850158358965823738774234014, 207840324999766336803043551516, 225877389886899909288599770822, 236151377104385391208945605776, 333763786159995454406808980778, 391440988385976458101477160538, 412993544084353358009671527839, 417129599073006969566296065983, 420680415000170946592385049310, 501432605659112212442060162870, 611019110042498778257780437650, 670249378971538719348084072262, 787853618017455020241079207784, 820047223194240571343379270237, 842157364119933669878724576312, 875760364729125592450096988274, 883250403723814028646289235523, 942250023621890053372283767791, 945835625082615328107605990782, 967356815179232955014353120421, 985411589425610376940100994253, 1015391281675958526945763146469, 1061929742036664551974241264487, 1097070965883381952500529665148, 1138032879732289593951618355686, 1184838719319599837411971553228, 1194105147376609475548065566784, 1230936408889134628289422324926, 1232678944113439040752176746674]
Great!! Here is your flag
HCMUS-CTF{15_tHI5_cOVARiaNC3_m4tRIx?}
```

### 2
```text=
p = 111212703769106633884519382991136517003826154082070082864284893741094895712807
secret[0] = 22013101787901346932546203876
solving for R (this brute forces ~60k (i0,pair,sign) combos, may take a bit)...
recovered secrets: [22013101787901346932546203876, 32353656833032806475328979128, 46468354242714947183928640751, 92176539413777481556799717539, 92678750451689309935262059289, 122906152645863096266200469291, 158319220984012239409120522193, 184515353403089046885723488385, 186271231463318990000853815490, 191874870357810130278083045105, 417346511370719864152103702755, 443864567027632233137895150685, 445916730796421504158017039561, 457009875735594771596852934850, 459741010046996619845858962098, 478907300417545151708243607632, 513047109321900091824656501791, 535778897101785771528346411074, 560346978677218129784715875282, 688798263950775386010745701702, 754236132529735325317522505913, 780464937667979530430807925412, 836888209292085373170978312211, 880660004714866077135256769054, 903348621270175469125966921413, 977694954943499714933527598658, 991113997420582322075113667310, 1005778780889988554509918812205, 1108841745770929370518386560662, 1206008354591616310698058702230, 1224667431117120261214642147063, 1250522640944657790200388612655]
You are so lucky!! Enjoy your flag
HCMUS-CTF{5iN6UL4r_va1u3_dEc0MPOSiTION_4Nd_L4t7Ic3_rEduct1On_4R3_w3irD}
```

## Flag

Part 1:

```text
HCMUS-CTF{15_tHI5_cOVARiaNC3_m4tRIx?}
```

Part 2:

```text
HCMUS-CTF{5iN6UL4r_va1u3_dEc0MPOSiTION_4Nd_L4t7Ic3_rEduct1On_4R3_w3irD}
```

## Lessons Learned

- Conjugation by an orthogonal matrix (`Q^T == Q^-1`) preserves eigenvalues; independent left/right orthogonal multiplication does not preserve a matrix's own eigenvalues but does preserve those of `M*M^T`, up to the same conjugation argument - always check what invariant survives a "mixing" transformation before assuming it destroys all structure.
- A sequence of unknown additive/multiplicative shifts collapses to a small number of aggregate unknowns (`sum of shifts`, `product of scalars`) rather than growing the unknown count with the round count.
- One or two leaked plaintext-like values against a small number of unknown aggregate constants is often enough to solve a low-degree polynomial relation (here a quadratic in `R`) and then invert the same relation across every other unknown.
- When only a single known value is available instead of two, look for a *ratio* trick (dividing out the leaked value's own relation) to turn a quadratic-in-one-unknown problem into a linear relation between two other unknowns - this is a generally reusable way to trade a missing oracle query for extra brute force.
- Naive nearest-point (Babai) rounding in a reduced lattice basis can fail when the target relation has a structurally spurious "trivial" solution that sits closer to the origin than the true one - searching a small neighborhood around the naive rounding, not just the single closest point, is a cheap and often necessary fix.
- Full-candidate verification (checking a reconstructed answer against *every* known/consistency constraint) is what makes a brute force over many structural guesses safe - it converts "this guess might be right" into "this guess is right," so wrong guesses cost time but never yield false positives.
