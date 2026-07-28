# RSA PTA Writeup

## Summary

The server generates its own RSA keypair and message, hands the player `m` and `c = m^e mod n` directly, then asks the player to submit `p`, `q`, `d` for a modulus of their own choosing; the flag is printed if `pow(c, d, p*q) == m`. There is no RSA to break - the vulnerability is that the server never checks the submitted `p`, `q`, `d` came from a keypair consistent with `c` and `e`, so the player can build a brand-new, purpose-built modulus in which `c^d == m` is easy to arrange.

Flag:

```text
HCMUS-CTF{d15cr3t3_lOg_1S_3aSy_wI7h_sM0OTH_0rDER}
```

## Triage

`chal.py` builds a normal RSA instance, but then leaks both the plaintext and ciphertext to the player before asking the player to supply the "private key" material:

```python
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p-1) * (q-1)

while True:
    e = random.randint(2,n-1)
    if math.gcd(e,phi) == 1:
        break

d = pow(e, -1, phi)

m = random.randint(2,n-1)
c = pow(m, e, n)

print(m, c)

p = int(input())
q = int(input())
d = int(input())

assert(p < q)
assert(512 <= p.bit_length())
assert(q.bit_length() < 1024)
assert(isPrime(p))
assert(isPrime(q))

n = p * q
assert(1 < d < n)

if m == pow(c, d, n):
    with open('flag.txt','r') as f:
        print(f.read())
```

The check only constrains the *shape* of the submitted `p`, `q`, `d` (bit lengths, primality, `1 < d < n`) - it never re-derives `n` or `d` from the original `e`. The original keypair, `e`, and `phi` are discarded entirely once `m` and `c` are printed. The only real inputs the player must satisfy are the public `m` and `c` values printed on connect, e.g.:

```text
<m> <c>
```

both up to ~1024-bit integers.

## Solve Path

Since `m` and `c` are handed over directly, the goal reduces to: pick fresh primes `p`, `q` and a `d` such that `c^d ≡ m (mod p*q)`, with `p ∈ [512, ∞)` bits, `q < 1024` bits, `p < q`, both prime, `n = p*q` large enough that `pow(c, d, n)` (always `< n`) can actually equal the ~1024-bit `m`.

The trick is to build each prime as a **smooth prime** (`prime - 1` is a product of small primes chosen by us), so its multiplicative group's discrete log is tractable via Pohlig-Hellman, and additionally require `c` to be a **primitive root** mod that prime so `m` is guaranteed to be *some* power of `c`:

```python
def generate_smooth_prime(min_bits, pool, tries=4000):
    for _ in range(tries):
        random.shuffle(pool)
        prod_val = 2
        factors = {2}
        for pr in pool:
            if prod_val.bit_length() >= min_bits:
                break
            prod_val *= pr
            factors.add(pr)
        cand = prod_val + 1
        if cand.bit_length() >= min_bits and is_prime(cand):
            return cand, factors
    return None, None


def is_primitive_root(base, p, factors):
    if base % p == 0:
        return False
    for r in factors:
        if pow(base, (p - 1) // r, p) == 1:
            return False
    return True
```

For each candidate smooth prime `p` (built from `pool_p`) and `q` (built from a disjoint pool `pool_q`), Sage's built-in discrete-log solver - which internally runs Pohlig-Hellman over the known smooth factorization of `p-1` - recovers the exponent `d_p` with `c^d_p ≡ m (mod p)`, and likewise `d_q` mod `q`:

```python
d_p = Integer(Zmod(p)(m_val % p).log(Zmod(p)(c_val % p)))
d_q = Integer(Zmod(q)(m_val % q).log(Zmod(q)(c_val % q)))
```

These two congruences (`d ≡ d_p mod p-1`, `d ≡ d_q mod q-1`) are combined with a CRT that tolerates a non-coprime modulus, since both `p-1` and `q-1` are even:

```python
def combine_crt(a, m, b, n):
    g = gcd(m, n)
    if (a - b) % g != 0:
        return None
    lcm = m // g * n
    m_g, n_g = m // g, n // g
    inv = inverse_mod(m_g, n_g)
    t = (((b - a) // g) % n_g) * inv % n_g
    return (a + m * t) % lcm
```

`d_p` and `d_q` must agree modulo `gcd(p-1, q-1)` for the CRT to be consistent; since both moduli are even this is at least a 50/50 coincidence on the shared factor of 2, so the script simply retries with fresh primes on failure - keeping `p` and `q`'s small-prime pools disjoint (`primes(3, 2000)` vs `primes(2003, 6000)`) keeps `gcd(p-1, q-1)` close to `2` so retries converge quickly. `p` is targeted at 520 bits and `q` at 650 bits so `n = p*q` comfortably exceeds the ~1024-bit range `m` came from, otherwise `pow(c, d, n) < n` could never equal `m`.

Once a consistent `d` is found, it is verified locally before sending:

```python
n = p * q
if 1 < d < n and pow(int(c_val), int(d), int(n)) == int(m_val):
    return p, q, d
```

## Exploit

The solve script is [solve.sage](#Solve). It connects to the remote, reads `m` and `c`, repeatedly builds a pair of disjoint-pool smooth primes for which `c` is a primitive root, solves the discrete log of `m` base `c` mod each prime via Sage's `.log()`, CRT-combines the two partial exponents into a single `d`, and - once `pow(c, d, p*q) == m` verifies locally - sends `p`, `q`, `d` to the server to receive the flag.

Run:

```bash
sage solve.sage
```

Key steps:

- `generate_smooth_prime`: builds a prime `P` where `P - 1` is a product of small primes from a given pool, so `Zmod(P)` discrete logs are cheap.
- `is_primitive_root`: checks `c` generates the full multiplicative group mod the candidate prime, guaranteeing `m` is expressible as `c^d`.
- `find_prime_with_primitive_root`: retries `generate_smooth_prime` until it also satisfies the primitive-root condition for `c`.
- `combine_crt`: CRT combination that tolerates non-coprime moduli (needed since both `p-1` and `q-1` are even).
- `solve_pd`: orchestrates prime generation, `Zmod(p).log()` Pohlig-Hellman discrete logs, CRT combination, and local verification, retrying on CRT inconsistency.

## Solve

```python=
import random
from pwn import *

context.log_level = "error"

HOST = ???
PORT = ???

P_BITS = 520
Q_BITS = 650

POOL_P = list(primes(3, 2000))
POOL_Q = list(primes(2003, 6000))


def generate_smooth_prime(min_bits, pool, tries=4000):
    for _ in range(tries):
        random.shuffle(pool)
        prod_val = 2
        factors = {2}
        for pr in pool:
            if prod_val.bit_length() >= min_bits:
                break
            prod_val *= pr
            factors.add(pr)
        cand = prod_val + 1
        if cand.bit_length() >= min_bits and is_prime(cand):
            return cand, factors
    return None, None


def is_primitive_root(base, p, factors):
    if base % p == 0:
        return False
    for r in factors:
        if pow(base, (p - 1) // r, p) == 1:
            return False
    return True


def find_prime_with_primitive_root(min_bits, base, other_val, pool, tries=300):
    for _ in range(tries):
        p, factors = generate_smooth_prime(min_bits, pool)
        if p is None:
            continue
        if other_val % p == 0:
            continue
        if is_primitive_root(base, p, factors):
            return p, factors
    return None, None


def combine_crt(a, m, b, n):
    g = gcd(m, n)
    if (a - b) % g != 0:
        return None
    lcm = m // g * n
    m_g, n_g = m // g, n // g
    inv = inverse_mod(m_g, n_g)
    t = (((b - a) // g) % n_g) * inv % n_g
    return (a + m * t) % lcm


def solve_pd(m_val, c_val):
    for attempt in range(200):
        p, p_factors = find_prime_with_primitive_root(P_BITS, c_val, m_val, POOL_P)
        if p is None:
            continue
        q, q_factors = find_prime_with_primitive_root(Q_BITS, c_val, m_val, POOL_Q)
        if q is None:
            continue
        if not (p < q and p.bit_length() >= 512 and q.bit_length() < 1024):
            continue

        d_p = Integer(Zmod(p)(m_val % p).log(Zmod(p)(c_val % p)))
        d_q = Integer(Zmod(q)(m_val % q).log(Zmod(q)(c_val % q)))

        d = combine_crt(d_p, p - 1, d_q, q - 1)
        if d is None:
            print(f"[attempt {attempt}] CRT inconsistent, retrying...")
            continue

        n = p * q
        if 1 < d < n and pow(int(c_val), int(d), int(n)) == int(m_val):
            print(f"found after {attempt+1} attempt(s)")
            return p, q, d
    raise RuntimeError("failed to find a consistent (p, q, d) in the attempt budget")


def main():
    io = remote(HOST, PORT)

    line = io.recvline().split()
    m_val = Integer(int(line[0]))
    c_val = Integer(int(line[1]))
    print("m =", m_val)
    print("c =", c_val)

    p, q, d = solve_pd(m_val, c_val)
    print("p =", p)
    print("q =", q)
    print("d =", d)

    io.sendline(str(p).encode())
    io.sendline(str(q).encode())
    io.sendline(str(d).encode())

    print(io.recvall(timeout=5).decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## Verification

```text
m = 39941817405692465036073127889130447370121759821836898235375099329950489869267279210591825593740205795095816991684994988815747989247145261839255889097978473588881651879553814485172898496350947128966322522376367619101817036808000171383840456303494434246926435742047530184419063960388382524471797970440977475885
c = 29466426033687121040905949449121718721979067411644059719389731349035273903943166106441245758167856965835611845639818167745242496039883875699522271719876466317147682626203618289596787765717358171300183152994104235416102282754296930561036847090766079333064016683528246199252697657577462542736899134909193357030
[attempt 0] CRT inconsistent, retrying...
found after 2 attempt(s)
p = 4380364723632112596981812444141176226728562637460540716294639100267419352494506085438889211062421539767039974814185782482060338265694008651820064477766368399
q = 52533510312787447081064202254022997105016088309095488951195162561623473090022287186998817683405786206691800608778071795266617013540367075471470617212344718949197207574553481456767468007414963870927
d = 71746249164328221454612312651265011767434403477924746769761010046615373032839703417416870791692965647314441312536662421278952660982855243758186272041152221745837349457618404430431006407987491770970257158886271999188558047582690326106743222990790332634358577773710620536683004278595617276479420865581964114424880160280433746679224525959169514535949654145
HCMUS-CTF{d15cr3t3_lOg_1S_3aSy_wI7h_sM0OTH_0rDER}
```

## Flag

```text
HCMUS-CTF{d15cr3t3_lOg_1S_3aSy_wI7h_sM0OTH_0rDER}
```

## Lessons Learned

- A server that lets the client fully control the modulus and private exponent - while only checking their *shape*, not their derivation from the actual keypair - has no real cryptographic binding; treat "prove you know `d`" as a puzzle to construct a convenient `d` for, not a puzzle to recover the *original* `d`.
- Smooth-order groups make discrete log trivial via Pohlig-Hellman; deliberately constructing a modulus with `p - 1` (or `q - 1`) fully factored into small primes turns an otherwise-hard DLP into a solved one.
- A primitive root guarantees every group element (including a target value like `m`) is reachable as some power of the base, which is the precondition that makes a chosen-modulus discrete-log attack always succeed rather than just "sometimes."
- CRT combination across two congruences with even (non-coprime) moduli is still solvable, but only when the two partial results agree on the shared factor - keeping the two prime-generation pools disjoint reduces that shared factor and cuts retries.
- When two independently generated constraints must agree by chance, the practical solve is a generate-and-retry loop rather than a closed-form guarantee.
