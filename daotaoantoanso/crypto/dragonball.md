# DragonBall Writeup

## Summary

This is a remote crypto challenge: no server source was provided, only `debug.py`, a comment-only fragment leaked from the service's own debug output containing the ElGamal domain parameters (`p`, `g`), the hash function used (SHA-1), and an example PyCryptodome `ElGamal.sign`/`verify` snippet, the actual "Dragon Ball Verification System" service. The core vulnerability is a static ElGamal signing nonce `k` (same `r = g^k mod p` reused across signatures), which lets two signatures over different messages leak the private key.

Flag:

```text
HCMUS-CTF{Same k? Really? No, ElGamal hates it.}
```

## Triage

`debug.py` contains no executable logic - it is entirely a comment block, apparently leaked debug output from the service, that discloses the ElGamal parameters and signing scheme in use:

```python
# ----- DEBUG MODE -----
#         # We used ElGamal signature scheme with
#         >>> p = 129395855808705212728342121899564040533627536165407217623699982163034898985604990453612738681235265684964910273382421570674875235106037524148312004154122323500944367988234700927644310658336581857679208804861661335768169851589929150626616698506529354785376916490328643358410300092039405295348822918174724269387
#         >>> g = 125119881720420900707670154269953309690838537679536446473408150363676013315875914220318853661265626997530402259420104771257078966641464155686445398996594055909718103795617751840611152747280651424068043671714408414771552296848509963265865300590662320297995606313265875459093865996548994154719802981360764938058
#         # SHA is the Hash Function we used.
#         >>> h = SHA.new('USERNAME=username&LEVEL=Saiyan').digest()
```

This tells us the challenge exposes a service that signs messages of the form `USERNAME=<name>&LEVEL=<level>` with ElGamal over a ~1024-bit prime `p`, hashed with SHA-1, and presumably verifies a submitted token against a required `LEVEL` (e.g. `SuperSaiyan`) to release the flag. Since there is no source for the actual signing/verification logic, the real behavior - including the suspicion that the nonce `k` is reused - had to be inferred by interacting with the live service and comparing multiple signatures.

## Solve Path

`solve.sage` first fetches the live `p`/`g` from the service (option `3`) rather than trusting the values in the leaked debug comment, since the actual deployed instance may differ:

```python
def get_params(io):
    io.recvuntil(b">>> ")
    io.sendline(b"3")
    data = io.recvuntil(b"Dragon Ball Verification System").decode(errors="replace")
    p = Integer(re.search(r"p = (\d+)", data).group(1))
    g = Integer(re.search(r"g = (\d+)", data).group(1))
    return p, g
```

It then requests signed tokens for three different usernames (option `1`), parsing out each message, its SHA-1 hash, and the `(r, s)` signature pair:

```python
def generate(io, name):
    io.recvuntil(b">>> ")
    io.sendline(b"1")
    io.recvuntil(b"Your name: ")
    io.sendline(name.encode())
    io.recvuntil(b"Say ")
    token = io.recvuntil(b" to summon", drop=True).strip()
    blob = b64decode(token)
    msg, rest = blob.split(b"&r=", 1)
    r_part, s_part = rest.split(b"&s=", 1)
    r = Integer(int.from_bytes(r_part, "big"))
    s = Integer(int.from_bytes(s_part, "big"))
    h = Integer(int.from_bytes(sha1(msg).digest(), "big"))
    return msg, h, r, s
```

Comparing `r = g^k mod p` across the three signatures showed it is identical every time - the signing nonce `k` is static rather than freshly random per signature, which is fatal for ElGamal. With two signatures `(h1, r, s1)` and `(h2, r, s2)` sharing the same `r`:

```text
s1 = (h1 - x*r) * k^-1 (mod p-1)
s2 = (h2 - x*r) * k^-1 (mod p-1)
```

Subtracting eliminates `x`, giving `k = (h1 - h2) / (s1 - s2) (mod p-1)`, and then `x = (h1 - s1*k) / r (mod p-1)`. Because `p-1` need not be coprime to the divisors involved, `solve_lin` solves the linear congruence `a*z == b (mod n)` generally (via `gcd`, not a plain modular inverse) and returns every valid residue class, and each private-key candidate `x` is verified against a real signature before being accepted:

```python
def solve_lin(a, b, n):
    a %= n
    b %= n
    g = gcd(a, n)
    if b % g != 0:
        return []
    a1, b1, n1 = a // g, b // g, n // g
    z0 = (b1 * inverse_mod(a1, n1)) % n1
    return [(z0 + i * n1) % n for i in range(g)]


def recover_x(p, g, sigs):
    p1 = p - 1
    (m1, h1, r, s1) = sigs[0]
    for j in range(1, len(sigs)):
        (m2, h2, r2, s2) = sigs[j]
        assert r2 == r, "nonce not static -> attack assumption broken"
        for k in solve_lin((s1 - s2) % p1, (h1 - h2) % p1, p1):
            for x in solve_lin(r % p1, (h1 - s1 * k) % p1, p1):
                y = pow(g, x, p)
                if pow(g, int(h1), p) == (pow(y, int(r), p) * pow(int(r), int(s1), p)) % p:
                    return Integer(x), Integer(k), Integer(y)
    return None, None, None
```

With the recovered private key `x`, the script signs its own message with the required level and submits it for verification:

```python
TARGET_MSG = b"USERNAME=pwn&LEVEL=SuperSaiyan"

def sign(p, g, x, msg):
    p1 = p - 1
    h = Integer(int.from_bytes(sha1(msg).digest(), "big"))
    k = Integer(3)
    while gcd(k, p1) != 1:
        k += 2
    r = pow(g, int(k), int(p))
    s = ((h - x * r) * inverse_mod(k, p1)) % p1
    return Integer(r), Integer(s)
```

## Exploit

The solve script is [solve.sage](#Solve). It connects to the live service, fetches the live ElGamal parameters, requests three signed tokens for different usernames, recovers the static nonce and private key from any pair of them via linear congruence solving, forges a fresh signature over `USERNAME=pwn&LEVEL=SuperSaiyan` with a freshly chosen coprime nonce, and submits it to the verification endpoint.

Run:

```bash
sage solve.sage
```

Key helpers:

- `get_params`: fetches the live `p`, `g` from the service's own printout instead of trusting the leaked debug comment
- `generate`: requests a signed token for a given username and parses out `(msg, h, r, s)`
- `solve_lin`: solves a general linear congruence `a*z == b (mod n)` (handles `gcd(a,n) > 1`, returns all solutions)
- `recover_x`: derives the static nonce `k` and private key `x` from two same-`r` signatures, verifying each candidate against a real signature
- `sign`: forges a fresh valid signature over an arbitrary message using the recovered private key
- `verify`: submits a forged token to the service's verification option and returns its response

## Solve

```python=
from sage.all import *
from pwn import *
from hashlib import sha1
from base64 import b64encode, b64decode
import re

HOST = "vm.daotao.antoanso.org"
PORT = 32791

TARGET_MSG = b"USERNAME=pwn&LEVEL=SuperSaiyan"


def l2b(n):
    n = int(n)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def solve_lin(a, b, n):
    # all z with a*z == b (mod n)
    a %= n
    b %= n
    g = gcd(a, n)
    if b % g != 0:
        return []
    a1, b1, n1 = a // g, b // g, n // g
    z0 = (b1 * inverse_mod(a1, n1)) % n1
    return [(z0 + i * n1) % n for i in range(g)]


def get_params(io):
    io.recvuntil(b">>> ")
    io.sendline(b"3")
    data = io.recvuntil(b"Dragon Ball Verification System").decode(errors="replace")
    p = Integer(re.search(r"p = (\d+)", data).group(1))
    g = Integer(re.search(r"g = (\d+)", data).group(1))
    return p, g


def generate(io, name):
    io.recvuntil(b">>> ")
    io.sendline(b"1")
    io.recvuntil(b"Your name: ")
    io.sendline(name.encode())
    io.recvuntil(b"Say ")
    token = io.recvuntil(b" to summon", drop=True).strip()
    blob = b64decode(token)
    msg, rest = blob.split(b"&r=", 1)
    r_part, s_part = rest.split(b"&s=", 1)
    r = Integer(int.from_bytes(r_part, "big"))
    s = Integer(int.from_bytes(s_part, "big"))
    h = Integer(int.from_bytes(sha1(msg).digest(), "big"))
    return msg, h, r, s


def verify(io, token):
    io.recvuntil(b">>> ")
    io.sendline(b"2")
    io.recvuntil(b"Summon Shenron: ")
    io.sendline(token)
    return io.recvall(timeout=5).decode(errors="replace").strip()


def recover_x(p, g, sigs):
    p1 = p - 1
    (m1, h1, r, s1) = sigs[0]
    for j in range(1, len(sigs)):
        (m2, h2, r2, s2) = sigs[j]
        assert r2 == r, "nonce not static -> attack assumption broken"
        for k in solve_lin((s1 - s2) % p1, (h1 - h2) % p1, p1):
            for x in solve_lin(r % p1, (h1 - s1 * k) % p1, p1):
                y = pow(g, x, p)
                if pow(g, int(h1), p) == (pow(y, int(r), p) * pow(int(r), int(s1), p)) % p:
                    return Integer(x), Integer(k), Integer(y)
    return None, None, None


def sign(p, g, x, msg):
    p1 = p - 1
    h = Integer(int.from_bytes(sha1(msg).digest(), "big"))
    k = Integer(3)
    while gcd(k, p1) != 1:
        k += 2
    r = pow(g, int(k), int(p))
    s = ((h - x * r) * inverse_mod(k, p1)) % p1
    # local sanity check
    y = pow(g, int(x), int(p))
    assert pow(g, int(h), int(p)) == (pow(y, int(r), int(p)) * pow(int(r), int(s), int(p))) % int(p)
    return Integer(r), Integer(s)


def main():
    io = remote(HOST, PORT)
    p, g = get_params(io)
    log.info(f"p bits: {int(p).bit_length()}")

    sigs = [generate(io, n) for n in ["pwna", "pwnbb", "pwnccc"]]
    log.info(f"r (should be identical): {hex(int(sigs[0][2]))[:20]}...")

    x, k, y = recover_x(p, g, sigs)
    if x is None:
        log.failure("failed to recover private key")
        io.close()
        return
    log.success(f"recovered private key x = {x}")

    r, s = sign(p, g, x, TARGET_MSG)
    token = b64encode(TARGET_MSG + b"&r=" + l2b(r) + b"&s=" + l2b(s))
    resp = verify(io, token)
    io.close()

    log.info(f"response:\n{resp}")
    if any(m in resp for m in ("CTF", "flag", "FLAG", "HCMUS", "{")):
        log.success("FLAG FOUND")


if __name__ == "__main__":
    main()
```

## Verification

```text
[+] Opening connection to vm.daotao.antoanso.org on port 32791: Done
[*] p bits: 1024
[*] r (should be identical): 0x4dc3be6bf1e702fa59...
[+] recovered private key x = 12841053699073275911948582609582036268035816999075891383482120347559247896616288846996721466728842982835660588351096284144328709549322351938920824008376895019700428848240004524021310165326109738573794348659829181144052586134072911352831288002506748789000912905006051038498110861831292263097809911298247559460
[+] Receiving all data: Done (89B)
[*] Closed connection to vm.daotao.antoanso.org port 32791
[*] response:
    Hooooo! Shenron will give you the FLAG!
    HCMUS-CTF{Same k? Really? No, ElGamal hates it.}
[+] FLAG FOUND
```

## Flag

```text
HCMUS-CTF{Same k? Really? No, ElGamal hates it.}
```

## Lessons Learned

- ElGamal (and DSA/ECDSA-family) signatures leak the private key immediately if the per-signature nonce `k` is ever reused - the same failure mode as reused nonces in any Schnorr-like signature scheme.
- A static/reused nonce shows up observably as an identical `r = g^k mod p` across otherwise-different signatures - this is a cheap, purely observational check to run before attempting any heavier cryptanalysis.
- When solving modular linear equations for an attack, don't assume the modulus is coprime to the coefficients - use a general `gcd`-based linear congruence solver so solutions aren't silently missed when `p-1` (or similar) is composite.
- Always verify a derived candidate secret (like a recovered private key) against an independent real signature before trusting it - division/inversion under a non-prime modulus can yield multiple candidate residues.
- Don't trust parameters found in leaked debug output or comments as authoritative - refetch live values from the running service where possible, since a deployed instance may differ from what was captured in a debug log.
