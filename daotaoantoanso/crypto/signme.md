# SignMe Writeup

## Summary

The server implements an ElGamal-style signature scheme (`(r, s)` over a public `(g, p, y=g^x)`), with the per-message nonce `k` derived from a keyed sum over the message bytes - but on an empty message that sum is `0`, and the "make `k` odd" fallback (`k += 1`) then forces `k = 1` deterministically. Signing the empty string leaks a fully known nonce, which is enough to solve for the private key `x` and forge a signature for the server's random "prove you can sign" challenge.

Flag:

```text
HCMUS-CTF{b4S364_1s_iNT3r3sT1nG}
```

## Triage

`chal.py` implements a Schnorr/ElGamal-like signing scheme over a fixed 256-bit prime `p`, with per-message key `k` computed from a dot product of secret coefficients and the message bytes:

```python
self.p = 99489312791417850853874793689472588065916188862194414825310101275999789178243
self.x = randint(1, self.p - 1)
self.g = randint(1, self.p - 1)
self.y = pow(self.g, self.x, self.p)
self.coef = [randint(1, self.p - 1) for _ in range(self.N)]
```

```python
def sign(self, pt):
    ...
    msg = b64decode(pt)
    if (len(msg) > self.N):
        return (0, 0)

    k = sum([coef * m for coef, m in zip(self.coef, msg)])
    if k % 2 == 0:            # Just to make k and p-1 coprime :)))
        k += 1

    r = pow(self.g, k, self.p)
    h = bytes_to_long(sha256(pt).digest())
    s = ((h - self.x * r) * inverse(k, self.p - 1)) % (self.p - 1)
    self.sign_attempt -= 1
    return (r, s)
```

`k = sum(coef * m for coef, m in zip(self.coef, msg))` uses `zip`, so if `msg` is empty the sum is over zero pairs - `k` is unconditionally `0` before the parity fix, and the `if k % 2 == 0: k += 1` fallback then makes it unconditionally `1`, regardless of the (secret) `coef` list. This is a nonce (`k`) that is fully known to the attacker for one specific, always-available input: base64 of the empty string.

The `get_flag` flow requires forging a valid `(r, s)` for a *server-chosen* random test message, verified with the standard ElGamal-style check:

```python
def verify(self, pt, r, s):
    if not 0 < r < self.p:
        return False
    if not 0 < s < self.p - 1:
        return False
    h = bytes_to_long(sha256(pt).digest())
    return pow(self.g, h, self.p) == (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
```

Signing is capped at `self.sign_attempt = self.N = 32` uses, so the attacker gets a limited but sufficient number of signing queries - one is enough.

## Solve Path

Requesting a signature on the empty message forces `k = 1` deterministically, since `sum([], [])` (via `zip`) is `0` and the odd-fix bumps it to `1`:

```python
def sign_empty_message(io):
    # msg = b64decode(pt) is empty -> sum(zip(coef, [])) = 0 -> k is forced to 1
    # (the "if k % 2 == 0: k += 1" bump), giving a fully known k for this query.
    select(io, 1)
    io.recvuntil(b"Input message you want to sign: ")
    io.sendline(b"")
    line = io.recvline().decode()
    r, s = map(int, re.findall(r"\d+", line))
    return r, s
```

With `k = 1` known, `r = g^k mod p = g`, and the signing equation `s = (h - x*r) * inverse(k, p-1) mod (p-1)` becomes linear in the single unknown `x` (since `inverse(1, n) = 1`):

```text
s = (h - x*r) mod (p-1)   =>   x = (h - s) * inverse(r, p-1) mod (p-1)
```

```python
r0, s0 = sign_empty_message(io)
h0 = bytes_to_long(sha256(b"").digest())

# s0 = (h0 - x*r0) * inverse(1, n) mod n  =>  x = (h0 - s0) * inverse(r0, n) mod n
x = (Integer(h0) - Integer(s0)) * inverse_mod(Integer(r0), n) % n
```

where `n = p - 1`. This recovers the private key `x` outright from a single signature - no signature forgery machinery needed beyond solving one linear congruence.

With `x` known, the server's `get_flag` challenge (a random base64 test message it asks the client to sign) is trivial to answer honestly: compute a fresh signature the same way the server itself would, again reusing `k = 1` (equivalently `r = g`) for simplicity:

```python
def forge_flag_signature(io, x, g, n):
    # Reuse k = 1 again so r_forge = g, exactly like sign_empty_message did.
    select(io, 3)
    io.recvuntil(b"Could you sign this for me:  ")
    test_b64 = io.recvline().strip()

    h_test = bytes_to_long(sha256(test_b64).digest())
    r_forge = g
    s_forge = (Integer(h_test) - x * r_forge) % n

    io.recvuntil(b"Input r: ")
    io.sendline(b64encode(long_to_bytes(int(r_forge))))
    io.recvuntil(b"Input s: ")
    io.sendline(b64encode(long_to_bytes(int(s_forge))))

    return io.recvall(timeout=5).decode(errors="replace")
```

Since `x` is now fully known, this signature satisfies `verify()` for any chosen message, including the server's random test string, so the flag branch fires.

## Exploit

The solve script is [solve.sage](#Solve). It connects to the remote, reads the public `(g, p)`, signs the empty message to obtain a known-nonce signature, solves the resulting linear congruence for the private key `x`, then signs the server's "prove you can sign" test message itself using the recovered `x` and submits it to retrieve the flag.

Run:

```bash
sage solve.sage
```

Key steps:

- `get_public_key`: reads `g`, `p` from menu option 0.
- `sign_empty_message`: requests a signature on `b""`, exploiting `zip`-over-nothing to force the nonce `k = 1`.
- private key recovery: `x = (h0 - s0) * inverse_mod(r0, n) % n` from the known-`k` signature equation.
- `forge_flag_signature`: signs the server's random test message with the recovered `x` (again using `r = g`, i.e. `k = 1`) and submits `(r, s)` to `get_flag`.

## Solve

```python=
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256
from base64 import b64encode
import re

HOST = ???
PORT = ???


def select(io, opt):
    io.recvuntil(b"Select an option: ")
    io.sendline(str(opt).encode())


def get_public_key(io):
    select(io, 0)
    io.recvuntil(b"g = ")
    g = int(io.recvline().strip())
    io.recvuntil(b"p = ")
    p = int(io.recvline().strip())
    return g, p


def sign_empty_message(io):
    # msg = b64decode(pt) is empty -> sum(zip(coef, [])) = 0 -> k is forced to 1
    # (the "if k % 2 == 0: k += 1" bump), giving a fully known k for this query.
    select(io, 1)
    io.recvuntil(b"Input message you want to sign: ")
    io.sendline(b"")
    line = io.recvline().decode()
    r, s = map(int, re.findall(r"\d+", line))
    return r, s


def forge_flag_signature(io, x, g, n):
    # Reuse k = 1 again so r_forge = g, exactly like sign_empty_message did.
    select(io, 3)
    io.recvuntil(b"Could you sign this for me:  ")
    test_b64 = io.recvline().strip()

    h_test = bytes_to_long(sha256(test_b64).digest())
    r_forge = g
    s_forge = (Integer(h_test) - x * r_forge) % n

    io.recvuntil(b"Input r: ")
    io.sendline(b64encode(long_to_bytes(int(r_forge))))
    io.recvuntil(b"Input s: ")
    io.sendline(b64encode(long_to_bytes(int(s_forge))))

    return io.recvall(timeout=5).decode(errors="replace")


def main():
    io = remote(HOST, PORT)

    g, p = get_public_key(io)
    n = p - 1

    r0, s0 = sign_empty_message(io)
    h0 = bytes_to_long(sha256(b"").digest())

    # s0 = (h0 - x*r0) * inverse(1, n) mod n  =>  x = (h0 - s0) * inverse(r0, n) mod n
    x = (Integer(h0) - Integer(s0)) * inverse_mod(Integer(r0), n) % n

    print(forge_flag_signature(io, x, g, n))


if __name__ == "__main__":
    main()
```

## Verification

```text
[+] Opening connection to vm.daotao.antoanso.org on port 32793: Done
[+] Receiving all data: Done (69B)
[*] Closed connection to vm.daotao.antoanso.org port 32793
Congratulation, this is your flag:  HCMUS-CTF{b4S364_1s_iNT3r3sT1nG}
```

## Flag

```text
HCMUS-CTF{b4S364_1s_iNT3r3sT1nG}
```

## Lessons Learned

- Any signature scheme where the per-message nonce `k` is derived from attacker-influenced input must be checked at the input's degenerate boundary (empty message, all-zero message, etc.) - a "should never happen" edge case can make `k` fully predictable.
- A single signature with a *known* nonce is enough to solve ElGamal/Schnorr-style schemes for the private key, because the signing equation `s = (h - x*r) * k^-1 mod (p-1)` becomes linear in `x` once `k` is known.
- "Fixing" `k` with a cheap transformation (like `k += 1` to force it odd) doesn't add entropy - if the underlying value was deterministic before the fix, it's still deterministic after.
- Once the private key is recovered, any "prove you can sign an unpredictable message" check collapses to normal, honest signing - unpredictability of the challenge message only matters if the private key is actually secret.
- Review keyed/nonce-derivation formulas (`sum(coef[i] * msg[i])`, HMAC-like constructs, etc.) for behavior on empty or minimal inputs, not just typical-length inputs - aggregation-based nonces often have a trivial identity case.
