# Polynomial AES Writeup

## Summary

Offline crypto challenge: `encrypt.py` runs locally and drops a single `output.txt` containing a 1024-bit prime `p`, a list of polynomial coefficients `q`, and an AES-ECB-encrypted flag - no network service involved. The AES key is derived from a sum-over-all-residues of a random polynomial mod `p`, and that sum degenerates via a power-sum identity to just `-q[0] mod p`, so only the first coefficient of `q` (which is printed in the clear) actually matters.

Flag:

```text
HCMUS-CTF{13arN-4lg38ra}
```

## Triage

`encrypt.py`'s `generate_key()` builds a degree-`d` polynomial (`d` random in `[20,30]`) over `F_p` with a 1024-bit prime `p`, coefficients `q[0..d]` each ~100 bits:

```python
def generate_key() -> bytes:
    d = getRandomRange(20, 30)
    p = getPrime(1024)
    q = []
    for _ in range(d + 1):
        q.append(getRandomInteger(100))

    def eval(x: int) -> int:
        ans = 0
        mul = 1
        for i in range(d + 1):
            ans = (ans + mul * q[i]) % p
            mul = (mul * x) % p
        return ans

    print(f"p = {p}")
    print(f"q = {q}")

    H = range(1, p)
    s = 0
    for h in H:
        s = (s + eval(h)) % p

    key = sha256(str(s).encode())
    return key
```

The suspicious part: `s` is the sum of the polynomial evaluated at *every* nonzero residue mod `p`, i.e. `s = sum_{h=1}^{p-1} eval(h) mod p`. That's a full sum over the multiplicative group, not a small sample - a classic setup for a power-sum identity to collapse it. `p` and the full coefficient list `q` (25+ entries, one of them oddly larger than 100 bits) are printed to `output.txt` in the clear, along with the ciphertext:

```
p   =   150798630896819594182651789541554972925701250717...
q   =   [72961712988575923480069485887, 51777043986742372200545207145..., ...]
Encrypted flag: 864b4997518f22d8f1f51325e805f0ef51f70e9b10be01dd2c3154d9d5a44321
```

(`output.txt` is UTF-16 encoded - reading it as plain text/bytes shows every character interleaved with null bytes.)

## Solve Path

Expand the sum by linearity: `s = sum_i q[i] * (sum_{h=1}^{p-1} h^i mod p)`. Each inner power sum `sum_{h=1}^{p-1} h^i mod p` follows a standard identity - it's `-1 mod p` when `(p-1) | i`, and `0 mod p` otherwise. Since `0 <= i <= d <= 30` and `p-1` is a ~1024-bit number, `(p-1)` divides `i` only when `i == 0`. Every term but the constant coefficient vanishes:

```python
# s == -q[0] (mod p)
```

So the entire polynomial - degree, the other ~24 coefficients, the oversized outlier at index 20 - is noise. Only `q[0]` and `p` determine the AES key. `solve.sage` parses those two values plus the ciphertext straight out of `output.txt`:

```python
with open("output.txt", encoding="utf-16") as f:
    data = f.read()

p = int(re.search(r"p\s*=\s*(\d+)", data).group(1))
q0 = int(re.search(r"q\s*=\s*\[\s*(\d+)", data).group(1))
ct = bytes.fromhex(re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", data).group(1))
```

then reconstructs `s` and the key directly:

```python
s = (-q0) % p

key = sha256(str(s).encode())

cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt)
```

No brute force, no factoring - the entire key derivation reduces to one modular negation once the power-sum identity is applied.

## Exploit

[solve.sage](#Solve) (folder name contains a space, hence the `%20`) parses `p`, `q[0]`, and the ciphertext out of `output.txt` (UTF-16 encoded), computes `s = -q[0] mod p`, derives `key = SHA256(str(s))`, and AES-ECB decrypts + unpads the flag. Run with:

```
sage solve.sage
```

Key steps in the script:
- Regex extraction of `p`, the first element of `q`, and the hex ciphertext from `output.txt`
- `s = (-q0) % p` - the collapsed power-sum result
- `sha256(str(s).encode())` - reproduces `generate_key()`'s SHA256-of-decimal-string key derivation
- `AES.new(key, AES.MODE_ECB).decrypt(ct)` + `unpad(...)` - recovers the flag bytes

## Solve
```python=
import re
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256

with open("output.txt", encoding="utf-16") as f:
    data = f.read()

p = int(re.search(r"p\s*=\s*(\d+)", data).group(1))
q0 = int(re.search(r"q\s*=\s*\[\s*(\d+)", data).group(1))
ct = bytes.fromhex(re.search(r"Encrypted flag:\s*([0-9a-fA-F]+)", data).group(1))

s = (-q0) % p


def sha256(b):
    h = SHA256.new()
    h.update(b)
    return h.digest()


key = sha256(str(s).encode())

cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt)
```

## Verification

```text
b'HCMUS-CTF{13arN-4lg38ra}'
```

## Flag

```text
HCMUS-CTF{13arN-4lg38ra}
```

## Lessons Learned

- A sum of a polynomial over *all* residues of a field is a red flag: power-sum identities (`sum_{h} h^i ≡ -1` iff `(p-1)|i`, else `0`) collapse it to just the constant term, no matter how many higher-degree coefficients are thrown in as noise.
- Bulk/oversized coefficients or degrees in a printed parameter set can be deliberate misdirection - check which values are mathematically load-bearing before assuming complexity implies security.
- Deriving a symmetric key from a low-entropy or fully-determined intermediate value (here, one 100-bit `q[0]` mod a known 1024-bit `p`) makes brute-forcing/guessing or, as here, direct algebraic recovery trivial regardless of the KDF (SHA256) used downstream.
- Always check file encoding before parsing challenge output - a UTF-16 file misread as UTF-8/binary will look corrupted even though the data is intact.
