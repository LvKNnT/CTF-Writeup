# XOR Writeup

## Summary

This is an offline crypto challenge: `xor.py` XORs an 8-byte key `k` against an 8-byte message `m`, and separately hashes `k` through a two-round SHA-256 chain, publishing only the XOR ciphertext, the final hash, and one structural fact about `m`. No remote service is involved - the printed hex strings in `xor.py`'s own output comments are the actual challenge data. The core mechanic is that the one structural constraint on `m` collapses one byte of the 8-byte key into a function of the others, and the two-round SHA-256 chain is used purely as a verification oracle to brute-force the remaining key space.

Flag:

```text
k = 'justakey' 
m = '<3meow<3'
```

## Triage

`xor.py` builds the ciphertext as a plain byte-wise XOR of an 8-byte message and an 8-byte key, then computes a SHA-256 hash chain over the key alone:

```python
m = '<3meow<3'  #pretty sure this is not the actual content
k = 'justakey'  #same as above
c = bytes(a ^ b for (a, b) in zip(toBa(m), toBa(k)))

h = SHA256.new()
h.update(toBa(k))
hk = h.digest()
h.update(hk)
hhk = h.digest()
```

The `m` and `k` values in the source are explicitly marked as placeholders used only to demonstrate the format; the real challenge data is what the script actually prints:

```python
print(isStandard(m,2))
# True
print(baToHex(c))
# 56461e110e1c594a
print(baToHex(hhk))
# 10d8261dcb7761cce260142ee7e6c7427056d2750c80d252f088f1274b235bca
```

`isStandard(s, nob)` checks a structural property of the plaintext, which for `nob=2` and an 8-byte string reduces to a single equality:

```python
def isStandard(s,nob):
    sl = len(s)
    for i in range(0,nob-1):
        if (s[i] == s[sl-nob+i]):
            continue
        return False
    return all(c in string.printable for c in s)
```

With `nob=2`, the loop only runs for `i=0`, so `isStandard(m,2) == True` means exactly `m[0] == m[6]` (plus every character of `m` being printable). `hhk = SHA256(k || SHA256(k))` is a one-way hash chain over `k` with no shortcut - recovering `k` requires an oracle-style brute force, but `k` is known (from the challenge's hint text) to match `/[a-z]{8}/`, an 8-character lowercase key.

## Solve Path

The single structural relation on `m` becomes a relation on `k` once XOR is unwound: `m[i] = c[i] XOR k[i]`, so `m[0] == m[6]` implies `c[0] XOR k[0] == c[6] XOR k[6]`, which pins `k[6]` as a function of `k[0]`:

```python
DELTA6 = c[0] ^^ c[6]
```

```python
for k0 in k0_values:
    k6 = k0 ^^ DELTA6
    if k6 not in ALPHABET:
        continue
    k[0] = k0
    k[6] = k6
```

(Note: inside a `.sage` file, `^` is preparsed as exponentiation, so bitwise XOR must be written `^^` everywhere.) This single relation cuts the brute-force space from `26^8` down to `26^7` (~8e9) candidates for the remaining six unconstrained key bytes, since `k[6]` is derived rather than guessed:

```python
FREE_POS = [1, 2, 3, 4, 5, 7]
```

The remaining six bytes (`k[1]`, `k[2]`, `k[3]`, `k[4]`, `k[5]`, `k[7]`) are brute-forced over the lowercase alphabet in nested loops, testing each full candidate key against the published hash chain:

```python
for a in ALPHABET:
    k[1] = a
    for b in ALPHABET:
        k[2] = b
        for d in ALPHABET:
            k[3] = d
            for e in ALPHABET:
                k[4] = e
                for f in ALPHABET:
                    k[5] = f
                    for g in ALPHABET:
                        k[7] = g
                        kb = bytes(k)
                        hk = sha256(kb).digest()
                        if sha256(kb + hk).digest() == target:
                            return kb
```

Once a candidate `k` reproduces `hhk = SHA256(k || SHA256(k))`, it is (with overwhelming probability) the true key, and the plaintext follows immediately from `c XOR k`:

```python
m = bytes(a ^^ b for a, b in zip(c, k))
```

Because `26^7` candidates is still a heavy brute force (documented as hours on a single core), the solve script is designed to be sharded across multiple parallel processes, splitting the outer `k[0]` loop by shard index:

```python
my_k0 = ALPHABET[shard::nshards]
```

```bash
sage solve.sage 0 4 &
sage solve.sage 1 4 &
sage solve.sage 2 4 &
sage solve.sage 3 4 &
```

## Exploit

[solve.sage](#Solve) hardcodes the published `c` (`C_HEX`) and `hhk` (`HHK_HEX`), derives `k[6]` from the `isStandard(m,2)` relation, then brute-forces the remaining six lowercase key bytes, checking each candidate against the two-round SHA-256 chain until it matches, and finally recovers `m = c XOR k`.

Run (optionally sharded across cores):

```bash
sage solve.sage
# or, sharded:
sage solve.sage <shard> <nshards>
```

Key steps:

- `DELTA6 = c[0] ^^ c[6]` - encodes the `isStandard(m,2)` constraint (`m[0] == m[6]`) as a direct relation between `k[0]` and `k[6]`.
- `crack(k0_values, ...)` - the sharded brute-force driver; iterates candidate `k0` values, derives `k6`, then nests loops over the six remaining free bytes.
- `FREE_POS = [1, 2, 3, 4, 5, 7]` - the key positions that must actually be brute-forced, after the derived-byte optimization.
- `sha256(kb).digest()` / `sha256(kb + hk).digest() == target` - the verification oracle: matches the two-round SHA-256 chain against the published `HHK_HEX` to confirm a candidate key.
- `my_k0 = ALPHABET[shard::nshards]` - shards the outer loop by `k[0]` so multiple processes can search in parallel.

## Solve

```python=
import sys
import string
import time
from hashlib import sha256

# output
C_HEX = "56461e110e1c594a"
HHK_HEX = "10d8261dcb7761cce260142ee7e6c7427056d2750c80d252f088f1274b235bca"

c = bytes.fromhex(C_HEX)
target = bytes.fromhex(HHK_HEX)
L = len(c)  
ALPHABET = list(string.ascii_lowercase.encode())  

DELTA6 = c[0] ^^ c[6]
FREE_POS = [1, 2, 3, 4, 5, 7]


def crack(k0_values, report_every=2_000_000):
    k = bytearray(L)
    tried = 0
    t0 = time.time()
    for k0 in k0_values:
        k6 = k0 ^^ DELTA6
        if k6 not in ALPHABET:
            continue
        k[0] = k0
        k[6] = k6
        for a in ALPHABET:
            k[1] = a
            for b in ALPHABET:
                k[2] = b
                for d in ALPHABET:
                    k[3] = d
                    for e in ALPHABET:
                        k[4] = e
                        for f in ALPHABET:
                            k[5] = f
                            for g in ALPHABET:
                                k[7] = g
                                kb = bytes(k)
                                hk = sha256(kb).digest()
                                if sha256(kb + hk).digest() == target:
                                    return kb
                                tried += 1
                                if tried % report_every == 0:
                                    rate = tried / (time.time() - t0)
                                    print(f"[k0={chr(k0)}] tried={tried:,} "
                                          f"rate={rate:,.0f}/s")
    return None


if __name__ == "__main__":
    if len(sys.argv) == 3:
        shard, nshards = int(sys.argv[1]), int(sys.argv[2])
    else:
        shard, nshards = 0, 1

    my_k0 = ALPHABET[shard::nshards]
    print(f"[shard {shard}/{nshards}] searching k0 in "
          f"{bytes(my_k0).decode()}")

    k = crack(my_k0)
    if k is None:
        print("not found in this shard")
    else:
        m = bytes(a ^^ b for a, b in zip(c, k))
        print("k =", k)
        print("m =", m)

```

## Verification

```text
$ sage solve.sage 1 4
[shard 1/4] searching k0 in bfjnrvz
[k0=b] tried=2,000,000 rate=1,461,540/s
[k0=b] tried=4,000,000 rate=1,404,403/s
...
[k0=j] tried=862,000,000 rate=1,182,944/s
[k0=j] tried=864,000,000 rate=1,183,065/s
k = b'justakey'
m = b'<3meow<3'
```

## Flag

```text
k = 'justakey' 
m = '<3meow<3'
```

## Lessons Learned

- Any structural constraint on a plaintext (repeated bytes, printable-only characters, fixed positions) becomes a constraint on the key once combined with a known ciphertext under XOR - always propagate plaintext structure through the cipher relation before brute-forcing.
- A single derived-byte relation can cut a brute-force search space by a full alphabet factor (here `26^8 -> 26^7`); look for these before reaching for raw brute force.
- A one-way hash chain (`H(k || H(k))`) published as "proof of key" gives no algebraic shortcut, but it is still just a verification oracle for a brute force over a small keyspace - don't mistake "can't invert the hash" for "can't recover the key."
- Small, structured keyspaces (e.g. `/[a-z]{8}/`) are brute-forceable even through SHA-256 once the space is small enough (tens of billions), especially when the work embarrassingly parallelizes by sharding one loop variable across processes/cores.
- In Sage, `^` is preparsed as exponentiation, not XOR - always use `^^` for bitwise XOR to avoid silently wrong results.
