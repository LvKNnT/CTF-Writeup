# DESX Writeup

## Summary

This is a remote crypto challenge - `desx.py`. The service implements an Even-Mansour-style DES construction with two fixed, never-revealed 64-bit whitening values, and leaks a fresh random DES key on every "get encrypted flag" call; the core vulnerability is DES's own key/plaintext complementation property, which lets an attacker decrypt the real flag ciphertext under the complemented key/ciphertext pair and bypass the server's "don't leak real flag bytes" guard.

Flag:

```text
HCMUS-CTF{https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties}
```

## Triage

`desx.py` defines an Even-Mansour-like wrapper around single-DES-ECB using two fixed random 8-byte whitening values `i1`, `i2` generated once at startup and never printed:

```python
i1 = os.urandom(8)
i2 = os.urandom(8)

def encrypt(k: bytes, p: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    ct = b""
    for i in range(0, len(p), 8):
        block = p[i:i+8]
        ct += xor(cipher.encrypt(xor(block, i1)), i2)
    return ct

def decrypt(k: bytes, c: bytes) -> bytes:
    cipher = DES.new(k, mode=DES.MODE_ECB)
    return xor(cipher.decrypt(xor(c, i2)), i1)
```

The menu offers two options every loop iteration:

```python
if option == 1:
    k = os.urandom(8)
    c = encrypt(k, pad(flag, DES.block_size))
    print(f"Key: {k.hex()}")
    print(f"Encrypted flag: {c.hex()}")
elif option == 2:
    ...
    p = decrypt(k, c)
    if p in flag:
        print("This one right here, officer")
        break
    print(f"Plaintext: {p.hex()}")
```

Option 1 leaks a brand-new random DES key `k` alongside the flag's ciphertext every time it's called - a fresh key each call, but always paired with its own matching ciphertext. Option 2 lets the attacker supply an arbitrary `(k, c)` pair and get back the decrypted plaintext, but explicitly refuses to answer if the decrypted plaintext is a literal substring of the real flag (`if p in flag: ... break`), which blocks the obvious move of just replaying the leaked `(k, block)` pair from option 1 into option 2.

## Solve Path

The naive attack - call option 1 to get `(k, c)` for the flag, then feed the exact same `(k, block)` pair into option 2 to invert it - is caught every time by the `p in flag` guard, since decrypting a real flag block with its own key always reproduces literal flag bytes. This flag happens to be exactly 96 bytes (12 DES blocks), so PKCS7 padding adds a full 13th block of pure `0x08` bytes; even the usual "the guard doesn't catch garbage padding in the last block" trick reveals nothing extra here, since that padding block still isn't useful on its own.

The real bug is DES's complementation property: for all keys `K` and inputs `P`, `DES_(K̄)(P̄) = DES_K(P)‾` (bar = bitwise NOT), and equivalently for decryption, `DES_(K̄)^-1(C̄) = DES_K^-1(C)‾`. Substituting into the challenge's `decrypt`:

```text
decrypt(k, c) = DES_k^-1(c XOR i2) XOR i1
```

Complementing both `k` and `c`: `c̄ XOR i2 = (c XOR i2)‾` regardless of what `i2` actually is, so:

```text
decrypt(complement(k), complement(c)) = complement(decrypt(k, c))
```

unconditionally - no dependence on `i1`, `i2`, or their relationship. So for a real flag block encrypted under key `k_j` as `C_m`, querying `decrypt(complement(k_j), complement(C_m))` returns `complement(P_m)`: the bitwise NOT of genuine printable-ASCII flag bytes. That complemented value is not a substring of the real flag, so it walks straight past the guard - for every block, not just the last one - and complementing the returned plaintext locally recovers the real block:

```python
def complement(b: bytes) -> bytes:
    return bytes(x ^^ 0xFF for x in b)

def decrypt_query(io, k: bytes, c: bytes) -> bytes:
    ...
    line = io.recvline()
    if b"officer" in line:
        raise RuntimeError(f"guard triggered for k={k.hex()} c={c.hex()}: {line}")
    p_hex = line.split(b":", 1)[1].strip()
    return bytes.fromhex(p_hex.decode())
```

```python
k_bar = complement(k)

flag_padded = b""
for m in range(n_blocks):
    block = c[m * 8:(m + 1) * 8]
    c_bar = complement(block)
    p_bar = decrypt_query(io, k_bar, c_bar)
    p = complement(p_bar)
    flag_padded += p
```

## Exploit

The solve script is [solve.sage](#Solve). It connects to the remote service, calls option 1 once to leak `(k, c)` for the padded flag, then for every 8-byte block of `c` queries option 2 with `(complement(k), complement(block))`, complements each returned plaintext locally to recover the real block, and finally strips PKCS7 padding from the reassembled plaintext.

Run:

```bash
sage solve.sage
```

Key helpers:

- `goto_menu`: consumes the menu prompt text so the next `sendline` lines up with the server's `input()` calls
- `complement`: bitwise-NOT of a byte string, used on keys, ciphertexts, and recovered plaintexts
- `decrypt_query`: drives one full option-2 interaction (send key, send ciphertext, parse plaintext or raise if the guard triggered)
- `main`: leaks `(k, c)` via option 1, loops over every block applying the complementation trick, and strips PKCS7 padding from the reassembled flag

## Solve

```python=
from pwn import *

# context.log_level = "debug"

HOST = ???
PORT = ???


def goto_menu(io):
    io.recvuntil(b"2. Decrypt")
    io.recvline()


def complement(b: bytes) -> bytes:
    return bytes(x ^^ 0xFF for x in b)


def decrypt_query(io, k: bytes, c: bytes) -> bytes:
    goto_menu(io)
    io.sendline(b"2")                      # Decrypt
    io.recvuntil(b"Key:")
    io.recvline()                          # flush rest of "Key: " prompt line
    io.sendline(k.hex().encode())
    io.recvuntil(b"Ciphertext:")
    io.recvline()                          # flush rest of "Ciphertext: " prompt line
    io.sendline(c.hex().encode())

    line = io.recvline()
    if b"officer" in line:
        raise RuntimeError(f"guard triggered for k={k.hex()} c={c.hex()}: {line}")

    p_hex = line.split(b":", 1)[1].strip()
    return bytes.fromhex(p_hex.decode())


def main():
    io = remote(HOST, PORT)

    goto_menu(io)
    io.sendline(b"1")                      # Get encrypted flag
    io.recvuntil(b"Key:")
    k_hex = io.recvline().strip()
    io.recvuntil(b"Encrypted flag:")
    c_hex = io.recvline().strip()

    k = bytes.fromhex(k_hex.decode())
    c = bytes.fromhex(c_hex.decode())
    n_blocks = len(c) // 8
    print("k =", k.hex())
    print("full ciphertext =", c.hex(), f"({len(c)} bytes, {n_blocks} block(s))")

    k_bar = complement(k)

    flag_padded = b""
    for m in range(n_blocks):
        block = c[m * 8:(m + 1) * 8]
        c_bar = complement(block)
        p_bar = decrypt_query(io, k_bar, c_bar)
        p = complement(p_bar)
        print(f"block {m}: {p!r}")
        flag_padded += p

    pad_len = flag_padded[-1]
    flag = flag_padded[:-pad_len] if 1 <= pad_len <= 8 else flag_padded
    print("flag =", flag)


if __name__ == "__main__":
    main()
```

## Verification

```text
[+] Opening connection to vm.daotao.antoanso.org on port 32784: Done
k = 6beacf329a4249c7
full ciphertext = f2231d89a750c8cabd51e743ec1835bc2c05ec5450c767b523e07630dfa1010b35f39e2703e6a8cee0d52ab1768d0f8b2e204be06565b684f1945609622ac112cf2da81e7218292783bac0ee83cd0275ad8de84e60a21fd39db3281ece59db01c13eb77443678122 (104 bytes, 13 block(s))
block 0: b'HCMUS-CT'
block 1: b'F{https:'
block 2: b'//en.wik'
block 3: b'ipedia.o'
block 4: b'rg/wiki/'
block 5: b'Data_Enc'
block 6: b'ryption_'
block 7: b'Standard'
block 8: b'#Minor_c'
block 9: b'ryptanal'
block 10: b'ytic_pro'
block 11: b'perties}'
block 12: b'\x08\x08\x08\x08\x08\x08\x08\x08'
flag = b'HCMUS-CTF{https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties}'
[*] Closed connection to vm.daotao.antoanso.org port 32784
```

## Flag

```text
HCMUS-CTF{https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties}
```

## Lessons Learned

- A "leak the key, but block replaying it" guard only stops the literal query you'd naively make - check whether the underlying primitive has an algebraic symmetry (like DES's complementation property) that produces a *different* query yielding equivalent information.
- DES's complementation property (`DES_K̄(P̄) = DES_K(P)‾`) holds unconditionally for every key and plaintext; any oracle built on raw DES-ECB (even wrapped in Even-Mansour-style whitening) inherits this symmetry regardless of the whitening values.
- Whitening (XOR before/after the block cipher) does not break bitwise-complement symmetries, because `X̄ XOR Y = (X XOR Y)‾` for any fixed `Y` - the complement commutes straight through XOR.
- A content-based guard (`if p in flag`) is a substring check, not a semantic one - any transformation of the guarded value that preserves recoverability but changes its literal bytes (complement, permutation, etc.) can slip past it.
- When a block cipher oracle looks locked down, test whether the cipher's own historical "minor cryptanalytic properties" apply to the exact wrapper construction in front of it before assuming the whitening/padding fully mitigates them.
