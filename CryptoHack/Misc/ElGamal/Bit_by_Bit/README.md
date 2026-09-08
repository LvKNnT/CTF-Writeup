# Bit by Bit Writeup

## Summary

This CryptoHack Misc/ElGamal challenge leaks the flag one bit at a time through the quadratic-residue class of each ElGamal ciphertext. The provided `output.txt` contains many `(public_key, c1, c2)` samples, and `solve.py` recovers the message bits with Legendre symbols.

Flag:

```text
crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}
```

## Triage

The source encrypts each flag bit as `me = (padding << 1) + bit`, then ElGamal-encrypts `me` modulo a prime `q`. The notes identify the encryption equations:

```text
c1 = g^y mod q
s  = h^y mod q
c2 = s * me mod q
```

## Solve Path

The attack uses the multiplicativity of the Legendre symbol:

```text
L(c2) = L(s) * L(me)
```

For each sample, `solve.py` computes `L(h)` and `L(c1)` to infer the parity of the secret exponents when `g` is a quadratic non-residue. That gives `L(s)`, and therefore `L(me)`. Since `me` is either an even padded value or that value plus one, comparing `L(me)` with `L(2)` distinguishes likely `0` and definite `1` bits.

The script then rebuilds the integer little-endian bit by bit:

```python
for i, bit in enumerate(recovered_bits):
    m += bit * (2**i)
```

## Exploit

The standalone exploit is `Misc/ElGamal/Bit_by_Bit/solve.py`. It parses `output.txt`, evaluates Legendre symbols for every ciphertext, reconstructs the bit string, and prints `long_to_bytes(m)`.

Run it from the challenge directory:

```bash
python solve.py
```

## Verification

Verified in WSL using the `sage` conda environment:

```text
b'crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}'
```

## Flag

```text
crypto{s0m3_th1ng5_4r3_pr3served_4ft3r_encrypti0n}
```

## Lessons Learned

- ElGamal is multiplicatively homomorphic, so residue-class information can survive encryption.
- Bitwise encryption with structured encodings can leak through parity or quadratic-residue side channels.
- Legendre symbols are often enough to distinguish two message classes without solving discrete logs.
