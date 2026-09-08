# DLOG on the Surface Writeup

## Summary

The challenge gives points `P`, `Q`, `R`, and `S` on a supersingular curve over `GF(p^2)`, where `R = aP + bQ` and `S = cP + dQ`. Weil pairings reduce the coefficient recovery to discrete logarithms in the smooth group of order `p + 1`, and the four coefficients decrypt the AES-CBC ciphertext.

Flag:

```text
crypto{now_try_writing_a_function_for_fast_torsion_basis_generation!}
```

## Triage

`output_a9fcd0db30822de938de639df287ab54.txt` contains the public points and ciphertext. `solve.sage` reconstructs the curve, derives the linear coefficients with pairings, and decrypts.

## Solve Path

With `e = Weil(P, Q)`, bilinearity gives:

```python
a = R.weil_pairing(Q, n).log(e) % n
b = -R.weil_pairing(P, n).log(e) % n
c = S.weil_pairing(Q, n).log(e) % n
d = -S.weil_pairing(P, n).log(e) % n
```

The script concatenates `a`, `b`, `c`, and `d`, hashes that string with SHA-256, and decrypts the ciphertext.

## Exploit

Run:

```bash
sage solve.sage
```

Key helpers:

- `decrypt_flag(...)`: derives the AES key from the recovered coefficients and decrypts the ciphertext.
- Pairing log lines: recover the four hidden scalar coefficients.

## Verification

```text
$ sage solve.sage
b'crypto{now_try_writing_a_function_for_fast_torsion_basis_generation!}\x0b...'
```

## Flag

```text
crypto{now_try_writing_a_function_for_fast_torsion_basis_generation!}
```

## Lessons Learned

- Pairing bilinearity can turn coordinates in a torsion basis into discrete logs.
- Smooth torsion orders make the logarithms practical.
- AES-CBC plaintext may need PKCS#7 padding stripped after decryption.
