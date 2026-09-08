# Bounded Noise Writeup

## Summary

This offline LWE challenge provides many samples where the error is bounded to small values. The solver embeds the samples into a lattice, uses LLL to recover the short error vector, then solves the cleaned linear system for the secret. The secret encodes the flag in base `q`.

Flag:

```text
crypto{linearised_polynomials_for_bounded_errors}
```

## Triage

The folder contains `bounded_noise_e86bbb663297048112cdbd476951da41.sage`, `output.txt`, and `solve.sage`. The JSON output file stores matrix `A` and vector `b`.

The modulus is:

```text
q = 0x10001
```

## Solve Path

The samples satisfy:

```text
A * s + e = b mod q
```

Because the error entries are only `0` or `1`, the vector `(e, 1)` is very short. The solver builds a primal-style lattice with blocks `qI`, `A^T`, and `b`, then runs LLL and extracts a row ending in `1` or `-1` whose first entries are small.

After recovering `e`, it solves:

```text
A * s = b - e mod q
```

The secret vector is interpreted as base-`q` limbs of the flag integer.

## Exploit

Use `solve.sage`. It:

- loads `A` and `b`,
- uses 50 samples for reduction,
- recovers the error vector with LLL,
- solves for `s`,
- decodes the flag.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Bounded_Noise
sage solve.sage
```

Output:

```text
Error vector recovered!
Secret recovered.
Flag: crypto{linearised_polynomials_for_bounded_errors}
```

## Flag

```text
crypto{linearised_polynomials_for_bounded_errors}
```

## Lessons Learned

- Small LWE errors can be recovered as short lattice vectors.
- Once the error is known, LWE becomes a normal linear system modulo `q`.
- Secrets may encode plaintext as base-`q` limbs.
