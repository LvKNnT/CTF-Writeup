# gram schmidt Writeup

## Summary

This challenge asks for Gram-Schmidt orthogonalization of a given vector basis. The solver uses Sage's exact rational arithmetic to compute the orthogonal vectors.

Answer:

```text
u4 = (-1456/4023, 273/298, 1729/8046, 455/4023)
```

## Triage

The script defines four 4-dimensional vectors and applies Gram-Schmidt manually or through exact vector operations. Exact rationals are important because decimal approximations can lose the challenge answer.

## Solve Path

For each vector `v_i`, subtract its projections onto the previous orthogonal vectors:

```text
u_i = v_i - sum((v_i . u_j) / (u_j . u_j)) * u_j
```

The final vector requested by the challenge is `u4`.

## Exploit

Run:

```bash
sage solve.sage
```

The script prints the original basis and the orthogonal basis.

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Lattices/gram_schmidt
sage solve.sage
```

Output:

```text
u4 = (-1456/4023, 273/298, 1729/8046, 455/4023)
```

## Flag

```text
(-1456/4023, 273/298, 1729/8046, 455/4023)
```

## Lessons Learned

- Gram-Schmidt turns a basis into mutually orthogonal directions.
- Exact rational arithmetic avoids rounding errors.
- Orthogonalized bases are central to understanding LLL and lattice reduction.
