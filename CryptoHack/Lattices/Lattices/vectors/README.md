# vectors Writeup

## Summary

This introductory challenge checks basic vector arithmetic. The solver evaluates the requested vector expression exactly in Sage and prints the resulting scalar answer.

Answer:

```text
702
```

## Triage

The only artifact is `solve.sage`. It defines the challenge vectors and performs the requested arithmetic directly.

## Solve Path

The challenge is not a cryptanalytic attack; it is a warm-up for manipulating vectors before using lattice reduction. The solve path is to encode the vectors in Sage, apply the expression from the prompt, and print the final scalar.

## Exploit

Run:

```bash
sage solve.sage
```

The script performs the vector operations and prints the answer.

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Lattices/vectors
sage solve.sage
```

Output:

```text
702
```

## Flag

```text
702
```

## Lessons Learned

- Lattice problems rely on exact vector arithmetic, so small warm-ups are useful.
- Sage vectors avoid hand-calculation mistakes.
- A challenge answer may be a numeric value instead of a formatted flag.
