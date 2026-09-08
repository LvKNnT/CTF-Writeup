# size and basis Writeup

## Summary

This warm-up asks for a simple property of a lattice basis. The provided Sage script computes the requested value from the basis and prints the numeric answer.

Answer:

```text
9
```

## Triage

The folder contains `solve.sage`. The script encodes the challenge basis and evaluates the requested basis-size calculation exactly.

## Solve Path

The solve is direct: represent the basis in Sage, apply the formula from the challenge prompt, and print the resulting integer.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Lattices/size_and_basis
sage solve.sage
```

Output:

```text
9
```

## Flag

```text
9
```

## Lessons Learned

- Basis problems should be handled with exact arithmetic.
- The first lattice exercises establish the vocabulary used by later attacks.
- Keep computed challenge answers reproducible even when they are just integers.
