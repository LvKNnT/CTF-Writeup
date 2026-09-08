# gaussian reduction Writeup

## Summary

This challenge uses two-dimensional Gaussian lattice reduction. The solver reduces the given basis and computes the requested dot product of the reduced vectors.

Answer:

```text
7410790865146821
```

## Triage

The folder contains `solve.sage`, which implements the two-vector reduction loop. In dimension two, Gaussian reduction repeatedly swaps vectors and subtracts the nearest multiple of the shorter vector.

## Solve Path

The reduction produces:

```text
Reduced Vector a: (87502093, 123094980)
Reduced Vector b: (-4053281223, 2941479672)
```

The challenge asks for their dot product, which is:

```text
7410790865146821
```

## Exploit

Run:

```bash
sage solve.sage
```

The script performs Gaussian reduction and prints the reduced basis plus dot product.

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Lattices/gaussian_reduction
sage solve.sage
```

Output:

```text
Reduced Vector a: (87502093, 123094980)
Reduced Vector b: (-4053281223, 2941479672)
Dot Product: 7410790865146821
```

## Flag

```text
7410790865146821
```

## Lessons Learned

- Gaussian reduction is the two-dimensional version of lattice basis reduction.
- Rounding to the nearest multiple is the key step.
- Reduced bases make short-vector relationships easier to see.
