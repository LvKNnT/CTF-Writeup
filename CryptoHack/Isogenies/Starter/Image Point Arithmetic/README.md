# Image Point Arithmetic Writeup

## Summary

This starter task asks for elliptic-curve point addition modulo `p = 63079`. The solve script applies the affine addition slope formula to the two provided points.

Flag:

```text
P + Q = (37097, 6657)
```

## Triage

The folder contains `solve.sage`, with the coordinates of `P`, `Q`, and the field prime.

## Solve Path

For distinct affine points, the slope is:

```text
lambda = (Qy - Py) / (Qx - Px) mod p
```

Then:

```text
Rx = lambda^2 - Px - Qx mod p
Ry = lambda * (Px - Rx) - Py mod p
```

The script computes exactly that with Sage's `inverse_mod`.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
P + Q = (37097, 6657)
```

## Flag

```text
P + Q = (37097, 6657)
```

## Lessons Learned

- Affine point addition reduces to modular inversion plus two coordinate formulas.
- Sage's `inverse_mod` keeps the arithmetic clean and avoids sign mistakes.
