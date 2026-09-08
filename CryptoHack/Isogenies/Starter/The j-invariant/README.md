# The j-invariant Writeup

## Summary

This starter challenge asks for the j-invariant of the elliptic curve over `GF(163)` with Weierstrass coefficients `[0, 0, 0, 145, 49]`. Sage computes the invariant directly from the curve model.

Flag:

```text
127
```

## Triage

The challenge folder contains `solve.sage`, which constructs the curve and prints `E.j_invariant()`.

## Solve Path

The curve is created over the finite field and Sage handles the invariant formula:

```python
E = EllipticCurve(GF(163), [0, 0, 0, 145, 49])
print(E.j_invariant())
```

## Exploit

Run the checked-in solve script:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
127
```

## Flag

```text
127
```

## Lessons Learned

- Sage's elliptic-curve object exposes standard invariants directly.
- For starter arithmetic tasks, the safest solve is to model the exact curve rather than retype formulas by hand.
