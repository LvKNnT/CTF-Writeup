# Where's the Supersingular Curve Writeup

## Summary

The challenge provides many Montgomery `A` coefficients over `p = 2^127 - 1` and asks which curve is supersingular. The provided Sage artifact builds each curve and checks `is_supersingular()`.

Flag:

```text
Elliptic Curve defined by y^2 = x^3 + 170141183460469230846243588177825628225*x^2 + x over Finite Field of size 170141183460469231731687303715884105727
```

## Triage

There is no `solve.sage`; the challenge data is in `curves_1e476e7d608576c05a13b269d1481602.sage`, and it already contains the loop over candidate curves.

## Solve Path

Each candidate is a Montgomery curve:

```python
E = EllipticCurve(F, [0, A, 0, 1, 0])
```

The script asks Sage which one is supersingular:

```python
for i, E in enumerate(curves):
    if E.is_supersingular():
        print(E.montgomery_model())
```

## Exploit

Run the provided Sage file:

```bash
sage curves_1e476e7d608576c05a13b269d1481602.sage
```

## Verification

```text
$ sage curves_1e476e7d608576c05a13b269d1481602.sage
Elliptic Curve defined by y^2 = x^3 + 170141183460469230846243588177825628225*x^2 + x over Finite Field of size 170141183460469231731687303715884105727
```

## Flag

```text
Elliptic Curve defined by y^2 = x^3 + 170141183460469230846243588177825628225*x^2 + x over Finite Field of size 170141183460469231731687303715884105727
```

## Lessons Learned

- Supersingularity testing is built into Sage's elliptic-curve methods.
- When the task gives many candidates, preserve the generated data and filter it programmatically.
