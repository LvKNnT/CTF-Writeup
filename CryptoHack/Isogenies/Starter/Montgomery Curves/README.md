# Montgomery Curves Writeup

## Summary

The challenge gives a short Weierstrass curve over `GF(1912812599)` and asks for an equivalent Montgomery model. Sage can convert the curve using `montgomery_model()`.

Flag:

```text
Elliptic Curve defined by y^2 = x^3 + 723347356*x^2 + x over Finite Field of size 1912812599
```

## Triage

`solve.sage` builds the curve from the given coefficients `[0, 0, 0, 312589632, 654443578]` and prints the Montgomery model.

## Solve Path

The solve is a direct model conversion:

```python
E = EllipticCurve(GF(1912812599), [0, 0, 0, 312589632, 654443578])
print(E.montgomery_model())
```

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
Elliptic Curve defined by y^2 = x^3 + 723347356*x^2 + x over Finite Field of size 1912812599
```

## Flag

```text
Elliptic Curve defined by y^2 = x^3 + 723347356*x^2 + x over Finite Field of size 1912812599
```

## Lessons Learned

- Sage can convert supported elliptic curves to Montgomery form automatically.
- Keeping the exact finite field in the model matters because isomorphism data depends on the base field.
