# Prime Power Isogenies Writeup

## Summary

This CSIDH-road challenge asks what happens after repeatedly walking a `7`-isogeny cycle from the starting curve. The solve chains isogenies until the curve returns to one isomorphic to the original curve.

Flag:

```text
27
```

## Triage

`solve.sage` works over `GF(419)` with `E0: y^2 = x^3 + x`, whose order is `420`. It computes a sample `5^9` isogeny and then counts the number of `7`-isogeny steps needed to return to `E0`.

## Solve Path

The script repeatedly chooses a rational point of order `ell` and constructs the isogeny:

```python
P = order_ell_point(E, ell)
E = E.isogeny(P).codomain()
```

For `ell = 7`, the loop stops when `E.is_isomorphic(E0)` is true.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
Number of 7-isogenies to return to E0: 27
```

## Flag

```text
27
```

## Lessons Learned

- CSIDH actions are walks in an isogeny graph.
- Use curve isomorphism rather than raw coefficients when detecting that a walk returned to the same vertex.
