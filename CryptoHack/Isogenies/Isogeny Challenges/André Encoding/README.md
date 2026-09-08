# André Encoding Writeup

## Summary

Each flag byte is encoded as the degree of a secret isogeny. Weil-pairing functoriality turns each leaked pair of image points into a discrete logarithm whose value is `2^64 * byte`, recovering the flag byte-by-byte.

Flag:

```text
crypto{weil_pairings_and_isogenies_are_best_friends}
```

## Triage

`source_b17b07370a5a535ebc81947d2f1d0d03.sage` describes the encoding. `output_6e30f9b5a6cd1356d485b369927bb106.txt` contains image-point pairs, and `solve.sage` implements the pairing attack.

## Solve Path

The codomain curve is not given directly, but two points on a short Weierstrass curve determine its coefficients:

```python
A = ((y1**2 - x1**3) - (y2**2 - x2**3)) / (x1 - x2)
B = (y1**2 - x1**3) - A * x1
```

For an isogeny `phi` and torsion points `P`, `Q`:

```text
e(phi(P), phi(Q)) = e(P, Q)^deg(phi)
```

The group order is smooth by construction, so `discrete_log` recovers each degree and the byte is `degree // 2^64`.

## Exploit

Run:

```bash
sage solve.sage
```

Key helpers:

- `parse_point(...)`: reconstructs `GF(p^2)` coordinates from JSON.
- `codomain_from_points(...)`: derives the image curve from two points.
- Pairing discrete log loop: recovers the encoded byte values.

## Verification

```text
$ sage solve.sage
b'crypto{weil_pairings_and_isogenies_are_best_friends}'
```

## Flag

```text
crypto{weil_pairings_and_isogenies_are_best_friends}
```

## Lessons Learned

- Pairings preserve isogeny degree in the exponent.
- If the relevant group order is smooth, pairing-derived DLOGs are practical.
- Two affine points can determine a short Weierstrass codomain when the model is known.
