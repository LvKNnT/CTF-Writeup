# Twisted CSIDH Isogenies Writeup

## Summary

This task introduces backward CSIDH graph steps using quadratic twists. The solve verifies the twist relation, then computes one backward 3-isogeny step from the base curve and returns its Montgomery coefficient.

Flag:

```text
261
```

## Triage

`solve.sage` works over the same small CSIDH field `GF(419)`. It defines helpers for twists, forward `ell`-isogeny steps, backward steps, and Montgomery normalization.

## Solve Path

A backward step is implemented by twisting, taking a forward step, then twisting back:

```python
def ell_isogeny_step_backwards(E, ell):
    return twist(ell_isogeny_step(twist(E), ell))
```

The script checks this against the `7`-isogeny cycle from the previous challenge, then applies a backward `3`-isogeny from `E0`.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
Sanity check passed: (k-1) forward 7-isogenies == 1 backward 7-isogeny (k = 27 )
Montgomery A: 261
flag: A = 261
```

## Flag

```text
261
```

## Lessons Learned

- On CSIDH volcano-style graphs, quadratic twists can model moving in the opposite direction.
- Sanity checks against a known cycle catch direction mistakes.
