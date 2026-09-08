# Better than Linear Writeup

## Summary

This challenge asks for the codomain of a large prime-degree isogeny. Sage's `velusqrt` implementation computes the isogeny in roughly square-root complexity instead of using linear Velu formulas.

Flag:

```text
48495725269*i + 91493879515
```

## Triage

`solve.sage` contains the curve over `GF(p^2)`, the kernel generator `K`, and uses `algorithm="velusqrt"`.

## Solve Path

The kernel point is passed directly to Sage's isogeny constructor:

```python
phi = E.isogeny(K, algorithm="velusqrt")
E2 = phi.codomain()
print("flag:", E2.j_invariant())
```

The j-invariant is the answer.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
j-invariant: 48495725269*i + 91493879515
flag: 48495725269*i + 91493879515
```

## Flag

```text
48495725269*i + 91493879515
```

## Lessons Learned

- Large-degree isogenies need better algorithms than naive Velu summation.
- Sage's `velusqrt` is the intended practical route for this size.
