# Special Isogenies Writeup

## Summary

The challenge demonstrates that different generators for the same cyclic kernel can define the same isogeny codomain. The solve builds two order-5 kernels and confirms both lead to the same Montgomery coefficient.

Flag:

```text
199
```

## Triage

`solve.sage` creates two order-5 points, computes the two codomains, and compares the resulting j-invariants and Montgomery `A` values.

## Solve Path

The important observation is kernel equality:

```text
<P> = <uP> when u is a unit modulo ell
```

Therefore two different nonzero order-5 points in the same subgroup generate the same isogeny.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
Montgomery A (1st) = 199
Montgomery A (2nd) = 199
flag: A = 199
```

## Flag

```text
199
```

## Lessons Learned

- An isogeny's kernel is the subgroup, not the particular generator.
- Comparing both codomains is a good sanity check when reasoning about kernel generators.
