# Secret Exponents Writeup

## Summary

The challenge asks for the Montgomery coefficient reached by applying a secret-exponent-style CSIDH walk. The solve composes the required small-prime isogeny steps and converts the result to Montgomery form.

Flag:

```text
404
```

## Triage

`solve.sage` sets up the small field `GF(419)`, starts from `E0`, follows the requested isogeny path, and prints the codomain j-invariant and Montgomery `A`.

## Solve Path

The key operation is one `ell`-isogeny step from a curve:

```python
P = order_ell_point(E, ell)
E = E.isogeny(P).codomain()
```

After applying the exponent vector, the answer is normalized through Sage's Montgomery model:

```python
Emont = E.montgomery_model()
_, A, _, _, _ = Emont.a_invariants()
```

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
j-invariant: 48
Montgomery A: 404
flag: A = 404
```

## Flag

```text
404
```

## Lessons Learned

- CSIDH public keys are usually represented by a Montgomery `A` coefficient.
- Small toy parameters are useful for checking each graph-walk step explicitly.
