# Dual Masters Writeup

## Summary

Only one image point is leaked, but it is enough to build the dual isogeny. Applying the dual to a torsion basis recovers the original kernel generator up to scale, and Weil pairings recover the hidden scalar.

Flag:

```text
crypto{but_I_only_gave_one_point?!}
```

## Triage

`output_dddb20abfff441071490f793e7851802.txt` provides `E_A` and `phi_a(Q_b)`. `solve.sage` rebuilds the dual from that single public image point.

## Solve Path

For a degree-`N` isogeny, the dual has kernel equal to the image of the `N`-torsion. Since `phi(Q_a)` has full order, it generates the dual kernel:

```python
psi = E_A.isogeny(phi_Q, algorithm="factored")
psi = psi.codomain().isomorphism_to(E) * psi
```

Pushing an `E_A[N]` basis through `psi` gives a generator `K = c(P_a + nQ_a)`. Pairings recover `c` and `cn`, so:

```python
n = (b * inverse_mod(a, N)) % N
```

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
b'crypto{but_I_only_gave_one_point?!}'
```

## Flag

```text
crypto{but_I_only_gave_one_point?!}
```

## Lessons Learned

- The dual isogeny can expose the original kernel structure.
- Pairings recover basis coordinates without enumerating a huge scalar space.
