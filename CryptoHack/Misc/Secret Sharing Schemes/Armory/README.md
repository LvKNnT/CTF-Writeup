# Armory Writeup

## Summary

Armory uses deterministic Shamir shares where the first share's x-coordinate equals `sha256(secret)`. That makes the polynomial coefficients predictable from the share itself, so one share is enough to recover the secret constant term.

Flag:

```text
crypto{fr46m3n73d_b4ckup_vuln?}
```

## Triage

The provided share is:

```text
(105622578433921694608307153620094961853014843078655463551374559727541051964080, 25953768581962402292961757951905849014581503184926092726593265745485300657424)
```

The source builds deterministic coefficients from the secret hash. For the first share:

```text
x = coeff[1] = sha256(secret)
coeff[2] = sha256(coeff[1])
```

## Solve Path

With the provided point `(x, y)`, the solver sets:

```python
c1 = x
c2 = int.from_bytes(hashlib.sha256(c1.to_bytes(32, "big")).digest(), "big")
```

The share equation is:

```text
y = secret + c1*x + c2*x^2 mod PRIME
```

So the secret is recovered directly:

```python
secret = (y - c1 * x - c2 * x**2) % PRIME
```

## Exploit

The standalone exploit is `Misc/Secret Sharing Schemes/Armory/solve.sage`.

```bash
sage solve.sage
```

## Verification

Verified in WSL using the `sage` conda environment:

```text
crypto{fr46m3n73d_b4ckup_vuln?}
```

The script also verifies the recovered secret by checking both the hash-derived x-coordinate and the regenerated share.

## Flag

```text
crypto{fr46m3n73d_b4ckup_vuln?}
```

## Lessons Learned

- Shamir coefficients must be random; deterministic derivation from the secret can destroy the threshold property.
- If a coefficient is also exposed as an x-coordinate, the polynomial can become solvable from one share.
- Sanity checks against the original share are essential for secret-sharing attacks.
