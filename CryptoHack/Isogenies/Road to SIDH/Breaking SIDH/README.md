# Breaking SIDH Writeup

## Summary

This challenge attacks SIDH with the Castryck-Decru polynomial-time key recovery method. The adapted script recovers Bob's secret scalar, recomputes the shared j-invariant, and decrypts the flag.

Flag:

```text
crypto{welcome_to_the_future_of_isogenies}
```

## Triage

The folder contains the challenge source plus helper files from the Castryck-Decru Sage implementation: `richelot_aux.py`, `uvtable.py`, `helpers.py`, `castryck_decru_shortcut.sage`, and `speedup.sage`. `solve.sage` is the challenge-specific driver.

## Solve Path

The attack needs a distortion-like endomorphism. Since the base curve is `E0: y^2 = x^3 + x`, the script builds the CM automorphism:

```python
def two_i(P):
    if P.is_zero():
        return P
    x, y = P.xy()
    return 2 * P.curve()(-x, i * y)
```

Then it loads the Castryck-Decru shortcut machinery and recovers Bob's ternary secret. With `skB`, it rebuilds Bob's isogeny from Alice's public curve and decrypts the challenge ciphertext.

## Exploit

Run:

```bash
sage solve.sage
```

Key files:

- `solve.sage`: challenge-specific parameters, endomorphism, recovery, and decryption.
- `castryck_decru_shortcut.sage`: glue-and-split search and key recovery.
- `richelot_aux.py`, `uvtable.py`, `helpers.py`: supporting genus-2/Richelot routines.

## Verification

```text
$ sage solve.sage
Recovered Bob's secret scalar skB = 39990433064274301814750584859416466
shared_secret (j-invariant) = 421029616794078049119876392175476166609445985547836876842018877642464913*i + 352069885679613699249770049888753013437198958765200606577656343301753327
crypto{welcome_to_the_future_of_isogenies}
```

## Flag

```text
crypto{welcome_to_the_future_of_isogenies}
```

## Lessons Learned

- SIDH's auxiliary torsion data enables powerful key-recovery attacks.
- Challenge-specific curve choices can require adapting the distortion map used by a reference attack.
- Keep the reference implementation nearby, but isolate the challenge-specific driver for reproducibility.
