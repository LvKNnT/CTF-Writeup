# SIDH Key Exchange Writeup

## Summary

Both SIDH private scalars are available, so the task is to implement public-key generation and the shared-secret computation correctly. Chaining the `2^ea` and `3^eb` isogenies recovers the common j-invariant, which decrypts the AES-CBC flag.

Flag:

```text
crypto{congratulations_you_are_an_isogenist!}
```

## Triage

`source_900b394e3f090ae9a3a0f1fb90f3c985.sage` leaves protocol functions to fill in. `solve.sage` implements `push_isogeny`, `gen_public_key`, and `gen_shared_secret`.

## Solve Path

For a secret scalar `s`, the kernel is `P + sQ`. The script evaluates the prime-power isogeny by repeated small-degree steps and pushes the other party's torsion basis through:

```python
EA, PA3, QA3 = gen_public_key(sA, 2, ea, P2, Q2, P3, Q3)
EB, PB2, QB2 = gen_public_key(sB, 3, eb, P3, Q3, P2, Q2)
```

Both sides compute the same j-invariant:

```python
shared_secret_A = gen_shared_secret(sA, 2, ea, EB, PB2, QB2)
shared_secret_B = gen_shared_secret(sB, 3, eb, EA, PA3, QA3)
assert shared_secret_A == shared_secret_B
```

That shared invariant is hashed to the AES key.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
shared_secret = 39554666822837634687042919937421151962429276036488365098856333817*i + 27806943580122755839932864641061887636351206881133282103584426284
b'crypto{congratulations_you_are_an_isogenist!}'
```

## Flag

```text
crypto{congratulations_you_are_an_isogenist!}
```

## Lessons Learned

- SIDH public keys include images of the other party's torsion basis.
- The final shared secret is an isomorphism invariant of the shared codomain curve.
