# RSA vs RNG Writeup

## Summary

RSA vs RNG generates RSA primes from a 512-bit linear congruential generator. Because the second prime is produced by iterating the same LCG from the first prime, the solver finds a root modulo `2^512` for `p * q(p) = n`, factors `n`, and decrypts the ciphertext.

Flag:

```text
crypto{pseudorandom_shamir_adleman}
```

## Triage

The source uses:

```python
state = (A * state + B) % 2**512
```

and `get_prime()` repeatedly advances the LCG until the state is prime. The public file contains `N`, `E`, and the encrypted flag.

## Solve Path

The Sage solver works in `Zp(2, 512)` and treats `p` as an unknown. It iterates possible LCG distances between the two primes:

```python
qq = A * qq + B
f = pp * qq - n
rs = [ZZ(p) for p, e in f.roots()]
```

When a root `p` divides `n`, the factorization is recovered. Standard RSA decryption then follows:

```python
d = inverse_mod(e, (p - 1) * (q - 1))
m = pow(c, d, n)
```

## Exploit

The standalone exploit is `Misc/PRNGs/RSA_vs_RNG/solve.sage`.

```bash
sage solve.sage
```

## Verification

Verified in WSL using the `sage` conda environment. The solver iterated candidate LCG gaps from `0` through `179`, factored `n`, and printed:

```text
b'crypto{pseudorandom_shamir_adleman}'
```

## Flag

```text
crypto{pseudorandom_shamir_adleman}
```

## Lessons Learned

- RSA primes must be independently random; predictable prime generation can make factoring algebraic.
- LCG state transitions give a direct relationship between consecutive prime candidates.
- Working modulo a power of two can expose roots that reveal integer factors.
