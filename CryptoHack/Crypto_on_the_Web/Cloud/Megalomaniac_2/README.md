# Megalomaniac 2 Writeup

## Summary

The second challenge keeps the same core weakness: encrypted RSA key material can be tampered with before login. A controlled corruption produces a partial faulty decrypt, and Coppersmith recovers the missing low bits so the RSA modulus can be factored.

Flag:

```text
crypto{W4s_th4t_rea11y_Any_hard3r??}
```

## Triage

The live service is `socket.cryptohack.org:13409`. `solve.sage` is structurally the same as the first exploit and uses the returned malformed SID as a factorization oracle.

## Solve Path

The known SID plaintext `S` is encrypted under the public key. After key-material tampering, the server returns a truncated faulty plaintext `S'`. The solve recovers the missing 128 bits with:

```python
f = (truncated_s_prime * shift + x) - S
roots = f.small_roots(X=2**128, beta=0.4)
p = gcd(S_prime - S, N)
```

The recovered `p` and `q` reproduce the flag key derivation.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
[+] Successfully factored N!
[SUCCESS] FLAG: crypto{W4s_th4t_rea11y_Any_hard3r??}
```

## Flag

```text
crypto{W4s_th4t_rea11y_Any_hard3r??}
```

## Lessons Learned

- Minor protocol changes do not help if the same malleable encrypted state is trusted.
- Factoring RSA from a faulty CRT relation becomes practical with enough known plaintext bits.
