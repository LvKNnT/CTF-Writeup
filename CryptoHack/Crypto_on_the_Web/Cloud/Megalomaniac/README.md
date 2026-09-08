# Megalomaniac Writeup

## Summary

The login flow decrypts RSA private-key material with malleable AES-ECB encryption. Flipping a block in the encrypted private key corrupts one RSA prime and turns the login response into a partial RSA-CRT fault oracle; Coppersmith recovers the missing bytes and factors `N`.

Flag:

```text
crypto{M4lleaBl3_3nCRypt1on_g0n3_wr0nG_:'(}
```

## Triage

The source server runs on `socket.cryptohack.org:13408`. `solve.sage` receives Alice's encrypted crypto material, modifies `share_key_enc`, submits a known encrypted SID, factors the RSA modulus, and decrypts the encrypted flag.

## Solve Path

The script corrupts a block inside `q` while preserving `p`:

```python
faulty_share_key[160] = operator.xor(faulty_share_key[160], 0xFF)
```

The response returns `SID[:-16]`, so the low 128 bits are missing. Model them as a small root:

```python
f = (truncated_s_prime * 2**128 + x) - S
roots = f.small_roots(X=2**128, beta=0.4)
p = gcd(S_prime - S, N)
```

Then derive `SHA256(p || q)` and decrypt the flag ciphertext.

## Exploit

Run with Sage:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
[+] Successfully factored N!
[SUCCESS] FLAG: crypto{M4lleaBl3_3nCRypt1on_g0n3_wr0nG_:'(}
```

## Flag

```text
crypto{M4lleaBl3_3nCRypt1on_g0n3_wr0nG_:'(}
```

## Lessons Learned

- ECB encryption is malleable block-by-block.
- RSA-CRT fault behavior can leak a factor of the modulus.
- Coppersmith is useful when the oracle gives all but a bounded number of bits.
