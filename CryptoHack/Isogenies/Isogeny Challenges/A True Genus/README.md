# A True Genus Writeup

## Summary

The challenge encodes a binary secret through relationships between supersingular curves. The solve compares a genus-character-style invariant across triples of curves, reconstructs the secret bitstring, and decrypts the AES-CBC flag.

Flag:

```text
crypto{Gauss_knew_how_to_break_CSIDH???}
```

## Triage

`output_6cddf765597314b7a2c5b737c98233b2.txt` contains `iv`, `ct`, and a list of challenge triples `EA`, `EB`, and `EC`. `output.py` parses that data for Sage, and `solve.sage` contains the recovery logic.

## Solve Path

For each triple, the script computes a sign-like value with `compute_supersingular_delta`:

```python
if compute_supersingular_delta(base, EA) == compute_supersingular_delta(EB, EC):
    key += "1"
else:
    key += "0"
```

The bitstring is reversed before conversion to an integer:

```python
secret = int(key[::-1], 2)
```

That integer is serialized to 8 bytes, hashed with SHA-256, and used as the AES-CBC key.

## Exploit

Run:

```bash
sage solve.sage
```

Key helpers:

- `compute_supersingular_delta(E_0, E_test)`: computes the curve relation bit.
- `decrypt_flag(iv, ct, secret)`: derives the AES key and decrypts the ciphertext.

## Verification

```text
$ sage solve.sage
b'crypto{Gauss_knew_how_to_break_CSIDH???}\x08...'
```

## Flag

```text
crypto{Gauss_knew_how_to_break_CSIDH???}
```

## Lessons Learned

- Structural curve invariants can leak secret bits even without an obvious scalar.
- Bit order matters; the script reverses the recovered bitstring before decryption.
- Keep generated output parsing separate when the challenge data is large.
