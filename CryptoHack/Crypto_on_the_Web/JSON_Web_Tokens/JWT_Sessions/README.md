# JWT Sessions Writeup

## Summary

This challenge accepts unsigned JWTs using `alg: none`. Building a token with an admin claim and no signature authorizes successfully.

Flag:

```text
crypto{The_Cryptographic_Doom_Principle}
```

## Triage

`solve.py` creates a token with `algorithm="none"` and an admin claim. The correct live endpoint for this challenge is `/no-way-jose/authorise/<token>/`.

## Solve Path

The forged token has a header with no signing algorithm:

```python
encoded = jwt.encode({"admin": "sybau"}, key="", algorithm="none")
```

Any accepted admin-like value is enough because the signature is not checked.

## Exploit

Run:

```bash
python solve.py
```

Submit the printed token:

```text
https://web.cryptohack.org/no-way-jose/authorise/<token>/
```

## Verification

```text
Welcome admin, here is your flag: crypto{The_Cryptographic_Doom_Principle}
```

## Flag

```text
crypto{The_Cryptographic_Doom_Principle}
```

## Lessons Learned

- Never allow clients to select `alg: none` for authenticated sessions.
- Algorithm confusion and disabled verification both violate the core JWT trust boundary.
