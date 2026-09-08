# JWT Secrets Writeup

## Summary

The service signs HS256 JWTs with the weak key `secret`. Forging an admin token with that key gives access to the flag endpoint.

Flag:

```text
crypto{jwt_secret_keys_must_be_protected}
```

## Triage

`solve.py` creates an HS256 token with `{"admin": True}` and key `secret`. The original file prints the token; submitting it to the challenge endpoint returns the flag.

## Solve Path

Create the forged token:

```python
encoded = jwt.encode({"admin": True}, key="secret", algorithm="HS256")
```

Then authorize it:

```text
https://web.cryptohack.org/jwt-secrets/authorise/<token>/
```

## Exploit

Run:

```bash
python solve.py
```

Then submit the printed JWT to the authorize endpoint.

## Verification

Using the token generated from the weak secret:

```text
Welcome admin, here is your flag: crypto{jwt_secret_keys_must_be_protected}
```

## Flag

```text
crypto{jwt_secret_keys_must_be_protected}
```

## Lessons Learned

- HS256 security depends entirely on the secrecy and entropy of the shared key.
- Common/default JWT secrets should be treated as compromised.
