# Token Appreciation Writeup

## Summary

This JWT starter demonstrates that token payloads are only base64url-encoded, not encrypted. Decoding the middle JWT segment reveals the flag directly.

Flag:

```text
crypto{jwt_contents_can_be_easily_viewed}
```

## Triage

`solve.py` contains a complete JWT and decodes it with signature verification disabled.

## Solve Path

The payload segment is decoded without needing the signing key:

```python
payload = jwt.decode(ct, options={"verify_signature": False})
print(payload["flag"])
```

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
$ python solve.py
crypto{jwt_contents_can_be_easily_viewed}
```

## Flag

```text
crypto{jwt_contents_can_be_easily_viewed}
```

## Lessons Learned

- JWT contents are readable by anyone unless the token is separately encrypted.
- Do not store secrets in JWT claims just because the token is signed.
