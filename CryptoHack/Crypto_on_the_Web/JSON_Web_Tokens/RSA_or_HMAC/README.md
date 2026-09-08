# RSA or HMAC Writeup

## Summary

The service exposes an RSA public key but accepts a token claiming `HS256`. Treating the RSA public key bytes as an HMAC secret allows signing an admin token.

Flag:

```text
crypto{Doom_Principle_Strikes_Again}
```

## Triage

`solve.py` targets `/rsa-or-hmac/get_pubkey/` and `/authorise/`. The checked-in script expects old PyJWT behavior; modern PyJWT 2.x blocks asymmetric keys as HMAC secrets, so verification used an equivalent manual HS256 signer.

## Solve Path

Fetch the public key:

```python
response = requests.get("https://web.cryptohack.org/rsa-or-hmac/get_pubkey/")
PUBLIC_KEY = response.json()["pubkey"]
```

Sign an admin payload with HS256 using those public-key bytes as the HMAC key, then submit the forged token.

## Exploit

With PyJWT 1.5-style behavior:

```bash
python solve.py
```

With modern libraries, build the HS256 signature manually or use a compatibility environment that permits the confusion.

## Verification

```text
Welcome admin, here is your flag: crypto{Doom_Principle_Strikes_Again}
```

## Flag

```text
crypto{Doom_Principle_Strikes_Again}
```

## Lessons Learned

- Verifiers must pin the expected JWT algorithm server-side.
- Public RSA keys must never be reinterpreted as shared HMAC secrets.
