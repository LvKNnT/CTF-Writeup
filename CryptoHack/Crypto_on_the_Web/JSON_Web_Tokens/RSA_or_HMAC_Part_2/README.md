# RSA or HMAC Part 2 Writeup

## Summary

The second RSA/HMAC challenge hides the public key but issues multiple RS256 tokens. The solve recovers the RSA public key from two signatures, then repeats the HS256 confusion attack.

Flag:

```text
crypto{thanks_silentsignal_for_inspiration}
```

## Triage

`solve.py` obtains two signed sessions and references PortSwigger's `sig2n` helper to recover the modulus. It then contains a base64-encoded recovered public key and forges an HS256 admin token.

## Solve Path

Generate two tokens:

```python
token1 = requests.get("https://web.cryptohack.org/rsa-or-hmac-2/create_session/sybau").json()["session"]
token2 = requests.get("https://web.cryptohack.org/rsa-or-hmac-2/create_session/67").json()["session"]
```

Recover the public key:

```bash
docker run --rm -it portswigger/sig2n <token1> <token2>
```

Then sign `{"admin": True}` as HS256 with the recovered public key bytes.

## Exploit

The checked-in script documents the full flow:

```bash
python solve.py
```

For PyJWT 2.x, the final HS256 token must be created with a manual signer or an older compatibility environment because modern PyJWT rejects asymmetric keys as HMAC secrets.

## Verification

```text
Welcome admin, here is your flag: crypto{thanks_silentsignal_for_inspiration}
```

## Flag

```text
crypto{thanks_silentsignal_for_inspiration}
```

## Lessons Learned

- Multiple RSA signatures can leak enough information to reconstruct a public key.
- Algorithm confusion remains exploitable even when the public key is not directly published.
