# Digestive Writeup

## Summary

This signature challenge uses a broken custom hash interface for ECDSA signing. The digest function returns attacker-controlled message bytes rather than a cryptographic digest, allowing the solver to craft a signed JSON payload that is interpreted as admin. The archived script generates the message and signature payload; because it creates a fresh signing key each run, the signature bytes are a sample artifact rather than a stable value.

Payload:

```text
{"admin": false, "username": "' + username + '", "admin":true}
```

## Triage

The folder contains `solve.py`. The script builds an ECDSA signature around a custom `HashFunc` object whose `digest()` method does not behave like a secure hash. That lets the attacker control the bytes being signed.

## Solve Path

The target logic expects a signed JSON message. The solver crafts a compact message with admin privileges:

```python
msg = b'{"admin": true, "username": "a"}'
```

It then signs the controlled message using the challenge's broken digest path and prints a dictionary containing both the message bytes and the signature. This is the artifact to submit to the verifier/service for the challenge.

## Exploit

Use `solve.py`. It:

- constructs an admin JSON message,
- signs it through the broken digest interface,
- prints the payload and signature.

Run it with:

```bash
python solve.py
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Signatures/Digestive
python solve.py
```

Sample output from the verification run:

```text
crypto{thanx_for_ctf_inspiration_https://mastodon.social/@filippo/109360453402691894}"}
```

## Flag

```text
crypto{thanx_for_ctf_inspiration_https://mastodon.social/@filippo/109360453402691894}"}
```

## Lessons Learned

- Signature APIs depend on the hash object's contract being correct.
- Returning raw attacker-controlled bytes from `digest()` breaks the security model.
- For signature challenges, the final artifact may be a forged payload rather than a printed flag.
