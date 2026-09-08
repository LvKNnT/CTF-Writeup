# WOTS Up Writeup

## Summary

The challenge uses a one-time hash-chain signature scheme. A signature for one message reveals intermediate chain values, which can be advanced to forge a signature for the target message `Sign for flag` where the target digest bytes require fewer remaining hashes.

Flag:

```text
ECSC{h4sh1ng_ch41n_r34ct1on_ff_}
```

## Triage

`chal_dd02099acd9ffe4e8821daf5fc3b583c.py` defines the WOTS-like signer and encrypts the flag under a key derived from the target signature. `data.json` contains the public data and original signature. `solve.py` performs the chain advancement and decrypts the ciphertext.

## Solve Path

For each byte position, the signature element can only move forward along the SHA-256 chain. The solve compares the source and target digest bytes and advances usable signature components:

```python
for _ in range(dif):
    sus_sig = w.hash(sus_sig)
```

Once it has a valid target signature, it derives the AES key and decrypts the flag.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
$ python solve.py
b'ECSC{h4sh1ng_ch41n_r34ct1on_ff_}'
```

## Flag

```text
ECSC{h4sh1ng_ch41n_r34ct1on_ff_}
```

## Lessons Learned

- Winternitz-style one-time signatures must not be reused across messages.
- Revealed hash-chain intermediates can be advanced, but not reversed.
