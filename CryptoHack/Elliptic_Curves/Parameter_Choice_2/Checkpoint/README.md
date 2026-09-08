# Checkpoint Writeup

## Summary

This live challenge is an ECDH service at `socket.cryptohack.org:13419`. It accepts arbitrary peer public keys during key exchange and derives AES keys from the resulting shared x-coordinate. Sending invalid-curve points of small order leaks the server's static private key modulo many small orders, and CRT reconstructs the key.

Flag:

```text
crypto{nice_forward_secrecy_you_have_there!}
```

## Triage

The service starts by sending a client ephemeral public key, a static server public key, and an encrypted flag. It then allows repeated key-exchange starts with attacker-controlled `Qx` and `Qy`.

The important endpoint is:

```json
{"option": "start_key_exchange", "ciphersuite": "ECDHE_P256_WITH_AES_128", "Qx": "...", "Qy": "..."}
```

There is no validation that the supplied point is actually on P-256.

## Solve Path

The solver uses a list of precomputed invalid curves and points with small subgroup orders. For each point, it starts a key exchange, asks for a test message, and brute-forces the small scalar residue by checking which derived AES key decrypts the known plaintext:

```python
shared_x = curr_P[0]
key = sha256(str(shared_x).encode()).digest()[:16]
```

Each successful brute force gives:

```text
s = +/- r_i mod order_i
```

The sign ambiguity comes from x-coordinate symmetry. The script tries all sign combinations, combines residues with CRT, and verifies the candidate against the real P-256 server public key. Once the static private key is known, it decrypts the initially captured flag.

## Exploit

Use `test.sage`, which is the complete invalid-curve attack implementation. It:

- parses the initial server public key, client ephemeral key, and encrypted flag,
- sends 17 invalid-curve public keys,
- recovers one residue per small subgroup,
- performs CRT with sign brute force,
- verifies the recovered key against the real server public key,
- decrypts the flag.

Run it with:

```bash
sage test.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice_2/Checkpoint
sage test.sage
```

Output:

```text
[+] FOUND SECRET KEY s: 107877272975808673075857224548623160671418349486635874521039253499430648764183
[SUCCESS] FLAG: crypto{nice_forward_secrecy_you_have_there!}
```

## Flag

```text
crypto{nice_forward_secrecy_you_have_there!}
```

## Lessons Learned

- ECDH implementations must validate peer public keys before scalar multiplication.
- Known plaintext can turn a small-subgroup shared secret into a scalar-residue oracle.
- Static ECDH keys are especially dangerous when invalid-curve queries are possible.
