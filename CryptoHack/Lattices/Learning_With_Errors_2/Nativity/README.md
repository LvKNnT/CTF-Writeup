# Nativity Writeup

## Summary

This offline Regev/LWE-style challenge provides a public key and many ciphertexts. The solver uses LLL to recover the secret vector, then decrypts the ciphertexts into the flag.

Flag:

```text
crypto{flavortext-flag-coprime-regev-yadda-yadda}
```

## Triage

The folder includes `nativity_3be57fcbd4a8a94592a21f621031b233.py`, `public_key.txt`, `ciphertexts.txt`, and `solve.sage`. The public key and ciphertext data are enough to run the attack offline.

## Solve Path

The public key creates an LWE lattice where the secret and error terms form unusually short vectors. The solver builds the corresponding lattice, applies LLL, and verifies that the secret `s` was recovered.

Once `s` is known, each ciphertext can be decrypted by subtracting the secret dot product and decoding the resulting bit/byte stream.

## Exploit

Use `solve.sage`. It:

- loads the public key and ciphertext data,
- runs LLL to recover the secret vector,
- decrypts the ciphertexts,
- prints the flag.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Nativity
sage solve.sage
```

Output:

```text
Running LLL...
Secret s recovered successfully!
Decrypting...
crypto{flavortext-flag-coprime-regev-yadda-yadda}
```

## Flag

```text
crypto{flavortext-flag-coprime-regev-yadda-yadda}
```

## Lessons Learned

- Regev-style encryption is still an LWE instance underneath.
- Weak parameters can let LLL recover the secret vector directly.
- After secret recovery, LWE ciphertext decryption is simple modular arithmetic.
