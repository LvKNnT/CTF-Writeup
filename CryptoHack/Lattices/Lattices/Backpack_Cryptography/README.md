# Backpack Cryptography Writeup

## Summary

This challenge is a knapsack cryptosystem instance. The ciphertext is a subset-sum over a public key, and the plaintext bits can be recovered by embedding the relation into a lattice and applying LLL.

Flag:

```text
crypto{my_kn4ps4ck_1s_l1ghtw31ght}
```

## Triage

The provided source and output give a long public key list and an encrypted flag integer. The public key has 272 entries, matching a bit-vector plaintext representation.

## Solve Path

The solver builds a lattice that encodes:

```text
sum(bit_i * public_key_i) = encrypted_flag
```

The identity block is scaled by `2`, a row of ones is added to bias the solution toward binary coefficients, and the public key plus ciphertext column is appended. After LLL, the target row has entries from a two-value set, which are mapped back to bits.

```python
if len(set(i[:-1])) == 2:
    F = i
```

The recovered bit string is reversed and converted to bytes.

## Exploit

Use `solve.sage`. It:

- loads the public key and encrypted flag,
- constructs the knapsack lattice,
- runs LLL,
- extracts the binary row,
- decodes the flag.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Lattices/Backpack_Cryptography
sage solve.sage
```

Output:

```text
b'crypto{my_kn4ps4ck_1s_l1ghtw31ght}'
```

## Flag

```text
crypto{my_kn4ps4ck_1s_l1ghtw31ght}
```

## Lessons Learned

- Subset-sum equations can be embedded as lattice problems.
- Low-density knapsack instances are often vulnerable to LLL.
- The shortest lattice vector can directly encode plaintext bits.
