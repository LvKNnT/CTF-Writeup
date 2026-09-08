# Micro Transmissions Writeup

## Summary

This challenge uses an elliptic curve whose subgroup is small enough for a practical discrete logarithm. The transcript gives a public key and ciphertext; recovering the private scalar allows the normal shared secret and AES key to be derived.

Flag:

```text
crypto{d0nt_l3t_n_b3_t00_sm4ll}
```

## Triage

The provided Sage source and output define the curve parameters, public points, IV, and ciphertext. The name and solver both point to the same issue: the effective scalar search space is too small.

The solve script directly attempts the discrete log:

```text
[*] Attempting to solve Discrete Log...
```

## Solve Path

The public key has the form:

```text
Q_A = n_A * G
```

On a properly sized subgroup this would be infeasible. Here, Sage can solve the DLP directly because the relevant order is small enough. After recovering `n_A`, the solver computes:

```text
S = n_A * Q_B
key = SHA1(str(S.x()))[:16]
```

and decrypts the AES-CBC ciphertext from the transcript.

## Exploit

Use `solve.sage`:

- load the challenge parameters,
- run Sage's discrete log routine,
- compute the ECDH shared secret,
- decrypt the flag.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice/Micro_Transmissions
sage solve.sage
```

Output:

```text
[+] Found n_a: 15423694994465574149
[*] Shared Secret (x): 92209717447332837440641806732517921920015580446111641942522142444036785043977
[SUCCESS] Flag: crypto{d0nt_l3t_n_b3_t00_sm4ll}
```

## Flag

```text
crypto{d0nt_l3t_n_b3_t00_sm4ll}
```

## Lessons Learned

- ECDLP security depends on the size of the subgroup actually used.
- Small-order or weak-order parameter choices can make direct discrete logs feasible.
- A valid-looking curve equation is not enough; the subgroup order must also be checked.
