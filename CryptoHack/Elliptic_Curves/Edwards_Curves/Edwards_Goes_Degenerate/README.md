# Edwards Goes Degenerate Writeup

## Summary

This challenge provides a twisted Edwards key exchange transcript and an AES-CBC ciphertext. The public points are chosen on a degenerate Edwards curve branch with `x = 0`, so the group law collapses to multiplication of the `y` coordinate modulo `p`. That turns Alice's private key recovery into an ordinary discrete logarithm.

Flag:

```text
crypto{degenerates_will_never_keep_a_secret}
```

## Triage

The provided files are `source_4dbd62b026616ba5f1c257632d4972c4.py`, `output_09a749469d6013824d26be039494ae00.txt`, and local solvers. The output gives the generator, public keys, IV, and ciphertext, while the source shows that the shared secret is hashed into an AES key.

The important observation is that all published points have `x = 0`. On this degenerate branch, scalar multiplication can be modeled by exponentiation of the `y` coordinate.

## Solve Path

For points of the form `(0, y)`, Alice's public key satisfies:

```text
Y_A = Y_G^n_A mod p
```

So the private key can be recovered with a finite-field discrete log. Once `n_A` is known, the shared secret is computed from Bob's public key in the same collapsed group, and the AES key is `SHA1(str(shared_secret))[:16]`.

## Exploit

The standalone solver is `solve.py`. It:

- reads the challenge constants from the transcript,
- solves `Y_A = Y_G^n_A mod p`,
- computes the shared secret from Bob's public key,
- decrypts the AES-CBC ciphertext.

Run it with:

```bash
python solve.py
```

## Verification

The solver was re-run under the WSL Sage conda environment:

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Edwards_Curves/Edwards_Goes_Degenerate
python solve.py
```

Output:

```text
[+] Found Alice's private key: 22177185339821817642584340290303072361216253354374422848549320419774574392697
[+] Calculated Shared Secret: 46772665978493537897908538371128954540513401182358149976776838971792020458357
[SUCCESS] Flag: crypto{degenerates_will_never_keep_a_secret}
```

## Flag

```text
crypto{degenerates_will_never_keep_a_secret}
```

## Lessons Learned

- Degenerate curve components can destroy the intended elliptic-curve group structure.
- Always validate that public points lie in the intended subgroup and curve component.
- If an elliptic-curve operation collapses to a simpler algebraic group, solve the simpler problem directly.
