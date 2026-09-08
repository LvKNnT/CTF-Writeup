# Abelian SIDH Writeup

## Summary

This challenge tries to make SIDH more "abelian" by publishing dual-isogeny output on a shared point. The construction accidentally makes the shared secret independent of the secret kernels, so it can be computed directly from public parameters and used to decrypt the flag.

Flag:

```text
crypto{wait_I_thought_this_was_the_post_quantum_section}
```

## Triage

`source_68276706efaf461ee2c4266b44cce964.sage` defines the protocol and AES encryption. `output_40889cc050743c3dd764374fd6a064ba.txt` gives the public point and ciphertext.

## Solve Path

For an isogeny `phi` of degree `l^e`, the dual satisfies:

```text
phi_hat(phi(G)) = [l^e]G
```

So the alleged shared secret is public:

```python
shared_secret = (l_a^e_a * l_b^e_b) * G
```

The script hashes `str(shared_secret)` with SHA-256 and decrypts the AES-CBC ciphertext.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```text
$ sage solve.sage
b'crypto{wait_I_thought_this_was_the_post_quantum_section}'
```

## Flag

```text
crypto{wait_I_thought_this_was_the_post_quantum_section}
```

## Lessons Learned

- Dual-isogeny identities can destroy secrecy if protocol values collapse to public scalar multiplication.
- Always check whether a published expression is actually independent of the secret.
