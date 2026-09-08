# Honest Verifier Zero Knowledge Writeup

## Summary

This challenge asks for a Schnorr transcript for a verifier-provided challenge. Because the challenge is known before the commitment, the solver uses the honest-verifier zero-knowledge simulator and proves without knowing the witness.

Flag:

```text
crypto{so_honest_very_zero_knowledge}
```

## Triage

The server gives `e` and `y` first, then asks for `(a, z)` satisfying:

```text
g^z = a * y^e mod p
```

## Solve Path

The HVZK simulator chooses `z` first, then solves backward for a matching commitment:

```python
z = randint(1, q - 1)
a = (g^z * y^(-e)) mod p
```

Since `a` is derived from `z` and the already-known challenge, the final transcript verifies even though the solver never learns `w`.

## Exploit

Run:

```bash
sage solve.sage
```

The script connects to `socket.cryptohack.org:13427`, receives `e`, constructs a simulated transcript, and submits it.

## Verification

Verified live against `socket.cryptohack.org:13427` from WSL using the `sage` conda environment:

```text
{'flag': 'crypto{so_honest_very_zero_knowledge}', 'message': 'You convinced me you know an `w` such that g^w = y mod p!'}
```

## Flag

```text
crypto{so_honest_very_zero_knowledge}
```

## Lessons Learned

- Honest-verifier zero knowledge means transcripts can be simulated when the challenge is known in advance.
- A verifier that commits to `e` before seeing `a` enables the simulator as an attack.
- Valid transcripts do not necessarily imply witness knowledge outside the intended interaction order.
