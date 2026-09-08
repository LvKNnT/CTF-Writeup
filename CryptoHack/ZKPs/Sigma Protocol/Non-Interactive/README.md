# Non-Interactive Writeup

## Summary

This challenge turns Schnorr into a non-interactive proof with Fiat-Shamir. The source gives the witness, so the solve constructs a real proof by hashing the commitment into the challenge and answering honestly.

Flag:

```text
crypto{shvzk_and_ss_to_nizk}
```

## Triage

The challenge expects a NIZK proof for `y = g^w mod p`. The verifier computes:

```text
e = SHA512(str(a)) mod 2^511
```

then checks the Schnorr equation.

## Solve Path

The solver chooses a fresh nonce, computes the commitment, derives the Fiat-Shamir challenge exactly as the server does, and responds with:

```python
r = randint(1, q - 1)
a = power_mod(g, int(r), p)
e = bytes_to_long(sha512(str(int(a)).encode()).digest()) % 2**511
z = (r + e * w) % q
```

## Exploit

Run:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13428`, reads `y`, submits `(a, z)`, and receives the flag if the proof verifies.

## Verification

Verified live against `socket.cryptohack.org:13428` from WSL using the `sage` conda environment:

```text
{'flag': 'crypto{shvzk_and_ss_to_nizk}', 'message': 'You convinced me you know an `w` such that g^w = y mod p!'}
```

## Flag

```text
crypto{shvzk_and_ss_to_nizk}
```

## Lessons Learned

- Fiat-Shamir security depends on matching the verifier's hash input exactly.
- Knowing the witness still gives a direct honest proof in the non-interactive setting.
- Serialization details, such as hashing `str(int(a))`, are part of the protocol.
