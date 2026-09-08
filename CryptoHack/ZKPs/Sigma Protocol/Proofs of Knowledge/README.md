# Proofs of Knowledge Writeup

## Summary

This is the honest Schnorr proof-of-knowledge flow. The challenge source gives the witness `w`, so the solve simply performs the Sigma protocol correctly and convinces the verifier.

Flag:

```text
crypto{sigma_protocol_complete!}
```

## Triage

The source defines a safe-prime group `p = 2q + 1`, generator `g = 2`, statement `y = g^w mod p`, and the witness `w`. The verifier expects a Schnorr transcript:

```text
a = g^r mod p
e = verifier challenge
z = r + e*w mod q
```

## Solve Path

Because the witness is known, no attack is needed. Choose a random nonce `r`, send `a = g^r`, receive `e`, then answer with:

```python
z = (r + e * w) % q
```

The verifier equation holds:

```text
g^z = a * y^e mod p
```

## Exploit

Use the standalone Sage script:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13425`, sends the commitment, receives the challenge, and returns the valid response.

## Verification

Verified live against `socket.cryptohack.org:13425` from WSL using the `sage` conda environment:

```text
{'flag': 'crypto{sigma_protocol_complete!}', 'message': 'You convinced me you know an `w` such that g^w = y mod p!'}
```

## Flag

```text
crypto{sigma_protocol_complete!}
```

## Lessons Learned

- A Sigma protocol transcript is straightforward when the witness is actually known.
- Local verifier assertions are useful before submitting protocol messages remotely.
- The Schnorr response hides `w` only when `r` is fresh and secret.
