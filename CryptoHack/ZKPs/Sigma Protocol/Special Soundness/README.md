# Special Soundness Writeup

## Summary

This challenge demonstrates Schnorr special soundness. The prover reuses the same commitment for two different challenges, so two accepting transcripts reveal the witness, which is the padded flag.

Flag:

```text
crypto{specially_sound_sigmas}
```

## Triage

The service proves knowledge of `w` such that `y = g^w mod p`. It emits one commitment `a`, accepts a challenge `e1`, then rewinds badly and emits the same commitment again for challenge `e2`.

## Solve Path

For two accepted transcripts sharing `a`:

```text
z1 = r + e1*w mod q
z2 = r + e2*w mod q
```

Subtracting cancels the nonce:

```python
w = (Integer(z1 - z2) * inverse_mod(e1 - e2, q)) % q
```

The recovered witness is converted to bytes and truncated at the first closing brace.

## Exploit

Run the checked-in Sage solver:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13426`, sends two different challenges, extracts `w`, verifies `g^w = y`, and prints the flag prefix.

## Verification

Verified live against `socket.cryptohack.org:13426` from WSL using the `sage` conda environment:

```text
crypto{specially_sound_sigmas}
```

## Flag

```text
crypto{specially_sound_sigmas}
```

## Lessons Learned

- Reusing a Sigma-protocol nonce across challenges leaks the witness.
- Special soundness is an extractor: two accepting transcripts with the same commitment are enough.
- Challenge freshness is part of the security boundary.
