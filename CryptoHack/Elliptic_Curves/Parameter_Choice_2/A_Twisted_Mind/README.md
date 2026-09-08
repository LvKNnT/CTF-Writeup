# A Twisted Mind Writeup

## Summary

This live challenge exposes an x-only scalar multiplication oracle at `socket.cryptohack.org:13416`. Because the server accepts arbitrary `x0` values and returns only an x-coordinate public key, we can send points from the curve and its quadratic twist, solve smooth subgroup logs, combine the residues with CRT, and try the sign ambiguities.

Flag:

```text
crypto{tw1st_s3curity_of_x_0nly_ladder}
```

## Triage

The provided server source defines a 192-bit curve and an endpoint:

```json
{"option": "get_pubkey", "x0": "..."}
```

The solver connects to:

```text
socket.cryptohack.org:13416
```

The key weakness is that the ladder works with x-coordinates only. If we choose `x0` from the twist, the server still multiplies it by the secret scalar and leaks enough information to recover residues of that scalar.

## Solve Path

The script constructs the curve over `GF(p^2)` and finds one point with order matching the original curve and one with order matching the twist. For each selected point, it asks the server for the multiplied x-coordinate:

```python
payload = {"option": "get_pubkey", "x0": int(point[0])}
```

Each returned x-coordinate is lifted locally, and Pohlig-Hellman is applied to the smooth part of the point order. Since x-only multiplication cannot distinguish `P` from `-P`, the recovered residues may have either sign. The solver tries all sign combinations with CRT and submits each candidate private key.

## Exploit

The archived solver is `solve.sage`. It:

- builds the original curve, its quadratic twist, and the `GF(p^2)` model,
- chooses points with useful orders,
- recovers scalar residues with Pohlig-Hellman,
- combines candidates with CRT,
- submits candidate private keys to the remote service.

Run it with:

```bash
sage solve.sage
```

For verification, I used a temporary copy with only the final `io.interactive()` replaced by a short receive loop so the service responses were printed.

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice_2/A_Twisted_Mind
sage /tmp/a_twisted_mind_read.sage
```

Output:

```text
{"error": "Sorry, this is not my private key."}
{"error": "Sorry, this is not my private key."}
{"error": "Sorry, this is not my private key."}
{"message": "Congratulations, you found my private key!", "flag": "crypto{tw1st_s3curity_of_x_0nly_ladder}"}
```

## Flag

```text
crypto{tw1st_s3curity_of_x_0nly_ladder}
```

## Lessons Learned

- X-only ladders still need strict input validation.
- Twist points can leak scalar residues through smooth subgroups.
- X-coordinate sign ambiguity can be handled by trying both signs in the CRT reconstruction.
