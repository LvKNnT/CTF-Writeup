# Mister Saplins The Prover Writeup

## Summary

Mister Saplins The Prover extends the Merkle preview idea. Stable flag-only leaves can be queried across fresh connections, while a negative index leaks the missing left branch for the active session, allowing the solver to brute-force one unknown byte and submit the correct root.

Flag:

```text
crypto{M3rkle_Trees__funny_if_U_can_replay_atk}
```

## Triage

The service stores secret bytes followed by the flag in Merkle leaves. The checked-in solve notes that leaves `3..7` are entirely flag bytes and stable across connections, while early leaves include per-session randomness.

## Solve Path

The solver opens separate connections to fetch stable previews for leaves `3..7`:

```python
h3, h4, h5, h6, h7 = [get_preview(i) for i in range(3, 8)]
```

On the active session, a negative index bypasses the normal preview restriction:

```python
res = conn.query({"option": "get_node", "node": -1})
```

That leaks the left branch hash `H(h0 || h1)`. The only missing value is one byte before the known `crypto{` prefix, so the solver brute-forces `0..255`, rebuilds the root, and submits `do_proof` until the server returns the flag.

## Exploit

Run:

```bash
sage solve.sage socket.cryptohack.org 13432
```

Without arguments, the script defaults to localhost port `13432`, so pass the remote host/port for the live challenge.

## Verification

Verified live against `socket.cryptohack.org:13432` from WSL using the `sage` conda environment:

```text
b'crypto{M3rkle_Trees__funny_if_U_can_replay_atk}'
```

## Flag

```text
crypto{M3rkle_Trees__funny_if_U_can_replay_atk}
```

## Lessons Learned

- Negative indexes can bypass naive index restrictions in Python services.
- Stable cross-session Merkle leaves can be combined with one live-session leak.
- Known flag prefixes make small unknown byte windows brute-forceable.
