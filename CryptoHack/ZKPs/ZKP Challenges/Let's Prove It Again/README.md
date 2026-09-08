# Let's Prove It Again Writeup

## Summary

Let's Prove It Again fixes the single-proof interval trick enough to require two chosen-seed proofs. The solver recovers the same hidden flag integer by comparing two proof equations, trying possible hash salts, and validating the result against both public statements.

Flag:

```text
crypto{CRT_1s_m4gic_for_cryptanalysis}
```

## Triage

The service alternates between server proofs and player-controlled refreshes. The solver uses two known seeds:

```python
KNOWN_SEEDS = [b"again-one", b"again-two"]
```

Each seed lets the solver reconstruct the prime `p` used in that proof.

## Solve Path

For each proof, the lifted equation is one of two possible integer terms:

```python
terms = [p - 1 - r, p - 1 - r - (p - 1)]
```

The challenge hash also includes a salt in a small range. The solver enumerates term choices and salt pairs, then solves:

```text
x = (b1 - b2) / (c1 - c2)
```

Valid candidates must fit the expected byte size and satisfy both discrete-log statements:

```python
power_mod(g1, x, p1) == y1
power_mod(g2, x, p2) == y2
```

Finally the script reverses the nonce XOR and removes the inserted junk byte.

## Exploit

Run:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13431`, collects two chosen-seed records, recovers the hidden integer, and prints the flag.

## Verification

Verified live against `socket.cryptohack.org:13431` from WSL using the `sage` conda environment:

```text
[+] recovered hash salts = 194, 293
crypto{CRT_1s_m4gic_for_cryptanalysis}
```

## Flag

```text
crypto{CRT_1s_m4gic_for_cryptanalysis}
```

## Lessons Learned

- Two noisy linear relations can remove unknown bounded randomness.
- Small hidden salts are brute-forceable when the rest of the equation is known.
- Chosen randomness in proof systems is often enough to align multiple leaks.
