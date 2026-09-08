# Let's Prove It Writeup

## Summary

Let's Prove It leaks a hidden flag integer from a flawed proof relation. After forcing a known PRNG seed, the solver knows the modulus `p`, receives a proof, bounds the prover nonce, and recovers the hidden flag from a narrow interval.

Flag:

```text
crypto{HNP_1s_a_b3aut1ful_Pr0blem_no?}
```

## Triage

The server prints a nonce, lets the player request one proof, then allows a controlled refresh seed. The solver chooses:

```python
seed = b"letsprove"
```

This makes the generated prime reproducible locally from `random.Random(nonce + seed)`.

## Solve Path

The proof relation gives:

```text
r = v - c*x mod (p - 1)
```

where `x` is the masked flag integer and `0 <= v < 2^512`. Because the flag and hash sizes make `c*x` smaller than `p - 1` with high probability, the lift has only a tiny candidate interval:

```python
lo = ceil((p - 1 - r) / c)
hi = floor((p - 1 - r + 2^512 - 1) / c)
```

The solver tests candidates by checking `g^x = y mod p`, then undoes the nonce XOR and removes one injected junk byte.

## Exploit

Run:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13430`, refreshes with a known seed, recovers the hidden integer, and prints the cleaned flag.

## Verification

Verified live against `socket.cryptohack.org:13430` from WSL using the `sage` conda environment:

```text
crypto{HNP_1s_a_b3aut1ful_Pr0blem_no?}
```

## Flag

```text
crypto{HNP_1s_a_b3aut1ful_Pr0blem_no?}
```

## Lessons Learned

- If prover randomness is bounded and partly algebraically exposed, the witness may lie in a tiny interval.
- Allowing attacker-controlled seeds can make supposedly random protocol parameters reproducible.
- Padding/junk bytes do not help if the full hidden integer can be recovered.
