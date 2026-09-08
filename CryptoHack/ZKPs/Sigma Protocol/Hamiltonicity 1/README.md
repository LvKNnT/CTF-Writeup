# Hamiltonicity 1 Writeup

## Summary

Hamiltonicity 1 uses a Fiat-Shamir version of Blum's Hamiltonian-cycle proof. The graph has no Hamiltonian cycle, but the prover controls the commitment and can grind until the hash challenge matches the type of opening it can answer.

Flag:

```text
crypto{not_hashing_entire_statement_is_bad}
```

## Triage

Each round has two possible openings:

```text
bit 0: open the full permuted committed graph
bit 1: open only the committed Hamiltonian cycle edges
```

The solver uses a disconnected graph and cannot answer both challenge types for the same commitment.

## Solve Path

Because the challenge bit is Fiat-Shamir-derived from the commitment, the solver can generate a type-0 or type-1 commitment, hash it locally, and keep only a commitment whose hash bit matches the answer it can provide.

For bit 0, it commits honestly to a permutation of the target graph. For bit 1, it commits to a graph containing only a cycle. It repeats this grinding for 128 rounds.

## Exploit

Run:
z
```bash
sage solve.sage
```

The script targets `archive.cryptohack.org:14635` by default and imports the provided `hamiltonicity_*.py` helper to match the server hash exactly.

## Verification

Verified live against `archive.cryptohack.org:14635` from WSL using the `sage` conda environment:

```text
you've convinced me it has a hamiltonian path! Cool!
b'crypto{not_hashing_entire_statement_is_bad}'
```

## Flag

```text
crypto{not_hashing_entire_statement_is_bad}
```

## Lessons Learned

- Fiat-Shamir can be grindable when the prover controls all hash inputs and the challenge is tiny.
- A prover that can answer one branch can keep sampling commitments until the branch is selected.
- Matching helper code exactly avoids serialization mismatches in hash-derived challenges.
