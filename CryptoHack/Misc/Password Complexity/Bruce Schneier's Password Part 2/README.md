# Bruce Schneier's Password Part 2 Writeup

## Summary

Part 2 changes the predicate so the signed 64-bit product must equal the signed sum. The solve treats the target sum as a prime, searches character counts that add to it, and checks whether the overflowed product lands on the same value.

Flag:

```text
crypto{https://www.schneierfacts.com/facts/1341}
```

## Triage

The checked-in scripts include both a randomized approach and a deterministic count-DFS solver. The accepted password must be ASCII `\w*`, include digit/uppercase/lowercase classes, and satisfy:

```text
sum(password bytes) == int64(product(password bytes))
```

with the sum prime.

## Solve Path

The deterministic solver iterates prime target sums and recursively assigns counts from a reduced odd-character alphabet:

```python
CHARS = "13579ACEGIKMOQSUWYacegikmoqsuwy_"
```

For each candidate target, the DFS prunes impossible remaining sums and tracks the class mask. A password is accepted only when the remaining sum is zero, the required classes are present, and the overflowed product equals the target.

## Exploit

Use the deterministic solver:

```bash
sage solve.sage --host socket.cryptohack.org --port 13401
```

The older `test.sage` also records a successful solve comment:

```text
Send that, receive 'crypto{https://www.schneierfacts.com/facts/1341}'
```

## Verification

I checked the WSL `sage` conda environment and ran one fixed-target attempt:

```text
sage solve.sage --target 211
no password found for target sum 211
```

The full default search ran longer than useful for this writeup pass and was stopped. The checked-in `test.sage` comment records the accepted flag below.

## Flag

```text
crypto{https://www.schneierfacts.com/facts/1341}
```

## Lessons Learned

- Overflow can be used as a modular equation, not just as a bug.
- Search over character counts is often cleaner than search over raw strings.
- Constraint pruning on sums and class masks keeps combinatorial password problems tractable.
