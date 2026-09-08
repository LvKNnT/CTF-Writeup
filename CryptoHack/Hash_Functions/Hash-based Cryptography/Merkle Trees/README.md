# Merkle Trees Writeup

## Summary

The output file encodes each flag bit as a Merkle-tree consistency test. For each line, recomputing the root with `left = H(a || b)` identifies a `1` bit; otherwise the generator added random bias and the bit is `0`.

Flag:

```text
crypto{U_are_R3ady_For_S4plins_ch4lls}
```

## Triage

`generate_15fce6199904ba00202bb32d01a11551.py` shows how each challenge line is generated from one flag bit. `output.txt` contains the public tuples, and `solve.py` reconstructs the bitstring.

## Solve Path

For each tuple `(a, b, c, d, root)`, compute:

```python
left = sha256(a + b).digest()
right = sha256(c + d).digest()
candidate = sha256(left + right).digest()
```

If `candidate == root`, the bit was generated with `is_true = 1`; otherwise it was generated with a biased `b || random` branch and the bit is `0`.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
$ python solve.py
crypto{U_are_R3ady_For_S4plins_ch4lls}
```

## Flag

```text
crypto{U_are_R3ady_For_S4plins_ch4lls}
```

## Lessons Learned

- Merkle proofs must commit to exactly the same leaf/internal-node construction.
- A single biased branch can leak one bit per proof instance.
