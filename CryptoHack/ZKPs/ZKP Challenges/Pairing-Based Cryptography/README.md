# Pairing-Based Cryptography Writeup

## Summary

Pairing-Based Cryptography gives many tuple-encoded pairing challenges whose truth values encode the flag bits. The solver checks each pairing equation over BN128, turns true/false into `1/0`, and decodes the bitstring as ASCII.

Flag:

```text
crypto{Pa1rings_R_Str0ng}
```

## Triage

The generator emits one challenge per flag bit. Each line contains `(xG, yG, zG)`, and the bit is determined by whether:

```text
pairing(yG, xG) == zG
```

in the target group.

## Solve Path

The solver converts serialized points into `py_ecc` field elements:

```python
def to_g1(point):
    return tuple(FQ(c) for c in point)

def to_g2(point):
    return tuple(FQ2(c) for c in point)
```

Then it checks every line:

```python
bits.append("1" if is_true_challenge(eval(line)) else "0")
```

The recovered bitstring is converted to an integer and decoded as bytes.

## Exploit

Run:

```bash
python solve.sage
```

Despite the filename, this script is plain Python and uses `py_ecc`.

## Verification

Verified in WSL using the `sage` conda environment:

```text
crypto{Pa1rings_R_Str0ng}
```

## Flag

```text
crypto{Pa1rings_R_Str0ng}
```

## Lessons Learned

- Pairing equations can encode a clean true/false oracle.
- Once the group operation is available locally, each challenge line becomes one bit.
- File extensions can be misleading; check the shebang/imports before choosing the runner.
