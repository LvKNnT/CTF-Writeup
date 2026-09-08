# No Difference Writeup

## Summary

The custom hash has a linear permutation layer and a symmetric S-box structure that makes it possible to construct a short collision. The solve computes two 4-byte messages with the same digest and submits them to the live service.

Flag:

```text
crypto{n0_d1ff_n0_pr0bl3m}
```

## Triage

`13395_5ed60003866ba89ca3db17fbd446b841.py` defines the permutation, substitution, and hash. `solve.sage` contains the derivation, but Sage's preparser turns Python `^` into exponentiation in one expression, so verification used the same payload with a corrected XOR expression.

## Solve Path

The script starts from:

```python
msg1 = b"aaaa"
```

Then it chooses `msg2` so the internal state difference is canceled:

```python
target_xor = [177, 1, 145, 97]
state = [80, 96, 112, 128]
msg2 = bytes([target_xor[i] ^ state[i] for i in range(4)])
```

The resulting messages are:

```text
msg1 = 61616161
msg2 = e161e1e1
```

## Exploit

Submit:

```json
{"a": "61616161", "b": "e161e1e1"}
```

## Verification

```text
{"flag": "Well done, here is the flag: crypto{n0_d1ff_n0_pr0bl3m}"}
```

## Flag

```text
crypto{n0_d1ff_n0_pr0bl3m}
```

## Lessons Learned

- Linear diffusion layers make it easier to reason about and cancel differences.
- Be careful running Python-like Sage files when `^` is intended as XOR.
