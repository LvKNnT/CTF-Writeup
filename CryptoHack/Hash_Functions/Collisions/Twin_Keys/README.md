# Twin Keys Writeup

## Summary

The safe accepts two distinct keys but tracks them by MD5 digest. Supplying a pair of precomputed MD5-colliding key files inserts two different keys with the same digest and unlocks the safe.

Flag:

```text
crypto{MD5_15_0n_4_c0ll151On_c0uRz3}
```

## Triage

The folder includes `collision1.bin` and `collision2.bin`. Both files hash to `ce1badb2d420cda5aba530a7b5a5a2ca`.

## Solve Path

The solve reads both binary keys and submits them:

```python
key1 = open("collision1.bin", "rb").read()
key2 = open("collision2.bin", "rb").read()
```

After both keys are inserted, the `unlock` option reveals the flag.

## Exploit

Run the checked-in script, or submit the keys manually:

```bash
python solve.py
```

## Verification

```text
md5-1 ce1badb2d420cda5aba530a7b5a5a2ca
md5-2 ce1badb2d420cda5aba530a7b5a5a2ca
{"msg": "The safe clicks and the door opens. Amongst its secrets you find a flag: b'crypto{MD5_15_0n_4_c0ll151On_c0uRz3}'"}
```

## Flag

```text
crypto{MD5_15_0n_4_c0ll151On_c0uRz3}
```

## Lessons Learned

- MD5 collisions remain dangerous when digests are used as object identities.
- Distinct binary objects can be crafted to share an MD5 while preserving chosen prefixes.
