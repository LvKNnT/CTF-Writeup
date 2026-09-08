# Collider Writeup

## Summary

The service stores documents by MD5 digest and crashes if a different document reuses an existing digest. Submitting a known MD5 collision pair triggers the crash path and leaks the flag.

Flag:

```text
crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}
```

## Triage

`13389_1044beb3c8949c7ee5813a8b1871e388.py` computes `hashlib.md5(document).hexdigest()` and stores the first document under that digest. `solve.py` sends two different hex documents with the same MD5.

## Solve Path

The first document inserts successfully:

```python
send({"document": "<md5-collision-message-1-hex>"})
```

The second document has the same MD5 but different bytes:

```python
send({"document": "<md5-collision-message-2-hex>"})
```

Because the digest already exists for different content, the server returns the crash message with the flag.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
{'success': 'Document 79054025255fb1a26e4bc422aef54eb4 added to system'}
{'error': 'Document system crash, leaking flag: crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}'}
```

## Flag

```text
crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}
```

## Lessons Learned

- MD5 collision resistance is broken in practice.
- Hash tables keyed only by weak digests can confuse distinct attacker-controlled inputs.
