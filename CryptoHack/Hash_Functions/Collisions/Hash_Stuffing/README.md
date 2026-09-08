# Hash Stuffing Writeup

## Summary

The custom hash pads messages with a zero-length padding block only when the length is not already a multiple of the block size. Sending two messages that differ by one full block exploits the missing full-block padding and creates a collision.

Flag:

```text
crypto{Always_add_padding_even_if_its_a_whole_block!!!}
```

## Triage

`source_8435bf432bcd68b3bf16736a8a47a003.py` defines `BLOCK_SIZE = 32` and a custom XOR/rotate hash. `solve.py` sends two nearly identical messages to `socket.cryptohack.org:13405`.

## Solve Path

The vulnerable padding function is:

```python
padding_len = (BLOCK_SIZE - len(data)) % BLOCK_SIZE
return data + bytes([padding_len] * padding_len)
```

For a full block, `padding_len` is zero, so no domain-separating padding is added. The solve submits a 32-byte message and a 31-byte message arranged to collide under the block processing.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
{"flag": "Oh no! Looks like we have some more work to do... As promised, here's your flag: crypto{Always_add_padding_even_if_its_a_whole_block!!!}"}
```

## Flag

```text
crypto{Always_add_padding_even_if_its_a_whole_block!!!}
```

## Lessons Learned

- Padding must be unambiguous even for already aligned messages.
- Custom hash constructions often fail at boundary cases around block length.
