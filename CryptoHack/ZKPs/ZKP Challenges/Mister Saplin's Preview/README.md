# Mister Saplin's Preview Writeup

## Summary

Mister Saplin's Preview is a Merkle-tree preview service with a race-style validation bug. A large node request keeps the checker busy while Python slicing still returns the existing leaves, letting the solver reconstruct the root and prove knowledge of the full tree.

Flag:

```text
crypto{M3rkle_tree_AND_race_condition_AND_replay_attack___that's_too_much}
```

## Triage

The service has `get_nodes` and `do_proof` options. The returned node list is encoded as Python `str(list)`, so the solver parses it with `ast.literal_eval`.

## Solve Path

The bug is a time-of-check/time-of-use issue. The solver requests far more nodes than exist:

```python
send_json(io, {"option": "get_nodes", "nodes": "0,10000000"})
```

The balance checker runs separately and does not block the slice result. Meanwhile, `self.nodes[0][:count]` gives the 8 real leaves. With those leaf hashes, the solver rebuilds the Merkle root:

```python
layer = [merge_nodes(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
```

It then sends that root to `do_proof`.

## Exploit

Run:

```bash
sage solve.sage
```

The script targets `socket.cryptohack.org:13414`.

## Verification

Verified live against `socket.cryptohack.org:13414` from WSL using the `sage` conda environment:

```text
crypto{M3rkle_tree_AND_race_condition_AND_replay_attack___that's_too_much}
```

## Flag

```text
crypto{M3rkle_tree_AND_race_condition_AND_replay_attack___that's_too_much}
```

## Lessons Learned

- Asynchronous validation can introduce TOCTOU bugs.
- A Merkle root is only secret if leaf access controls actually hold.
- Python slicing may quietly return fewer elements than requested, which can be exploitable when validation is separate.
