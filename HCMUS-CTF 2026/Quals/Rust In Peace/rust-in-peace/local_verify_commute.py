#!/usr/bin/env python3
"""
Offline sanity check for the G=F^12 commute attack used by solve.sage,
against an in-process fake cipher (no network). Confirms the algorithm
recovers the 4 secret 4-bit S-boxes exactly and matches on fresh random
blocks, before trusting it against the real remote oracle.
"""
import random

ROUNDS = 12
NIBBLES = 16

PERM = [
    5, 44, 34, 62, 13, 29, 9, 59, 47, 23, 43, 39, 18, 35, 51, 21,
    2, 48, 45, 7, 54, 46, 30, 10, 3, 12, 42, 1, 11, 37, 19, 0,
    55, 60, 32, 38, 27, 49, 20, 58, 15, 36, 53, 56, 31, 52, 6, 40,
    14, 28, 26, 24, 63, 61, 16, 33, 41, 4, 17, 25, 22, 8, 50, 57,
]


def permute_bits(x):
    out = 0
    for i, dst in enumerate(PERM):
        out |= ((x >> i) & 1) << dst
    return out


def inv_permute_bits(x):
    out = 0
    for i, dst in enumerate(PERM):
        out |= ((x >> dst) & 1) << i
    return out


def sbox_layer(x, sboxes4):
    out = 0
    for i in range(NIBBLES):
        nib = (x >> (4 * i)) & 0xF
        out |= sboxes4[i % 4][nib] << (4 * i)
    return out


def encrypt_local(x, sboxes4):
    state = x
    for _ in range(ROUNDS - 1):
        state = sbox_layer(state, sboxes4)
        state = permute_bits(state)
    return sbox_layer(state, sboxes4)


def type_state(tup):
    out = 0
    for i in range(NIBBLES):
        out |= tup[i % 4] << (4 * i)
    return out


def nibbles_of(x):
    return [(x >> (4 * i)) & 0xF for i in range(NIBBLES)]


def consistent(input_nibbles, output_nibbles):
    """Same input nibble (within an S-box type) -> same output; distinct -> distinct."""
    for t in range(4):
        seen = {}
        for i in range(t, NIBBLES, 4):
            iv, ov = input_nibbles[i], output_nibbles[i]
            if iv in seen:
                if seen[iv] != ov:
                    return False
            elif ov in seen.values():
                return False
            else:
                seen[iv] = ov
    return True


def recover_sboxes(G_batch, powers=8):
    """G_batch(list[int]) -> list[int] is the only oracle access needed."""
    all_tuples = [(a, b, c, d) for a in range(16) for b in range(16) for c in range(16) for d in range(16)]
    cand_cur = [permute_bits(type_state(t)) for t in all_tuples]

    xs = [type_state((a, a, a, a)) for a in range(16)]
    real_chain = [[x] for x in xs]

    survivors = [list(range(len(all_tuples))) for _ in range(16)]
    resolved = [None] * 16

    for k in range(1, powers + 1):
        cand_cur = G_batch(cand_cur)
        real_next = G_batch([chain[-1] for chain in real_chain])
        for a in range(16):
            real_chain[a].append(real_next[a])

        for a in range(16):
            if resolved[a] is not None:
                continue
            ck_nibbles = nibbles_of(real_chain[a][k])
            still = []
            for idx in survivors[a]:
                inv = inv_permute_bits(cand_cur[idx])
                if consistent(ck_nibbles, nibbles_of(inv)):
                    still.append(idx)
            survivors[a] = still
            if len(still) == 1:
                resolved[a] = all_tuples[still[0]]
            elif len(still) == 0:
                raise RuntimeError(f"a={a}: 0 surviving candidates at round {k}")

        print(f"round {k}: resolved so far = {sum(r is not None for r in resolved)}/16")
        if all(r is not None for r in resolved):
            break
    else:
        missing = [a for a in range(16) if resolved[a] is None]
        raise RuntimeError(f"unresolved a={missing} after {powers} rounds")

    sboxes4 = [[0] * 16 for _ in range(4)]
    for a in range(16):
        for t in range(4):
            sboxes4[t][a] = resolved[a][t]
    return sboxes4


if __name__ == "__main__":
    random.seed(99)
    true_sboxes = []
    for _ in range(4):
        p = list(range(16))
        random.shuffle(p)
        true_sboxes.append(p)

    queries = [0]

    def fake_G_batch(values):
        queries[0] += len(values)
        return [permute_bits(encrypt_local(v, true_sboxes)) for v in values]

    recovered = recover_sboxes(fake_G_batch, powers=8)
    print("recovered == true:", recovered == true_sboxes)
    print("total oracle queries used:", queries[0])

    random.seed(7)
    all_match = all(
        encrypt_local(x, true_sboxes) == encrypt_local(x, recovered)
        for x in (random.getrandbits(64) for _ in range(200))
    )
    print("fresh random blocks match:", all_match)
