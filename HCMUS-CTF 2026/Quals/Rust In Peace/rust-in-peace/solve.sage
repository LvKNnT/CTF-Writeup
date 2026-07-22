#!/usr/bin/env sage
"""
Rust In Peace.

The cipher has no round keys: it repeats a public bit permutation P and a
4-nibble-type S-box layer S for ROUNDS=12 rounds. Writing F = P o S, one
full keyed round is F, and:

    E(x) = S(F^11(x))              <- what the 'E' oracle command returns
    G(x) = P(E(x)) = F^12(x)       <- computable from the oracle + local P

G is a power of F, so F and G commute: G(F(z)) = F(G(z)) for all z, and by
extension G(F^j(z)) = F^j(G(z)) for any j (every power of F commutes with
every other power of F).

For a chosen state x_a where every nibble equals the same value a, the
unknown y = F(x_a) has only 16^4 candidates: y = P(type_state(S0(a),
S1(a), S2(a), S3(a))), i.e. a 4-tuple of guesses (one per S-box, since
sboxes[i] only depends on i % 4).

For the TRUE y, G^k(y) = G^k(F(x_a)) = F(G^k(x_a)) for every k. G^k(x_a)
is measured exactly (a=x_a is known, so its images under repeated oracle
queries are exact - no guessing). So for each k we can locally check
whether a candidate's G^k(y) is *consistent* with being F(G^k(x_a)):
undo the public permutation P, and require that nibble positions of the
same S-box type that had equal inputs in G^k(x_a) produce equal outputs
(S is a function), and that positions with distinct inputs produce
distinct outputs (each S-box is a bijection). False candidates get
filtered out almost immediately.

Crucially the 16^4 candidate set (and its G^1..G^k images) do not depend
on which 'a' we're solving for, only on P and the oracle -- so the whole
candidate batch is built ONCE and reused across all 16 values of a. This
script does that incrementally (stop expanding a given a's candidate
list as soon as it is down to a single survivor) instead of blindly
grinding to G^8 for every a, which cuts the total oracle traffic
significantly versus the brute "compute G^8 for all 65536 candidates
unconditionally" approach, while remaining exactly the same technique.

Once all four S-boxes are fully recovered (16 entries each), local
encryption is checked against a couple of fresh oracle queries, the
interactive phase is closed (empty line), and the 100 challenge blocks
are answered locally with the recovered S-boxes.

Usage:
    sage solve.sage --host chall.blackpinker.com --port 20280 \
        --powers 8 --chunk-blocks 8192
"""

import argparse
import random
import re

from pwn import remote, context

ROUNDS = 12
NIBBLES = 16
BLOCK_BYTES = 8

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


class Oracle:
    """Pipelines many 'E<hex>' queries over one connection."""

    def __init__(self, io, chunk_blocks):
        self.io = io
        self.chunk_blocks = chunk_blocks
        self.queries = 0

    def batch_encrypt(self, values):
        out = [0] * len(values)
        for start in range(0, len(values), self.chunk_blocks):
            chunk = values[start:start + self.chunk_blocks]
            payload = b"".join(
                b"E" + v.to_bytes(BLOCK_BYTES, "little").hex().encode() + b"\n"
                for v in chunk
            )
            self.io.send(payload)
            for i in range(len(chunk)):
                self.io.recvuntil(b"> ")
                line = self.io.recvline().strip()
                out[start + i] = int.from_bytes(bytes.fromhex(line.decode()), "little")
            self.queries += len(chunk)
        return out

    def encrypt_one(self, v):
        return self.batch_encrypt([v])[0]


def recover_sboxes(G_batch, powers, log=print):
    """G_batch(list[int]) -> list[int] is the only oracle access needed."""
    all_tuples = [(a, b, c, d) for a in range(16) for b in range(16) for c in range(16) for d in range(16)]
    cand_cur = [permute_bits(type_state(t)) for t in all_tuples]

    xs = [type_state((a, a, a, a)) for a in range(16)]
    real_chain = [[x] for x in xs]

    survivors = [list(range(len(all_tuples))) for _ in range(16)]
    resolved = [None] * 16

    for k in range(1, powers + 1):
        log(f"[*] Round {k}/{powers}: querying oracle for {len(all_tuples)} candidates + 16 real chains...")
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
                log(f"    [+] a={a:2d} resolved after {k} rounds -> {resolved[a]}")
            elif len(still) == 0:
                raise RuntimeError(f"a={a}: no surviving candidates at round {k} (bad transcript, retry)")

        if all(r is not None for r in resolved):
            log("[+] All 16 type-values resolved.")
            break
    else:
        missing = [a for a in range(16) if resolved[a] is None]
        raise RuntimeError(f"failed to resolve a={missing} within {powers} rounds; rerun with a higher --powers")

    sboxes4 = [[0] * 16 for _ in range(4)]
    for a in range(16):
        for t in range(4):
            sboxes4[t][a] = resolved[a][t]
    return sboxes4


def solve(host, port, powers, chunk_blocks):
    io = remote(host, port)
    io.recvuntil(b"> ")
    oracle = Oracle(io, chunk_blocks)

    def G_batch(values):
        enc = oracle.batch_encrypt(values)
        return [permute_bits(v) for v in enc]

    sboxes4 = recover_sboxes(G_batch, powers)

    print("[*] Recovered S-boxes:")
    for t in range(4):
        print(f"    S{t} = {sboxes4[t]}")
    print(f"[*] Total oracle queries used: {oracle.queries}")

    print("[*] Sanity-checking against fresh oracle queries...")
    for _ in range(4):
        x = random.getrandbits(64)
        real = oracle.encrypt_one(x)
        local = encrypt_local(x, sboxes4)
        if real != local:
            raise RuntimeError("recovered S-boxes do not match a fresh oracle check!")
    print("[+] Local encryption matches the oracle.")

    print("[*] Ending oracle phase, entering the 100-challenge phase...")
    io.sendline(b"")

    for i in range(100):
        line = io.recvline().decode()
        m = re.search(r"Challenge: ([0-9a-f]+)", line)
        if not m:
            print(line, end="")
            break
        chall = bytes.fromhex(m.group(1))
        block = int.from_bytes(chall, "little")
        resp = encrypt_local(block, sboxes4).to_bytes(BLOCK_BYTES, "little").hex()
        io.recvuntil(b"Response: ")
        io.sendline(resp.encode())

    print(io.recvall(timeout=5).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="chall.blackpinker.com")
    parser.add_argument("--port", type=int, default=20280)
    parser.add_argument("--powers", type=int, default=8)
    parser.add_argument("--chunk-blocks", type=int, default=8192)
    args = parser.parse_args()
    solve(args.host, args.port, args.powers, args.chunk_blocks)
