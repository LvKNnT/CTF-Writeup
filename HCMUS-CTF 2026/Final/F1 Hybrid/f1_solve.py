#!/usr/bin/env python3
"""
F1 Hybrid solver.

Idea:
 * Pick feedback_index so the LFSR order divides N=23738715  ->  round keys
   collapse to an alternating 2-key schedule (k0 even rounds, k1 odd rounds).
 * The no-swap last round makes  D == E with the two keys swapped, giving
   conjugacies   E = rho_k0 o D o rho_k0   and   D = rho_k1 o E o rho_k1.
   => column relation  E((L,0)).hi == D((0, L^K)).lo  with  K=f(0,k0).
   Find K as the mode of L^m over collisions E((L,0)).hi == D((0,m)).lo, then
   k0 = Sinv(ror11(K)). Symmetrically recover k1.
 * Rebuild the cipher, decrypt the option-3 challenge block, win.
"""
import sys, random
from collections import defaultdict, Counter

from f1cipher import (Ghost, period2, substitute_u32, SBOX, ISBOX,
                      rotl32, MASK32)
from period_check import is_period2

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

T_DATA = 1 << 19          # queries per column (mode count ~ T^2/2^32 = 64)
CHUNK  = 1 << 15          # blocks per network request

def ror11(x):  return rotl32(x, 21)

def k_from_K(K):
    # K = f(0,k) = rotl11(S(k))  =>  S(k)=ror11(K)  =>  k = Sinv(ror11(K))
    return substitute_u32(ror11(K), ISBOX)

def recover(P_col, Q_col, V):
    """A[L]=P_col((L,0)).hi ; B[m]=Q_col((0,m)).lo ; K=mode(L^m | A[L]==B[m])."""
    blocksA = [L.to_bytes(4, 'big') + b'\x00\x00\x00\x00' for L in V]
    blocksB = [b'\x00\x00\x00\x00' + m.to_bytes(4, 'big') for m in V]
    outA = P_col(blocksA)
    outB = Q_col(blocksB)
    A = {V[i]: int.from_bytes(outA[i][:4], 'big') for i in range(len(V))}
    val2m = defaultdict(list)
    for i, m in enumerate(V):
        val2m[int.from_bytes(outB[i][4:], 'big')].append(m)
    votes = Counter()
    for L in V:
        for m in val2m.get(A[L], ()):
            votes[L ^ m] += 1
    (K, cnt), = votes.most_common(1)
    return k_from_K(K), cnt

# ----------------------------------------------------------------------------
def test_local():
    print("[*] local self-test of recover()/decrypt path")
    k0 = random.getrandbits(32); k1 = random.getrandbits(32)
    g = period2(k0, k1)
    enc_col = lambda blocks: [g.encrypt_block(b) for b in blocks]
    dec_col = lambda blocks: [g.decrypt_block(b) for b in blocks]
    V = random.sample(range(1 << 32), T_DATA)
    rk0, c0 = recover(enc_col, dec_col, V)
    rk1, c1 = recover(dec_col, enc_col, V)
    print(f"    k0 {'OK' if rk0==k0 else 'BAD'} (votes {c0});  k1 {'OK' if rk1==k1 else 'BAD'} (votes {c1})")
    assert rk0 == k0 and rk1 == k1, "local recover failed"
    # decrypt-a-challenge path
    pt = random.getrandbits(64).to_bytes(8, 'big')
    ct = g.encrypt_block(pt)
    g2 = period2(rk0, rk1)
    assert g2.decrypt_block(ct) == pt
    print("    decrypt-challenge path OK")

# ----------------------------------------------------------------------------
def solve_network():
    from pwn import remote, context
    context.log_level = "info"

    def feedback_from_seed(seed, idx):
        value = 0
        for bit in range(47):
            sb = idx + bit
            value |= ((seed[len(seed) - 1 - (sb // 8)] >> (sb % 8)) & 1) << bit
        return (1 << 47) | value

    while True:
        io = remote(HOST, PORT)
        data = io.recvuntil(b">> ")
        import re
        m = re.search(rb"([0-9a-fA-F]{512})", data)
        seed = bytes.fromhex(m.group(1).decode())

        idx = next((i for i in range(0, 2048 - 47 + 1)
                    if is_period2(feedback_from_seed(seed, i))), None)
        if idx is None:
            io.info("no period-2 window this connection; reconnecting")
            io.close()
            continue
        io.info(f"period-2 feedback at index {idx}")
        io.sendline(str(idx).encode())

        def col(op, blocks):
            out = []
            for s in range(0, len(blocks), CHUNK):
                chunk = blocks[s:s + CHUNK]
                io.recvuntil(b">> "); io.sendline(op)
                io.recvuntil(b">> "); io.sendline(b''.join(chunk).hex().encode())
                res = bytes.fromhex(io.recvline().strip().decode())
                out += [res[i:i + 8] for i in range(0, len(res), 8)]
            return out
        enc_col = lambda blocks: col(b"1", blocks)
        dec_col = lambda blocks: col(b"2", blocks)

        V = random.sample(range(1 << 32), T_DATA)
        io.info("recovering k0 ...")
        k0, c0 = recover(enc_col, dec_col, V)
        io.info("recovering k1 ...")
        k1, c1 = recover(dec_col, enc_col, V)
        io.info(f"k0={k0:08x} (votes {c0})  k1={k1:08x} (votes {c1})")

        g = period2(k0, k1)
        # sanity: oracle-encrypt a random block and compare
        tb = random.getrandbits(64).to_bytes(8, 'big')
        if enc_col([tb])[0] != g.encrypt_block(tb):
            io.info("key check FAILED, reconnecting")
            io.close()
            continue
        io.success("key check passed")

        io.recvuntil(b">> "); io.sendline(b"3")
        ct = bytes.fromhex(io.recvline().strip().decode())
        pt = g.decrypt_block(ct)
        io.info(f"challenge ct={ct.hex()}  -> pt={pt.hex()}")
        io.recvuntil(b">> "); io.sendline(pt.hex().encode())
        print(io.recvall(timeout=3).decode(errors="replace"))
        io.close()
        return

if __name__ == "__main__":
    # test_local()
    if "--local" not in sys.argv:
        solve_network()
