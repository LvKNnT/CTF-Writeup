# CryptoHack - Road to SIDH - Breaking SIDH
#
# Castryck-Decru polynomial-time key recovery on SIDH, adapted from the
# reference implementation:
#     https://github.com/GiacomoPope/Castryck-Decru-SageMath
#
# The generic machinery (Richelot / (2,2)-isogeny chains, the u,v table,
# the glue-and-split test) lives in the helper files copied next to this
# script and is prime-independent:
#     richelot_aux.py, uvtable.py, helpers.py,
#     castryck_decru_shortcut.sage, speedup.sage
#
# Only the *driver* below is specific to this challenge.  Two differences
# from the SIKE reference:
#
#   1. Starting curve.  Here E0 : y^2 = x^3 + x  (j = 1728), not SIKE's
#      Montgomery curve y^2 = x^3 + 6x^2 + x.  E0 has CM by Z[i]: the map
#          iota : (x, y) |-> (-x, i*y)
#      is a degree-1 automorphism with iota^2 = [-1].  The endomorphism the
#      attack needs is "2i", of degree 4 with (2i)^2 = [-4], which we build
#      directly as  two_i = [2] . iota.  This plays the exact role of the
#      distortion map produced by generate_distortion_map() in the reference,
#      and matches the norm relation encoded by the u,v table:
#          deg(u + v*two_i) = u^2 + 4*v^2 = 2^a_i - 3^b_i.
#
#   2. Cofactor.  p = 45 * 2^117 * 3^73 - 1, so p + 1 = 5 * 2^117 * 3^75.
#      The extra 5*3^2 is harmless: every place the attack isolates the
#      3^b torsion it multiplies by (p+1)/3^b, which divides the cofactor
#      away and still yields points of exact order 3^73.

import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

set_verbose(-1)
proof.all(False)

# ----------------------------------------------------------------------
# Load all public data (field, curves, torsion points, iv/ct) straight
# from the challenge source, so the big constants can't be mistyped.
# ----------------------------------------------------------------------
load('source_0e46e87ca6110ad062f6ce1819ded232.sage')

# SIDH / attack parameters
a, b = ea, eb                      # a = 117, b = 73
assert p == f * 2**a * 3**b - 1

E_start = E0
E_start.set_order((p + 1)**2)
EA.set_order((p + 1)**2)
EB.set_order((p + 1)**2)

# P2, Q2 (2^a-torsion basis on E_start) are already defined by the source.
# Their images under Bob's secret isogeny are his public torsion points:
PB, QB = phiB_P2, phiB_Q2          # = phi_B(P2), phi_B(Q2)

# Sanity: correct torsion orders
assert 2**a * P2 == E_start(0) and 2**(a - 1) * P2 != E_start(0)
assert 3**b * P3 == E_start(0) and 3**(b - 1) * P3 != E_start(0)
assert 2**a * PB == EB(0) and 2**(a - 1) * PB != EB(0)


# ----------------------------------------------------------------------
# The "2i" endomorphism of E0 : y^2 = x^3 + x.
#     iota  : (x, y) |-> (-x, i*y),   iota^2 = [-1]
#     two_i = [2] . iota,             two_i^2 = [-4],  deg = 4
# (If a full run finds no glue-and-split, the other sign of the distortion
#  map is obtained by flipping i -> -i below.)
# ----------------------------------------------------------------------
def two_i(P):
    if P.is_zero():
        return P
    x, y = P.xy()
    return 2 * P.curve()(-x, i * y)


# quick self-check that two_i really is a degree-4, trace-0 endomorphism
_T = 3**(b - 1) * P3
assert two_i(two_i(_T)) == -4 * _T, "two_i^2 must equal [-4]"

# ----------------------------------------------------------------------
# Run the attack (this is the slow part: a few thousand candidate first
# digits, each tested with a (2,2)-isogeny chain).  Use --parallel to fan
# out across cores.
# ----------------------------------------------------------------------
load('castryck_decru_shortcut.sage')


def RunAttack(num_cores):
    return CastryckDecruAttack(E_start, P2, Q2, EB, PB, QB, two_i, num_cores=num_cores)


if __name__ == '__main__' and '__file__' in globals():
    import os, sys
    if '--parallel' in sys.argv:
        num_cores = os.cpu_count()
        print(f"Performing the attack in parallel using {num_cores} cores")
    else:
        num_cores = 1

    t0 = time.time()
    skB = RunAttack(num_cores)
    print(f"Recovered Bob's secret scalar skB = {skB}")

    # ------------------------------------------------------------------
    # Reconstruct the shared secret from Bob's key + Alice's public data.
    # Bob's isogeny has kernel <P3 + skB*Q3>; pushed through Alice's
    # isogeny its kernel becomes <phiA_P3 + skB*phiA_Q3> on EA.
    # The shared secret is j(E_AB), which is symmetric in the two parties.
    # ------------------------------------------------------------------
    K_shared = phiA_P3 + skB * phiA_Q3
    assert 3**b * K_shared == EA(0)
    phi = EA.isogeny(K_shared, algorithm="factored")
    shared_secret = phi.codomain().j_invariant()
    print(f"shared_secret (j-invariant) = {shared_secret}")

    # ------------------------------------------------------------------
    # Decrypt the flag exactly as encrypt_flag() did in the source.
    # ------------------------------------------------------------------
    key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
    cipher = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))
    flag = unpad(cipher.decrypt(bytes.fromhex(ct)), 16)
    print(flag.decode())

    print(f"Total time: {time.time() - t0:.1f}s")
