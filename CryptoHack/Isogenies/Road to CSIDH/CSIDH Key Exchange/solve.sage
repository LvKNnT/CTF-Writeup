# CryptoHack - Road to CSIDH - CSIDH Key Exchange
# Full CSIDH-512 key exchange: apply Alice's/Bob's private exponent
# vectors to E0 to get public curves, apply each private vector to the
# other party's public curve to get the shared secret (Montgomery A),
# then decrypt the flag with it.
#
# Reuses the building blocks from "Prime Power Isogenies" (forward
# l-isogeny step) and "Twisted CSIDH Isogenies" (twist-based backward
# step for negative exponents).

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

# CSIDH-512 prime
ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
        71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
        149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
        227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293,
        307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
N = p + 1   # order of every curve in this graph (supersingular, trace 0);
            # hardcoded so we never pay for a generic point-counting call

a_priv = [-1, -2, -3, -3, -2, -3, -3, 0, 2, -1, 2, -1, -2, -3, 1, 2, 1, 2, 0, 0, 1, -1, 0, 2, -1, 0, 0, 0, 1, -1, -3, 1, -1, -3, -3, 2, 2, 1, -1, -1, 1, 0, 1, 1, 1, -2, 2, 2, -2, -2, 0, 0, 2, 0, -1, -3, -2, -2, 0, -1, -3, -1, -2, -3, -2, 2, 1, 1, -2, 0, 1, -1, -3, 2]
b_priv = [-1, -1, 0, 1, 2, 0, 2, -1, -3, 1, 0, -2, -2, 2, -1, -2, -3, -3, -3, 2, 2, 2, -2, -1, 1, -2, 0, -3, -1, 1, -1, -1, -3, -1, -2, 1, -1, -2, -3, 1, 0, -1, 1, 2, 2, 0, 0, -1, -2, -2, 1, -1, 1, 1, 1, 1, 0, 0, 0, -3, -2, -1, 2, 0, -3, -2, 1, 1, -2, -1, -1, 2, 0, 1]


def nonsquare(F):
    while True:
        d = F.random_element()
        if d != 0 and not d.is_square():
            return d


def twist(E):
    return E.quadratic_twist(nonsquare(E.base_ring()))


def order_ell_point(E, ell):
    m = N // ell
    while True:
        P = m * E.random_point()
        if P != E(0):
            return P


def ell_isogeny_step(E, ell):
    """Forward step: ell-isogeny via the rational point of order ell."""
    P = order_ell_point(E, ell)
    return E.isogeny(P).codomain()


def ell_isogeny_step_backwards(E, ell):
    """Backward step: twist, forward-step on the twist, untwist."""
    return twist(ell_isogeny_step(twist(E), ell))


def csidh_action(E, ells, exponents):
    for ell, e in zip(ells, exponents):
        if e > 0:
            for _ in range(e):
                E = ell_isogeny_step(E, ell)
        elif e < 0:
            for _ in range(-e):
                E = ell_isogeny_step_backwards(E, ell)
    return E


def montgomery_A(E):
    Emont = E.montgomery_model()
    _, A, _, _, _ = Emont.a_invariants()
    return A


# Public keys
E_A = csidh_action(E0, ells, a_priv)
E_B = csidh_action(E0, ells, b_priv)

# Shared secrets (both should land on isomorphic curves)
E_shared_A = csidh_action(E_B, ells, a_priv)
E_shared_B = csidh_action(E_A, ells, b_priv)

assert E_shared_A.is_isomorphic(E_shared_B)
shared_secret = montgomery_A(E_shared_A)
print("shared_secret =", shared_secret)

iv_hex = "daf6cd181775664b099609789fb564c9"
ct_hex = "3dd92e255c8e677f4a92226d09f56e2b2f567052ffd4f6f60200018454a83affc2e694c2bf2ad27da38f7f49b6e89928"

key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
iv = bytes.fromhex(iv_hex)
ct = bytes.fromhex(ct_hex)

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16)
print(flag)
