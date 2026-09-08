# CryptoHack - Road to CSIDH - Twisted CSIDH Isogenies
# E0 : y^2 = x^3 + x over F_419.  p + 1 = 2^2 * 3 * 5 * 7.
#
# The l-isogeny graph on these curves is directed and cyclic: from a
# curve E, the unique F_p-rational point of order l gives exactly one
# "forward" step. To take a "backwards" step in a single isogeny
# (instead of walking all the way around), twist first: E -> E^t, take
# the ordinary forward l-isogeny step on the twist, then twist the
# codomain back.

p = 419
F = GF(p)
E0 = EllipticCurve(F, [1, 0])
assert E0.order() == p + 1   # 420 = 2^2 * 3 * 5 * 7


def nonsquare(F):
    while True:
        d = F.random_element()
        if d != 0 and not d.is_square():
            return d


def twist(E):
    return E.quadratic_twist(nonsquare(E.base_ring()))


def order_ell_point(E, ell):
    m = E.order() // ell
    while True:
        P = m * E.random_point()
        if P != E(0):
            return P


def ell_isogeny_step(E, ell):
    """One "forward" step: ell-isogeny via the rational point of order ell."""
    P = order_ell_point(E, ell)
    assert P.order() == ell
    return E.isogeny(P).codomain()


def ell_isogeny_step_backwards(E, ell):
    """One "backwards" step: twist, forward-step on the twist, untwist."""
    return twist(ell_isogeny_step(twist(E), ell))


def montgomery_A(E):
    Emont = E.montgomery_model()
    _, A, _, _, _ = Emont.a_invariants()
    return A


# --- Explore: E0's quadratic twist ---
E0t = twist(E0)
print("E0 Montgomery A:", montgomery_A(E0))
print("E0^t Montgomery A:", montgomery_A(E0t))
print("j(E0) =", E0.j_invariant(), " j(E0^t) =", E0t.j_invariant())
print("E0 isomorphic to E0^t?", E0.is_isomorphic(E0t))
print("#E0(F_p) =", E0.order(), " #E0^t(F_p) =", E0t.order())
print()

# --- Sanity check (as suggested): (k - 1) forward 7-isogenies should
# match a single backward 7-isogeny, where k is the length of the
# 7-isogeny cycle from "Prime Power Isogenies" ---
E = E0
k = 0
while True:
    E = ell_isogeny_step(E, 7)
    k += 1
    if E.is_isomorphic(E0):
        break

E_forward = E0
for _ in range(k - 1):
    E_forward = ell_isogeny_step(E_forward, 7)

E_backward = ell_isogeny_step_backwards(E0, 7)

assert E_forward.is_isomorphic(E_backward)
print("Sanity check passed: (k-1) forward 7-isogenies == 1 backward 7-isogeny (k =", k, ")")
print()

# --- The flag: one backward step on the 3-isogeny graph from E0 ---
E_back3 = ell_isogeny_step_backwards(E0, 3)
print("codomain:", E_back3)
print("j-invariant:", E_back3.j_invariant())

A = montgomery_A(E_back3)
print("Montgomery A:", A)
print("flag: A =", A)
