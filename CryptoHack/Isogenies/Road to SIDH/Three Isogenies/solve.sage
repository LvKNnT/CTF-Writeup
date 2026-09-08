# CryptoHack - Road to SIDH - Three Isogenies
# Compute the 3-isogeny phi_3 : E -> E' with kernel <K> and print j(E').

p = 2^18 * 3^13 - 1
F = GF(p^2, names="i", modulus=[1, 0, 1])   # F_{p^2} = F_p(i), i^2 = -1
i = F.gen()

# E: y^2 = x^3 + x
E = EllipticCurve(F, [1, 0])

# K, a point of order 3
K = E(483728976, 174842350631)
assert 3 * K == E(0)
assert K != E(0) and 2 * K != E(0)

# Velu's formulas handle any kernel subgroup automatically once we pass
# a generator of the (order 3) kernel - Sage internally uses K and [2]K.
phi = E.isogeny(K)
E3 = phi.codomain()

print("codomain:", E3)
print("j(E') =", E3.j_invariant())
