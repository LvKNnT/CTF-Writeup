# CryptoHack - Road to SIDH - Two Isogenies
# Compute the 2-isogeny phi_2 : E -> E' with kernel <K> and print j(E').

p = 2^18 * 3^13 - 1
F = GF(p^2, names="i", modulus=[1, 0, 1])   # F_{p^2} = F_p(i), i^2 = -1
i = F.gen()

# E: y^2 = x^3 + x   (a-invariants [a1, a2, a3, a4, a6] = [0, 0, 0, 1, 0])
E = EllipticCurve(F, [1, 0])

# K = (i, 0), a point of order 2
K = E(i, 0)
assert 2 * K == E(0)

# Velu's formulas (Sutherland Thm 5.13 for degree 2)
phi = E.isogeny(K)
E2 = phi.codomain()

print("codomain:", E2)
print("j(E') =", E2.j_invariant())

# Sanity check by hand (Thm 5.13, kernel point (x0, 0) on y^2 = x^3 + a*x + b):
#   t = 3*x0^2 + a,  w = x0*t
#   E' : y^2 = x^3 + (a - 5t)*x + (b - 7w)
a, b, x0 = F(1), F(0), i
t = 3 * x0^2 + a
w = x0 * t
E2_manual = EllipticCurve(F, [a - 5*t, b - 7*w])
assert E2_manual.j_invariant() == E2.j_invariant()
