# CryptoHack - Road to SIDH - Composite Isogenies
# Compute the 3^13-isogeny phi : E -> E' with kernel <K> by chaining
# 13 degree-3 isogenies, and print j(E').

p = 2^18 * 3^13 - 1
F = GF(p^2, names="i", modulus=[1, 0, 1])   # F_{p^2} = F_p(i), i^2 = -1
i = F.gen()

# E: y^2 = x^3 + x
E = EllipticCurve(F, [1, 0])

# K, a point of order 3^13
K = E(357834818388 * i + 53943911829, 46334220304 * i + 267017462655)
assert (3^13) * K == E(0)
assert (3^12) * K != E(0)

E_cur = E
K_cur = K
for step in range(13):
    order_left = 13 - step               # current order of K_cur is 3^order_left
    ker_pt = (3^(order_left - 1)) * K_cur  # scale down to a point of order 3
    phi = E_cur.isogeny(ker_pt)
    K_cur = phi(K_cur)                     # push kernel generator through
    E_cur = phi.codomain()

print("codomain:", E_cur)
print("j(E') =", E_cur.j_invariant())
