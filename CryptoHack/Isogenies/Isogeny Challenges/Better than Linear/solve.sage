# CryptoHack - Isogeny Challenges - Better than Linear
# E/F_p^2 : y^2 = x^3 + x, compute the isogeny with kernel K using the
# sqrt-Velu ("velusqrt") algorithm (Bernstein-De Feo-Leroux-Smith),
# which computes large prime-degree isogenies in O(sqrt(l)) instead of
# Velu's O(l).

p = 92935740571
F = GF(p^2, name="i", modulus=[1, 0, 1])
i = F.gen()

E = EllipticCurve(F, [1, 0])
K = E(11428792286*i + 6312697112, 78608501229*i + 30552079595)

phi = E.isogeny(K, algorithm="velusqrt")
E2 = phi.codomain()

print("codomain:", E2)
print("j-invariant:", E2.j_invariant())
print("flag:", E2.j_invariant())
