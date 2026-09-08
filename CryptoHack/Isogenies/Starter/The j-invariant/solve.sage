from sage import * 

E = EllipticCurve(GF(163), [0, 0, 0, 145, 49])

print(E.j_invariant())