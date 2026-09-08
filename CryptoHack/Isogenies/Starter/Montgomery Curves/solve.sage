from sage import *

E = EllipticCurve(GF(1912812599), [0, 0, 0, 312589632, 654443578])

print(E.montgomery_model())