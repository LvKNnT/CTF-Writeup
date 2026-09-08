from sage import *

Px = 48622
Py = 27709
P = (Px, Py)

Qx = 9460
Qy = 13819
Q = (Qx, Qy)

p = 63079

# P + Q
lam = (Qy - Py) * inverse_mod(Qx - Px, p) % p

Rx = (lam^2 - Px - Qx) % p
Ry = (lam * (Px - Rx) - Py) % p

print("P + Q = ({}, {})".format(Rx, Ry))