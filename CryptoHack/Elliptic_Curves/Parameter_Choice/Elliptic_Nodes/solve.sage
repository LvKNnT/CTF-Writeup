from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
from sage.all import *

# Create a simple Point class to represent the affine points.
Point = namedtuple("Point", "x y")

# Define the curve
p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
gy = 225987949353410341392975247044711665782695329311463646299187580326445253608
G = Point(gx, gy)
Q = Point(2582928974243465355371953056699793745022552378548418288211138499777818633265, 
            2421683573446497972507172385881793260176370025964652384676141384239699096612)
O = 'Origin'

a = ((Q.y ^ 2 - G.y ^ 2) - (Q.x ^ 3 - G.x ^ 3)) * inverse(Q.x - G.x, p) % p
b = (G.y ^ 2 - G.x ^ 3 - a * G.x) % p
print(f"Curve parameters: a = {a}, b = {b}")

Gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
Gy = 225987949353410341392975247044711665782695329311463646299187580326445253608
Qx = 2582928974243465355371953056699793745022552378548418288211138499777818633265
Qy = 2421683573446497972507172385881793260176370025964652384676141384239699096612

x = GF(p)["x"].gen()
f = x^3 + a*x + b
roots = f.roots()

assert len(roots) == 2 # two roots, so one must be double
if roots[0][1] == 2:
    double_root = roots[0][0]
    single_root = roots[1][0]
else:
    double_root = roots[1][0]
    single_root = roots[0][0]

print("double root:", double_root)
print("single root:", single_root)

# map G and Q to the new "shifted" curve
Gx = (Gx - double_root)
Qx = (Qx - double_root)

# Transform G and Q into numbers g and q, such that q=g^n
t = double_root - single_root
t_sqrt = t.square_root()

def transform(x, y, t_sqrt):
    return (y + t_sqrt * x) / (y - t_sqrt * x)

g = transform(Gx, Gy, t_sqrt)
q = transform(Qx, Qy, t_sqrt)
print("g:", g)
print("q:", q)

# Find the private key n
print("Factors of p-1:", factor(p-1))
print("Calculating discrete log for g and q...")
found_key = discrete_log(q, g)
print("Found private key:", found_key)

from Crypto.Util.number import long_to_bytes
print("The secret is:", long_to_bytes(found_key).decode())
