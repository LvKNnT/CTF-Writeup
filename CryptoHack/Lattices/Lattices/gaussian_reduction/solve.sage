from sage.all import *

v = vector((846835985, 9834798552))
u = vector((87502093, 123094980))

# 1. Create a matrix with u and v as rows
M = Matrix([u, v])

# 2. Call LLL reduction
reduced_M = M.LLL()

# 3. Extract the reduced vectors
a_sage, b_sage = reduced_M.rows()

print("Reduced Vector a:", a_sage)
print("Reduced Vector b:", b_sage)
print("Dot Product:", a_sage * b_sage)