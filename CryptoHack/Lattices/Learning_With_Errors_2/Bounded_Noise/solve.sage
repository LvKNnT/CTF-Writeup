from sage.all import *
import json
from Crypto.Util.number import long_to_bytes

def solve():
    print("Loading data...")
    with open("output.txt", "r") as f:
        data = json.load(f)
        # Load A and b. 
        # CAUTION: In real usage, avoid eval(). Here we trust the local challenge file.
        A_full = Matrix(ZZ, eval(data["A"]))
        b_full = vector(ZZ, eval(data["b"]))

    q = 0x10001
    n = A_full.ncols()
    
    # OPTIMIZATION: We don't need all 4000+ samples. 
    # m = 2*n is usually enough for such small noise.
    m_eff = 2 * n 
    print(f"Using {m_eff} samples for lattice reduction...")

    A = A_full[:m_eff]
    b = b_full[:m_eff]

    # --- Step 1: Construct the Lattice ---
    # We want to find vector v = (e, 1) or (-e, -1) which is very short.
    # Block Matrix Structure:
    # | q*I_m   0 |
    # | A^T     0 |
    # | b       1 |
    
    # Create the matrix components
    Identity_q = q * identity_matrix(m_eff)
    A_transpose = A.transpose()
    
    # Construct the lattice basis matrix
    # Dimensions: (m_eff + n + 1) rows, (m_eff + 1) cols
    Lattice = Matrix(ZZ, m_eff + n + 1, m_eff + 1)
    
    # Fill in the blocks
    Lattice.set_block(0, 0, Identity_q)           # Top-left: q*I
    Lattice.set_block(m_eff, 0, A_transpose)      # Middle-left: A^T
    
    # Bottom row: [b_0, b_1, ..., b_m, 1]
    for i in range(m_eff):
        Lattice[m_eff + n, i] = b[i]
    Lattice[m_eff + n, m_eff] = 1

    # --- Step 2: Lattice Reduction (LLL) ---
    print("Running LLL...")
    L_reduced = Lattice.LLL()

    # --- Step 3: Extract the Error ---
    e_vector = None
    
    # Look for the row ending in 1 or -1
    for row in L_reduced:
        if row[m_eff] == 1:
            # We found (e, 1) or something close. 
            # In our embedding: row = A^T*s + q*k + b*1 = e (mod q) roughly.
            # Actually, standard embedding usually results in vector (e, 1) or (-e, 1).
            # Let's check if the vector is small (0s and 1s).
            potential_e = row[:m_eff]
            # Verify it looks like noise (composed of 0s and 1s)
            if all(x in [0, 1] for x in potential_e):
                e_vector = potential_e
                break
        elif row[m_eff] == -1:
            # We found (-e, -1)
            potential_e = -row[:m_eff]
            if all(x in [0, 1] for x in potential_e):
                e_vector = potential_e
                break

    if e_vector is None:
        print("Failed to recover error vector via LLL.")
        return

    print("Error vector recovered!")

    # --- Step 4: Recover the Secret ---
    # Equation: A * s + e = b (mod q)
    # Rewrite:  A * s = b - e (mod q)
    
    # Clean b
    b_clean = vector(GF(q), [b[i] - e_vector[i] for i in range(m_eff)])
    A_gf = Matrix(GF(q), A)
    
    # Solve linear system
    try:
        s = A_gf.solve_right(b_clean)
        print("Secret recovered.")
    except ValueError:
        print("Could not solve linear system.")
        return

    # --- Step 5: Decode the Flag ---
    # The flag was encoded base-q chunks, starting with the least significant.
    # secret_key.append(flag_int % q) -> s[0] is LSB
    
    flag_int = 0
    for i, val in enumerate(s):
        flag_int += int(val) * (q**i)
        
    flag = long_to_bytes(flag_int)
    print(f"Flag: {flag.decode()}")

if __name__ == "__main__":
    solve()