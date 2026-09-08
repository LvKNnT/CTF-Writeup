def gram_schmidt_process(vectors):
    # Initialize list for orthogonal vectors u
    u_list = []

    for v in vectors:
        # Start ui as vi
        ui = v
        
        # Subtract projections of v onto all previous uj
        for uj in u_list:
            # Calculate coefficient μ = (v . uj) / ||uj||^2
            # Note: dot_product returns a scalar
            mu = v.dot_product(uj) / uj.dot_product(uj)
            
            # ui = ui - μ * uj
            ui = ui - mu * uj
            
        # Append the new orthogonal vector ui to the list
        # (Optional: Check if ui is zero to handle linearly dependent inputs)
        if not ui.is_zero():
            u_list.append(ui)
            
    return u_list

# --- Example Usage ---

# Define the Vector Space over Rational Field (QQ) for exact fractions
V = VectorSpace(QQ, 4)

# Define input vectors v1, v2, v3
v1 = V([4, 1, 3, -1])
v2 = V([2, 1, -3, 4])
v3 = V([1, 0, -2, 7])
v4 = V([6, 2, 9, -5])

input_vectors = [v1, v2, v3, v4]

# Run the algorithm
orthogonal_basis = gram_schmidt_process(input_vectors)

# Display results
print("Original Vectors:")
for i, v in enumerate(input_vectors):
    print(f"v{i+1} = {v}")

print("\nOrthogonal Vectors (u):")
for i, u in enumerate(orthogonal_basis):
    print(f"u{i+1} = {u}")