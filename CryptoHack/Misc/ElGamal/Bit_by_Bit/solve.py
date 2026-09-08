from Crypto.Util.number import long_to_bytes

def legendre(a, p):
    # Euler's criterion: a^((p-1)/2) mod p
    # Returns 1 if QR, -1 if QNR, 0 if a is a multiple of p
    res = pow(a, (p - 1) // 2, p)
    if res == p - 1:
        return -1
    return res

# Parameters from source
q = 117477667918738952579183719876352811442282667176975299658506388983916794266542270944999203435163206062215810775822922421123910464455461286519153688505926472313006014806485076205663018026742480181999336912300022514436004673587192018846621666145334296696433207116469994110066128730623149834083870252895489152123
g = 104831378861792918406603185872102963672377675787070244288476520132867186367073243128721932355048896327567834691503031058630891431160772435946803430038048387919820523845278192892527138537973452950296897433212693740878617106403233353998322359462259883977147097970627584785653515124418036488904398507208057206926

# Captured output from the challenge (You must parse the output file into this list)
# Format: List of tuples (h, c1, c2)
captured_data = []
with open('output.txt') as f:
    for line in f:
        line = line.strip()
        if line.startswith('(public_key='):
            # Parse h
            h_str = line.split('=')[1].strip(' )')
            h = int(h_str, 16)
            
            # Read the next line which contains BOTH c1 and c2
            c_line = next(f).strip()
            
            # Split by comma to separate c1 and c2
            parts = c_line.split(',')
            
            # Parse c1 (remove 'c1=' and parentheses/spaces)
            c1_str = parts[0].split('=')[1].strip()
            c1 = int(c1_str, 16)
            
            # Parse c2 (remove 'c2=' and parentheses/spaces)
            c2_str = parts[1].split('=')[1].strip(' )')
            c2 = int(c2_str, 16)
            
            captured_data.append((h, c1, c2))

# 1. Determine base properties
leg_g = legendre(g, q)
leg_2 = legendre(2, q)

recovered_bits = []

for h, c1, c2 in captured_data:
    # 2. Determine Legendre symbol of the shared secret s
    # s = g^(xy)
    # If g is QR, s is QR.
    # If g is QNR, s is QNR iff x and y are both odd.
    
    if leg_g == 1:
        leg_s = 1
    else:
        # If g is QNR:
        # L(h) = L(g^x) = (-1)^x. If L(h)==-1, x is odd.
        # L(c1) = L(g^y) = (-1)^y. If L(c1)==-1, y is odd.
        x_odd = legendre(h, q) == -1
        y_odd = legendre(c1, q) == -1
        
        if x_odd and y_odd:
            leg_s = -1
        else:
            leg_s = 1

    # 3. Determine Legendre symbol of the message me
    # L(c2) = L(s) * L(me)  =>  L(me) = L(c2) * L(s)  (since L(s) is +/-1, inverse is itself)
    leg_c2 = legendre(c2, q)
    leg_me = leg_c2 * leg_s

    # 4. Guess the bit
    if leg_me != leg_2:
        # If L(me) differs from L(2), bit MUST be 1
        recovered_bits.append(1)
    else:
        # If L(me) equals L(2), bit is LIKELY 0 (ambiguous case)
        recovered_bits.append(0) 

# Reconstruct
# Note: The script processes bits LSB to MSB (m //= 2)
m = 0
for i, bit in enumerate(recovered_bits):
    m += bit * (2**i)

print(long_to_bytes(m))