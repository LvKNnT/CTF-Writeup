#this challenge uses power analysis
#here is a nice blog
#https://circuitcellar.com/research-design-hub/design-solutions/power-analysis-of-ecc-hardware-implementations/

from Crypto.Util.number import long_to_bytes
import numpy as np

with open('collected_data.txt') as f:
        data = eval(f.read())

# combine the 50 lists into 1 list (the means)
means = np.array(data).mean(axis=0, dtype=int)
print(means)

# now find the mean of this list
middle = np.mean(means)
print(middle)

# now we can loop through the means and if it is greater 
# than the middle it's a 1 and if it's lower it's a 0
binary_string = ""
for i in means:
        if i > middle:
                binary_string += "1"
        else:
                binary_string += "0"
print(binary_string)

# now I tried reading this
flag = long_to_bytes(int(binary_string, 2))
print(flag)

# but I realised I had to reverse the string
binary_string = binary_string[::-1]
flag = long_to_bytes(int(binary_string, 2))
print(flag)
#crypto{Sid3_ch4nn3ls_c4n_br34k_s3cur3_curv3s}