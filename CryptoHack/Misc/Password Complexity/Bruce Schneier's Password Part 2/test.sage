import numpy as np
from Crypto.Util.number import *
import random
import string

def is_pass(password):
	array = np.array(list(map(ord, password)))
	s, p = array.sum(), array.prod()
	if isPrime(int(array.sum())) and array.sum() == array.prod():
		return True
	else:
		return False

def gen_pass():
	n = 69 # It's odd and can cause overflow. A smaller (but more boring) number would be 21.
	password = ''
	chars = string.ascii_lowercase+string.ascii_uppercase+string.digits
	odd_chars = []
	for i in chars:
		if (ord(i) % 2 == 1):
			odd_chars.append(i)
	while len(password) != n:
		password += random.choice(odd_chars)
	return password

while True:
    p = gen_pass()
    if (is_pass(p)):
        print(p) # Send that, receive 'crypto{https://www.schneierfacts.com/facts/1341}'

        from pwn import *
        io = remote("socket.cryptohack.org", 13401)
        io.recvline()
        io.send(f'{{"password": "{p}"}}'.encode())
        print(io.recvline().decode())
        exit()
