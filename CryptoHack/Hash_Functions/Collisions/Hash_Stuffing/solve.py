from pwn import *
from json import *

HOST = 'socket.cryptohack.org'
# HOST = 'localhost'
PORT = 13405

io = remote(HOST, PORT)

i = io.recvuntil(b'JSON: ')
print(i)
io.send(dumps({'m1': "0101010101010101010101010101010101010101010101010101010101010101", 
               'm2': "01010101010101010101010101010101010101010101010101010101010101"}).encode())
i = io.recv()
print(i)