from pwn import *
import json
from Crypto.Util.number import long_to_bytes
x = 1042949915673747639548394979539773519387432406920217853474982925582324441002369106807062644005773384014539089496972340217284225886262811961269251256830829063
y = 1042949915673747639548394979539773519387432406920217853474982925582324441002369106807076447498466965142113959008696894268189128104207757197289383619865780743

HOST = "socket.cryptohack.org"
PORT = 13392
r = remote( HOST, PORT )
r.recvline()
r.sendline( json.dumps( { "option" : "sign", "prime" : x } ).encode() )
sig =  json.loads( r.recvline().strip().decode() )["signature"]
r.sendline( json.dumps( { "option" : "check", "prime" : y , "signature" : sig, "a" : 71 } ).encode() )
print( r.recvline() )
