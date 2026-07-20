#!/bin/sh

# Listen on TCP port 1337 and execute the Rust binary for every incoming connection
socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/app/chall",stderr