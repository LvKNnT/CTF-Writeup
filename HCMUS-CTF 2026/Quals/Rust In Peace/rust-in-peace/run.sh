#!/bin/sh
set -eu
exec socat TCP-LISTEN:1337,fork,reuseaddr EXEC:/app/chall,stderr
