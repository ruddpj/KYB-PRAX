#!/bin/python

from pwn import *
from Crypto.PublicKey import RSA

p = process("/challenge/run")

p.recvuntil(b"(public)  n = 0x")
n = int(p.recvline().strip().decode(), 16)

p.recvuntil(b"(private) d = 0x")
d = int(p.recvline().strip().decode(), 16)

p.recvuntil(b"Flag Ciphertext (hex): ")
flag = int(p.recvline().strip().decode(), 16)

pt = pow(flag, d, n).to_bytes(256, "little")
print(pt)
