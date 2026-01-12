#!/bin/python

from pwn import *

pr = process("/challenge/run")

pr.recvuntil(b'p = 0x')
p=int(pr.recvline().strip().decode(), 16)

g=2

pr.recvuntil(b'A = 0x')
A=int(pr.recvline().strip().decode(), 16)

b = int('7FFFFFFF', 16)
# Výpočet B

pr.sendlineafter(b"B? ", hex(B).encode())
# Výpočet s

pr.sendlineafter(b"s? ", s)

print(pr.readline().decode())
print(pr.readline().decode())
