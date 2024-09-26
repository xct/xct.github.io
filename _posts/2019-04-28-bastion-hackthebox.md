---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-28-bastion-hackthebox
tags:
- hackthebox
- mRemoteNG
- password cracking
- windows
title: Bastion @ HackTheBox
---

Bastion is an easy 20 points machine on hackthebox. It is about mounting a .vhd file over the network, retrieving password hashes from backups (via SAM) and a privilege escalation that involves stored credentials in mRemoteNG.

## User Flag

The initial scan shows the following open ports:

```
22/tcp  open  ssh
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

By checking port 445 with smbmap we notice that we have a readable and writable share called Backups:

```
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.134...
[+] IP: 10.10.10.134:445  Name: 10.10.10.134
  Disk                                                    Permissions
  ----                                                    -----------
  ADMIN$                                              NO ACCESS
  Backups                                             READ, WRITE
  C$                                                  NO ACCESS
  IPC$                                                READ ONLY
```

Since we learned from the helpline box that a windows vm is best for testing windows, we will be using a windows 10 vm from now on. We connect to the share via windows explorer and notice it has 2 .vhd backup files in it. Since it is very slow to download them we directly mount them over the smb share:

![](htb_bastion_mount.png)

This allows us to read the backup of the c drive from L4mpje. There aren’t any flags or otherwise too interesting files, but we can download the SAM and SYSTEM file from "C:\\windows\\system32\\config\\". We copy them to our Linux box and use pwdump to obtain the user hashes:

```
pwdump SYSTEM SAM
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
```

Using [hashkiller](https://hashkiller.co.uk/) we retrieve the password of L4mpje: "bureaulampje". We can now ssh into the box with the credentials and read the userflag.

## Root Flag

After enumerating the box a bit we notice that an application called mRemoteNG is installed, which manages connections (to ssh, rdp, ftp, etc.) and saves the connection details, including the used credentials. The file it saves these in is "C:\\users\\l4mpje\\AppData\\Roaming\\mRemoteNG\\confCons.xml", the credentials are however somewhat encrypted. There exist some ways to decrypt these but I did not bother with them, instead I loaded the file into a local mRemoteNG installation on my windows vm and was able to connect as administrator to the box (make sure you change the ip address & protocol accordingly).

This enabled us to read the root flag and finish the box.

Overall a nice box – what made it a bit frustrating is the very slow speed on release that resulted in several timeouts when dealing with SMB.