---
categories:
- Misc
image:
  path: st1.png
layout: post
media_subpath: /assets/posts/2022-01-08-kerberos-silver-tickets
tags:
- active directory
- silver ticket
title: About Kerberos Silver Tickets
---

I always had difficulties understanding what Silver Tickets are and how they are used. Maybe this comes from the fact that they are rarely seen in labs. They can be really powerful though, so I’ll be trying my best to describe my understanding of them in this post.

In the graphic you can see the basic workings of kerberos service tickets. A client (which can be a user or machine) requests a TGT from the DC. On the DC we have the Key Distribution Center which consists of an Authentication Server & Ticket Granting Server.

![](st1.png)

When the Authentication Server receives the request, it verifies the credentials & sends back an encrypted TGT & session key. The client now sends this TGT back to the DC, specifically to the Ticket Granting Server (TGS), and includes the SPN of the target service it wants to access.

If the client is authorized, the TGS sends back a Service Ticket (ST) which is encrypted with the service master key. Note that the client can not decrypt this ST as it does not know this service master key. Instead the client just forwards this ST to the service.

![](st2.png)

The target service can now check if the ST is valid by decrypting it. If it decrypts successfully it assumes the DC did create it & checks the User Principle Name & Service Principle Name. It then uses the session key to communicate with the client.

![](st3.png)

There is a flaw here. If someone would be able to get access to the service master key, he would be able to craft a ticket with any content because the target service will trust the contents if it can decrypt it successfully. This is possible because the service never checks back with the DC if the ticket is actually coming from the DC.

And this is basically what silver tickets are. If you can get access to the password / ntlm hash of the account a service runs under, you can spoof a ticket & become any user in context of the application.

So how can we practically use them? There are 2 common scenarios.

**Web Application**

Assume you target a web application that has multiple user roles & uses kerberos authentication. If you can craft a Silver Ticket, you will be able to impersonate any user on the application & might be able to access privileged areas.

**Database**

Assume you target a MSSQL database. If you can craft a Silver Ticket, you will be able to impersonate the SA user & use it to enable & execute xp\_cmdshell.

To create a silver ticket, you can either use impacket-ticketer.py or mimikatz. In both cases you will need the password / ntlm hash of the account the application/database is running under. This can be the machine account if virtual accounts are used, or a service account. In case it’s a service account you might be able to kerberoast & crack the password.

**Impacket-Ticketer.py**

```
impacket-ticketer -nthash <ntlm hash> -domain-sid <sid> -domain <domain> -spn <spn> -user-id <id> <username>
```

You can then export the resulting ticket:

```
export KRB5CCNAME=user.ccache
```

Now you can for example start firefox from that shell & access a target website. When using firefox you need to specifiy this setting in "about:config":

```
network.negotiate-auth.trusted-uris
```

**Mimikatz**

```
.\mimikatz.exe "kerberos::purge" "kerberos::golden /sid:<sid> /domain:domain.com /id:<id> /target:<domain> /service:<spn> /rc4:<ntlm hash> /ptt /user:<username>" "exit"
```

After generating the ticket, PowerShell can be used to make a request using Kerberos Authentication:

```
iwr http://target -UseBasicParsing -UseDefaultCredentials
```

There are some common pitfalls here: If you want to impersonate a specific user, it is not enough to only give the correct username, instead you also have to provide the correct user id (e.g. 500 for an Administrator). You also have to pay attention on the context you are running in – this will likely fail from WinRM session 0 & requires a proper domain context (any domain user or SYSTEM on a domain-joined machine).

**Lab**

Patreon subscribers can practice exploiting Silver Tickets & other techniques in a private lab environment and get access to a detailed walkthrough.