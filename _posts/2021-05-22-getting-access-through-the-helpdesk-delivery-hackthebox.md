---
categories:
- CTF
image:
  path: https://img.youtube.com/vi/3pJ1OL23ty4/0.jpg
layout: post
media_subpath: /assets/posts/2021-05-22-getting-access-through-the-helpdesk-delivery-hackthebox
tags:
- hackthebox
- linux
- mattermost
title: Getting Access through the Helpdesk - Delivery @ HackTheBox
---

We are going to solve Delivery, a 20-point machine on HackTheBox. For user, we will bypass email verification on a local Mattermost instance by opening a helpdesk ticket and using its temporary email address to register. For root we will use su-crack to bruteforce the root password based on a hint.

{% youtube 3pJ1OL23ty4 %}