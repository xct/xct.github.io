---
categories:
- Misc
image:
  path: token_privs_preview.png
layout: post
media_subpath: /assets/posts/2021-09-10-on-disabled-windows-privileges
tags:
- c++
- windows
title: On Disabled Windows Privileges
---

On a recent video someone asked a good question in the comments about why we can shutdown a box when our user has SeShutdownPrivilege listed as disabled:

```
whoami /all
...
Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

  
As with all of these Privileges, disabling them does not actually prevent the user from using them – it is just supposed to prevent accidental misuse. The idea is that you have to explicitly enable them again in code in order to use them.

Let’s confirm that for SeShutdownPrivilege using C++:

```cpp
#include <iostream>
#include <windows.h>

#pragma comment(lib, "user32.lib")

int main()
{
    bool result = ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
    if (!result) {
        std::cout << "Shutdown failed!" << std::endl;
    }
}
```

```
C:\Users\xct\source\repos\TokenPrivileges\x64\Release>TokenPrivileges.exe
Shutdown failed!
```

We can however enable that privilege using AdjustTokenPrivileges:

```cpp
#include <iostream>
#include <windows.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

int main()
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken); // get token for current process
    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid); // get LUID for shutdown priv
    tkp.PrivilegeCount = 1;  // change 1 priv
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // set it to enabled
    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0); // adjust privilege

    bool result = ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER);
    if (!result) {
        std::cout << "Shutdown failed!" << std::endl;
    }
}
```

Now the shutdown is possible. So to summarize, shutting down a box with SeShutdownPrivilege disabled is possible because "shutdown.exe" is using AdjustTokenPrivileges to enable the Privilege before calling the required Windows API function. As for other Privileges, you can follow the same methodology to enable & use them.