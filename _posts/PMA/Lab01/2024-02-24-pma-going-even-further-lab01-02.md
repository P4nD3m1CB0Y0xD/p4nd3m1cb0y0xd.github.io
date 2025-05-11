---
title:  "PMA - Going even further: Lab01-02"
date:   2024-02-24 12:00:00 +0300
classes: wide
header:
  teaser: "/assets/images/PMA/lab01-02/8.png"
ribbon: red
categories: 
  - PMA
tags:
  - malware
  - reverse-engineering
toc: true
---

# Introduction

In this blog, we'll reverse-engineer the second lab from PMA. This lab presents some new challenges, such as unpacking a UPX program. This is the easiest packer out there. We also will learn how to create a Windows service for persistence and privilege escalation. So, let's dive in.

# Triage

The first tool I usually use for this first analysis stage is the DiE (Detect It Easy). This tool provides information related to the PE file, such as if it's packed, time-stamped, imported, exported (if it's a DLL file), and other related things like entropy.

![File packed with UPX version 3.04](/assets/images/PMA/lab01-02/1.png)
File packed with UPX version 3.04

As we can see, this file uses a packer to obfuscate and evade the system. We also see that this file was created a long time ago. This information can be manipulated for a Threat Actor, but sometimes it helps during an incident response.

![Entropy of the file](/assets/images/PMA/lab01-02/2.png)
Entropy of the file

DiE says that this file is not packed, but it's clear that this file is using UPX; one of its sections says that it is packed. This is because the entropy is measured between 0 to 8, our total was **5.25021**. But, the section that says it is packed has an entropy of **7.06812**.

As this is a simple packer, we can use two approaches to unpack this file. The first uses the same utility used to pack by passing the `-d` flag. The other is to use the *tail jump technique*. This technique involves finding a JMP instruction that will jump to the program's OEP (Original Entry Point). So, let's see how it works.

After opening the file with x32dbg (the 32-bit version of x64dbg) and pressing run once, we get into the Lab01-02.exe module.

![The entry point of the packed file](/assets/images/PMA/lab01-02/3.png)
The entry point of the packed file

The first instruction commonly used by UPX is `pushed`. This instruction will save the current value of all registries on the stack for later usage.

To find the tail jump, we just need to scroll down until we find something like the image below. 

![The jump tail](/assets/images/PMA/lab01-02/4.png)
The jump tail

After we scroll down, we see a JMP and a bunch of nonsense instructions without opcodes. This is our Tail Jump. So, hitting the `F2`, we set a break point at it and hit run. After pressing `F8`, we are in the OEP of the unpacked program.

![Original Entry Point at 0x401190](/assets/images/PMA/lab01-02/5.png)
Original Entry Point at 0x401190

Now, we just need to dump this file. For this, we'll use the Scylla plugin. Just click in `IAT Autosearch → Get Imports → Dump → select dumped file → Fix Dump`.

![Dump and fix the unpacked file](/assets/images/PMA/lab01-02/6.png)
Dump and fix the unpacked file

![The entropy of the unpacked file](/assets/images/PMA/lab01-02/7.png)
The entropy of the unpacked file

Now, we can continue without analysis. Let's get back to DiE and see if we can create some hypotheses for this malware by looking at its imported functions.

The main relevant DLL and functions used by this malware are:

- advapi32.dll
    - CreateServiceA
    - StartServiceCtrlDispatcherA
    - OpenSCManagerA

This sequence of functions may give some indications that this malware tries to create a Windows service for persistence on the target host.

- kernel32.dll
    - OpenMutexA
    - CreateMutexA
    - CreateThread

The usage of mutex is very common by malicious software when they want just one instance of the program running on the system. 

- wininet.dll
    - InternetOpenA
    - InternetOpenUrlA

This give some insights that the malware will try to access the internet.

We can also try to find some interesting strings if they are not obfuscated. Let's see what we can find:

```
MalService
hxxp://www[.malwareanalysisbook.]com
Internet Explorer 8.0
```

We found a string that may be the name of the created service, a user-agent, and a URL that the malware will try to connect. Those are good indicators for performing a hunting.

# Looking at the inside

After finding the main function at `0x401000`, one of our hypotheses is correct: this malware uses service as its persistence.

![Main function](/assets/images/PMA/lab01-02/8.png)
Main function

After connecting to the SCM (Service Control Manager), the main actions start by checking if the process is already running on the system and looking for the mutex `HGL345`.

![ServiceMain](/assets/images/PMA/lab01-02/9.png)
ServiceMain

By looking at this code, we can presume that this malware will create a timer and wait until the year 2100. After that, this malware will create 20 threads and perform a request to the target website. We can conclude that the objective of this malware is to perform a DDoS on the target website.

![Requesting thread](/assets/images/PMA/lab01-02/10.png)
Requesting thread

Now that we know what this malware does, let's recreate this program in C. The full source code can be found on my [GitHub](https://github.com/P4nD3m1CB0Y0xD/PMA-Book-Code/blob/main/Lab01/Lab01-02/Lab01-02.c).

Obs: The majority of those exercises don't work on the recent Windows 10 versions; it is recommended to use at least Windows 7 for those exercises (if you want to perform dynamic analysis).

# CTI just for fun!

We know that this is just an exercise, but why not try to map all TTPs of this malware and create a Yara rule?

Based on our analysis, the following TTPs are:

| Tactic | Technique | Description |
| --- | --- | --- |
| Defense Evasion | [T1027.002](https://attack.mitre.org/techniques/T1027/002/) | This malware uses a UPX packer to protect the final payload. |
| Persistence / Privilege Escalation | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | This malware creates a Windows service as part of persistence.  |
| Impact | [T1499.003](https://attack.mitre.org/techniques/T1499/003/) | This malware will wait until 2100 and then perform a DDoS on the target website by creating 20 threats.  |

```
rule Lab01_02_PMA {
	
	strings:
		$check_mutex = { 00 00 68 28 30 40 00 6a 00 68 01 00 1f 00 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 6a 00 ff 15 ?? ?? ?? ?? 56 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? }
		$str_mutex = "HGL345" ascii wide
		$str_malservice = "MalService" ascii wide

	condition:
		filesize <= 20KB and $check_mutex and any of ($str_*)

}
```
