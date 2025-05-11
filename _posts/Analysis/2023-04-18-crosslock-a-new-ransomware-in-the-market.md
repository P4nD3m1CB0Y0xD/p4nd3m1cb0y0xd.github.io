---
title:  "CrossLock a new ransomware in the market"
date:   2023-04-18 12:00:00 +0300
classes: wide
header:
  teaser: "/assets/images/ma-crosslock/2023-04-18_crosslock-ransomware.webp"
ribbon: red
categories: 
  - Malware Analysis
tags:
  - malware
  - reverse-engineering
  - CTI
toc: true
---

![CrossLock Ransomware by NightCafe.Studio](/assets/images/ma-crosslock/2023-04-18_crosslock-ransomware.webp){:class="img-responsive"}

# Introduction
CrossLock is a new variant of the ransomware family. Its first appearance was in April 2023, targeting a Brazilian company. It was first shared by [S!Ri on Twitter](https://twitter.com/siri_urz/status/1647892158739873793). This new threat is written in Golang, a programming language known for its efficiency and speed. Even though it’s a new variant, its modus operandi is very similar to other ransomware.

However, even though it has nothing particularly different from other ransomware in the market, it’s a really simple piece of code. As mentioned by [JohnK3r on Twitter](https://twitter.com/johnk3r/status/1648000267864907779), CrossLock uses a framework called [Freeze](https://github.com/optiv/Freeze), which is used for creating payloads to circumvent EDRs.

![Tweet from johnk3r](/assets/images/ma-crosslock/2023-04-18_johnk3r-tweet.webp){:class="img-responsive"}

# A quick analysis
Just by getting the information provided by VirusTotal, it’s possible to see that its infection chain isn’t different from other ransomware. Basically, it will use some LOLBins to remove shadow copies, delete Windows logs, disable recovery mode, etc. It’s pretty much the same.

An interesting thing about this sample is that it tries to impersonate the `notepad.exe` file, but this file isn’t signed by Microsoft.

![CrossLock trying to impersonate a legitimate file](/assets/images/ma-crosslock/2023-04-18_crosslock-impersonate-legitimate-file.webp){:class="img-responsive"}

Looking at its strings, they aren’t obfuscated. So, after collecting some basic information about the binary, we start to observe its behavior in the lab environment.

![Injection Chain](/assets/images/ma-crosslock/2023-04-18_infection-chain.webp){:class="img-responsive"}

As we can see in the image above, those are some of the LOLBins used by the CrossLock ransomware in its infection chain.

![CrossLock video](/assets/images/ma-crosslock/2023-04-18_crosslock.gif){:class="img-responsive"}

So basically, CrossLock will create a suspended process using Notepad as its target. And just to be clear, those are the default options from the Freeze framework.

![Ransom note](/assets/images/ma-crosslock/2023-04-18_ransom-note.webp){:class="img-responsive"}

## Parameters
As we can see in the image below, these are all the arguments that can be passed to CrossLock to gain administrator privileges, abuse UAC by leveraging the `eventvwr.exe` binary, and encrypt other hosts in the infrastructure using the SMB protocol.

![Parameters used by CrossLock](/assets/images/ma-crosslock/2023-04-18_parameters-crosslock.webp){:class="img-responsive"}

# Conclusion
As this is a new ransomware variant, we need to keep up with its development in its next attacks. Performing hunting in your environment is a good idea to find some indicators.

# TTPs
<script src="https://gist.github.com/P4nD3m1CB0Y0xD/f8a8c1c42ae73366e7286eb5164090c7.js"></script>

# IoC & IoA
- SHA256: 495fbfecbcadb103389cc33828db139fa6d66bece479c7f70279834051412d72
- Build ID: TR_mEgwgRBRKBzLqwtCy/CrTSwLAFXgP-LonyC_5w/HFmcLGBkNJTMEENx_Huw/jmKxq_pGZOM9ijCEss6Y
- Ransom Note: — CrossLock_readme_To_Decrypt — .txt
- bcdedit /set {default} bootstatuspolicy ignoreallfailures
- bcdedit /set {default} recoveryenabled No
- cmd.exe /c “bcdedit /set {default} bootstatuspolicy ignoreallfailures”
- cmd.exe /c “bcdedit /set {default} recoveryenabled No”
- cmd.exe /c “vssadmin delete shadows /all /quiet”
- cmd.exe /c “wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest”
- cmd.exe /c “wbadmin DELETE SYSTEMSTATEBACKUP”
- cmd.exe /c “wbadmin delete catalog -quiet”
- cmd.exe /c “wevtutil cl application”
- cmd.exe /c “wevtutil cl security”
- cmd.exe /c “wevtutil cl system”
- vssadmin delete shadows /all /quiet
- wbadmin DELETE SYSTEMSTATEBACKUP
- wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest
- wbadmin delete catalog -quiet
- wevtutil cl application
- wevtutil cl security
- wevtutil cl system
- eventvwr.exe
- HKCU\Software\Classes\mscfile\shell\open\command
- .crlk