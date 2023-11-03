---
title:  "CrossLock a new ransomware in the market"
date:   2023-04-18 12:00:00 +0300
header:
  teaser: "/assets/images/2/2023-04-18_crosslock-ransomware.webp"
categories: 
  - tutorial
tags:
  - malware
  - reverse-engineering
  - CTI
---

![CrossLock Ransomware by NightCafe.Studio](/assets/images/2/2023-04-18_crosslock-ransomware.webp){:class="img-responsive"}

# Introduction
CrossLock is a new variant of the ransomware family. Its first appearance was in April 2023, targeting a Brazilian company. It was first shared by [S!Ri on Twitter](https://twitter.com/siri_urz/status/1647892158739873793). This new threat is written in Golang, a programming language known for its efficiency and speed. Even though it’s a new variant, its modus operandi are very similar to others ransomwares.

However, even though it has nothing so different from others ransomwares in the market. It’s a real simple piece of code. As mentioned by [JohnK3r on Twitter](https://twitter.com/johnk3r/status/1648000267864907779), CrossLock uses a framework called [Freeze](https://github.com/optiv/Freeze), that its used for creating payloads to circumventing EDRs.

![Tweet from johnk3r](/assets/images/2/2023-04-18_johnk3r-tweet.webp){:class="img-responsive"}

# A quick analysis
Just by getting the information that Virustotal inform to us it’s possible to see that its infection chain isn’t different from others ransomwares. Basically, it will use some LOLBins to remove shadow copys, delete windows logs, disable recovery mode, etc… It’s pretty much the same.

An interesting thing of this sample is that it’ll try to impersonate the `notepad.exe` file, but this file isn’t signed by Microsoft.

![CrossLock trying to impersonate a legitimate file](/assets/images/2/2023-04-18_crosslock-impersonate-legitimate-file.webp){:class="img-responsive"}

Looking at its strings, they aren’t obfuscated. So, after collecting some basic information about the binary. We start to see its behavior in the lab environment.

![Injection Chain](/assets/images/2/2023-04-18_infection-chain.webp){:class="img-responsive"}

As we can see on the image above, those are some of the LOLBins used by the CrossLock ransomware in its infection chain.

![CrossLock video](/assets/images/2/2023-04-18_crosslock.gif){:class="img-responsive"}

So basically CrossLock will create a suspended process using notepad as its target. And just to be clear, those are the default options from the Freeze framework.

![Ransom note](/assets/images/2/2023-04-18_ransom-note.webp){:class="img-responsive"}

## Parameters
As we can see in the image below, those are all the arguments that can be pass to the CrossLock to gain administrator privileges abuse de UAC by abusing `eventvwr.exe` binary and encrypt others hosts in the infrastructure using SMB protocol.

![Parameters used by CrossLock](/assets/images/2/2023-04-18_parameters-crosslock.webp){:class="img-responsive"}

# Conclusion
As this is a new ransomware variant, we need to keep up with its development in it next attacks. Perform a hunting in your environment is a good idea to find some indicators

# Conclusion
As this is a new ransomware variant, we need to keep up with its development in it next attacks. Perform a hunting in your environment is a good idea to find some indicators

# TTPs
| **Tactic** | **Technique** | **Sub-Technique**
| ----- |  ------- | ------- 
| Execution| Command and Scripting Interpreter| Windows Command Shell
| Defense Evasion| Process Injection| Process Hollowing
| Defense Evasion| Indicator Removal| Clear Windows Event Logs
| Privilege Escalation| Abuse Elevation Control Mechanism| Bypass User Account Control
| Discovery| System Service Discovery| -
| Discovery| Process Discovery| -
| Discovery| File and Directory Discovery| -
| Lateral Movement| Remote Services| SMB/Windows Admin Shares
| Impact| Data Encrypted for Impact| -
| Impact| Inhibit System Recovery| -

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