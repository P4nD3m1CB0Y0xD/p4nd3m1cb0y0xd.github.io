---
title:  "A new downloader in Go used by Brazillian threat actors"
date:   2024-07-22
draft: false
categories: ["YouGotReversed"]
tags: ["reverse-engineer", "malware-analysis", "golang"]
---

## Key Finds

- During our hunt section, we identified what looks like a new downloader written in the Go programming language, which was employed by Brazilian threat actors.
- Based on our information and data so far, this new downloader has existed since 06/20/2024.
- The second stage of this threat appears to be the Ousaban banking trojan, but this assumption is not very trustworthy.
- Based on this new malware, we can assume that Brazilian threat actors are experimenting with new technologies to apply to their infection chain.

## Introduction

This threat delivered its payload by sending a phishing [[T1566](https://attack.mitre.org/techniques/T1566/)] email to the victim. The email contained a link to a cloud storage provider, Azure Blob Storage.  

{{< figure
    src="imgs/img00.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

After a victim clicks on the malicious link, a zip file is downloaded to the target computer. From what we observe, this malicious archive follows a name similar to:

- `docx<9 random number>.zip`
- `ação<9 random number>.zip`

If a victim extracts the content of the zip file, an executable (the Golang downloader) follows a similar nomenclature but with a `“` symbol at the end of the nine random numbers.

- `ação<9 random number>".exe`

Using a fuzzing hash like TLSH and creating a simple query to search for similar files in VirusTotal, it was possible to identify other eight similar samples.

`tlsh:T1CCB6BF47EC9545A9C0EEA230C9B292977A717C495B3123D32B90F73D2F76BD06AB9340 AND entity:file tag:overlay engines:redcap AND sigma_rule:157ee4e95270f64481c50464c0e4766830e1e2b38b214a98f9e3f977857c6c69`

**Obs:** This sigma rule was used because this sample performs a reboot of the target system to set its persistence.

{{< figure
    src="imgs/img01.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

Similar samples uploaded to virustotal

By taking our suspicious file to our lab environment, it was possible to desiccate this threat.

## Digging into their minds

Performing a simple triage in the binary reveals that the time stamp was changed [[T1070.006](https://attack.mitre.org/techniques/T1070/006/)]. Malware authors commonly use this as a basic anti-forensic technique. We also see that this binary targets just x64-bit systems.

The final thought that is taken from this is a suspicious binary overlay. This suggests that it may be packed (this was just part of my hypothesis process during the analysis).

{{< figure
    src="imgs/img02.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

Collecting simple information about the binary

Another good observation is that this go binary isn’t stripped, which means we can see a lot of information, like function names.

Open the sample in IDA and jump into the `main_main` function; we will start desiccating this sample to extract all kinds of intelligence.

{{< figure
    src="imgs/img03.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

In this first block of assembly code, just by reading the function names that IDA recovers, we can assume that it will just create a directory named `Microsoft.NET\assembly\tangeu` into the user’s directory. In the very beginning, we also see a call to `time.Sleep` function, probably to slow down the execution into the sandbox.

After creating the directory, the malware generates a 10-length random string to use as a name for a zip file that will be placed in the `Microsoft.NET\assembly` directory.

{{< figure
    src="imgs/img04.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

The next action performed by this malware is to decode its config. The encoding process employed is very simple: `base64 → xored (key: psdql)`

After writing a simple Python script to decode its config, the output result is:

```python
import base64

def b64decode_xor(data: str, key: bytes) -> bytearray:
    try:
        cipher_text = base64.b64decode(data)
    except Exception as e:
        return None
    
    bKey = bytes(key)
    cipher_text = bytearray(cipher_text)
    for i in range(len(cipher_text)):
        cipher_text[i] ^= bKey[i % len(bKey)]

    return cipher_text.decode()

def main() -> None:
    encoded_data: list[str] = [
    "GAcQAR9KXEsGGwddBx4BFQEHGAMZFwEQABkJBRUDXhALHEMHHBYVQgoaFA==",
    "M0k4IR4fFBYQAVA1DR0JAy8wHhwRCUQ+KjQvMxAeAxIT",
    "GAcQAR9KXEsSAx0WFhIFHwEBBwMcBgcQA14QCxxDHhwSEEMTEgkUHhFdFBkcTwEICVE=",
    "IxwCBRsRAQEtIRkQFh4fHxUQLTsZHQAeGwMvJwQeAhYKBToVARcYAx4vNgQC"
    ]
    xor_key: bytes  = b"psdql"

    for data in encoded_data:
        print(b64decode_xor(data, xor_key))

if __name__ == '__main__':
    main()
```

```text
Output results:
>>> https[://]www[.comercioidealizado.]com/word.zip --> Second stage

>>> C:\Program Files\Topaz OFD\Warsaw --> Path to Topaz software

>>> https[://]comerciorevolucao[.]com/nova/camera.php?rlx= --> C2 domain

>>> Software\Microsoft\Windows\CurrentVersion\Run --> Persistence place
```

After decoding its config, the malware performs a request to the `https[://]www[.comercioidealizado.]com/word.zip` to download its second stage and extract the content from the zip file to the `tangeu` directory and execute the command: `shutdown /r /t 90` to reboot the system with the message.

{{< figure
    src="imgs/img05.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

Finally, the malware just set its persistence into the hive `HKEY_CURRENT_USER` with a random name pointing to the legitimate executable `textr.exe`, an OCR software from `ASCOMP Software GmbH` used to perform a DLL Side Loading [[T1574.002](https://attack.mitre.org/techniques/T1574/002/)]. The malicious DLL used is named as `NsBars.dll`. By searching its hash into VirusTotal, we see that this is a Delphi binary packed with VMProtect.

{{< figure
    src="imgs/img06.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

After this, I shift my focus to reverse engineering the Go binary. The full source code can be found on my [GitHub](https://github.com/P4nD3m1CB0Y0xD/YouGotReversed/tree/main/Golang/Downloader/04-07-2024).

## Conclusion

Based on our analysis, we probably discovered a new downloader written in Go used by Brazillian threat actors to change their infection chain. This shows us the continues evolution in the Brazilian threat landscape.

We also reverse-engineered the binary and tried to recreate a similar code employed by the threat actor. You can check at my Github.

## Mitre ATT&CK

| Tactic | Technique | Description |
| --- | --- | --- |
| Initial Access | Phishing [T1566] | This threat employed phishing attack to delivery its malicious file.    |
| Execution | User Execution::Malicious File [T1204.002] | The used need to extract the content from the zip file and execute the executable file. |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder [T1547.001] | The downloader set its persistence at the user CurrentVersion\Run registry key. |
| Defense Evasion | Obfuscated Files or Information [T1027] | This downloader encodes its config using base64 and xor cipher. |
| Defense Evasion | Indicator Removal: Timestamp [T1070.006] | The timestamp of the file was changed. |
| Defense Evasion | Hijack Execution Flow: DLL Side-Loading [T1574] | After downloading the second stage, this malware performs a side loading using the ASCOMP Software GmbH |
| Discovery | File and Directory Discovery [T1083] | Checks if the infected host has the Topaz OFD directory.  |
| Impact | System Shutdown/Reboot [T1529] | The malware reboots the system after setting its persistence. |

## IoCs

| IOCs | Description |
| --- | --- |
| https[://]www[.comercioidealizado.]com/word.zip | Second stage |
| https[://]comerciorevolucao[.]com/nova/camera.php?rlx= | C2 |
| 4e2719f310a99893258f5727ef7ec340f70ede74dfad581da73358ef429b5fd9 | .exe |
| d3ba423f5788b1f2eeb2c51ad393c07f87b3af60dbd0f6c4194e9122fb9a6149 | .zip |
| 24053c24abf52a804823c8ee044981f795b49a4c1a8bc6f8982331fb3174d781 | .dll (vmprotect) |
