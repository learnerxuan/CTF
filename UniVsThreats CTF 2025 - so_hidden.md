# Android Pentesting CTF Writeup - so_hidden Challenge

## Challenge Overview
**Description:** "We found an APK. It is useless, or isn't it?"  
An APK named "jokes_and_info.apk" was provided for analysis.

## Solution Approach

### Step 1: Initial APK Analysis
I began by opening the APK using jadx-gui, a tool that decompiles Android APKs and DEX files into readable Java source code. This allowed me to examine the application's structure and code.

### Step 2: Code Examination
After extracting the AndroidManifest.xml and MainActivity code, I analyzed them to identify potential entry points or vulnerabilities. During my analysis, I discovered an interesting `Utils` class with native methods:

```java
package com.example.uvt_ctf_2025;
/* loaded from: classes3.dex */
public class Utils {
    private native String getHiddenFlag();
    public native String getJoke();
    public native String getUVTCTF();
    static {
        System.loadLibrary("native-lib");
    }
}
```

The class referenced a native library (`native-lib`), which suggested that critical functionality was implemented in native code.

![Utils Class Code](https://github.com/user-attachments/assets/b749f2fb-635d-4038-b142-4684b109ecce)

### Step 3: Native Library Analysis
I imported the `libnative-lib.so` file into Ghidra for deeper analysis. This revealed three important functions corresponding to the native methods from the `Utils` class:

![Native Library Functions](https://github.com/user-attachments/assets/4440086c-cd33-4b5d-a98e-97aabec83370)

```java
undefined4 Java_com_example_uvt_1ctf_12025_Utils_getHiddenFlag(int *param_1)
{
  void *__ptr;
  undefined4 uVar1;
  
  __ptr = (void *)FUN_00010a50("91.99.1.179",0xa4fa,"/somebody-found-a-random-flag-path");
  uVar1 = (**(code **)(*param_1 + 0x29c))(param_1,__ptr);
  free(__ptr);
  return uVar1;
}
```

```java
undefined4 Java_com_example_uvt_1ctf_12025_Utils_getJoke(int *param_1)
{
  void *__ptr;
  undefined4 uVar1;
  
  __ptr = (void *)FUN_00010a50("91.99.1.179",0xa4fa,"/jokes");
  uVar1 = (**(code **)(*param_1 + 0x29c))(param_1,__ptr);
  free(__ptr);
  return uVar1;
}
```

```java
undefined4 Java_com_example_uvt_1ctf_12025_Utils_getUVTCTF(int *param_1)
{
  void *__ptr;
  undefined4 uVar1;
  
  __ptr = (void *)FUN_00010a50("91.99.1.179",0xa4fa,"/uvt-ctf");
  uVar1 = (**(code **)(*param_1 + 0x29c))(param_1,__ptr);
  free(__ptr);
  return uVar1;
}
```

### Step 4: Network Request Analysis
All three functions followed a similar pattern, calling `FUN_00010a50` with three parameters:
1. IP address: `91.99.1.179`
2. Port number: `0xa4fa` (decimal 42234)
3. Endpoint paths:
   - `/somebody-found-a-random-flag-path` for `getHiddenFlag`
   - `/jokes` for `getJoke`
   - `/uvt-ctf` for `getUVTCTF`

This indicated that the application was making network requests to a remote server.

### Step 5: Dynamic Analysis
I installed the APK on an Android emulator and configured HTTP Toolkit to monitor network traffic on port 42234. When I launched the application, I observed the following UI:

![Application UI](https://github.com/user-attachments/assets/00353278-3461-4e1b-a234-1f336c4a460a)

### Step 6: Traffic Monitoring
Through HTTP Toolkit, I successfully captured requests to:
- `91.99.1.179:42234/jokes`
- `91.99.1.179:42234/uvt-ctf`

However, I noticed that the `/somebody-found-a-random-flag-path` endpoint was never accessed during normal application usage.

### Step 7: Finding the Flag
After attempting several approaches to trigger the hidden endpoint from within the application without success, I realized the simplest solution might be to directly access the endpoint. I opened a web browser and navigated to:

```
http://91.99.1.179:42234/somebody-found-a-random-flag-path
```

This returned the flag:
```json
{"flag":"UVT{m0b1l3_.s0_m4y_c0nt4in_s3ns1tiv3_1nf0}"}
```

## Key Takeaways
- Native code in Android applications often contains sensitive information or functionality.
- Network requests hardcoded in native libraries can reveal important endpoints.
- Sometimes the simplest approach (directly accessing an endpoint) can be the most effective solution.
- Always check for hardcoded URLs, IP addresses, and credentials in both Java and native code when performing mobile application security assessments.

## Tools Used
- jadx-gui: For decompiling the APK
- Ghidra: For analyzing the native library
- Android Emulator: For running the application
- HTTP Toolkit: For monitoring network traffic
