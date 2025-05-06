Learned a bit of Android Pentest a while ago before this CTF. I solved this challenge with the help of AI (Gemini).

DESCRIPTION: We found an APK. It is useless, or isn't it?  
An APK named "jokes_and_info.apk" was given.

1. First, I opened the APK using jadx-gui, which decompiles Android APKs and DEX files into readable Java source code.  
2. After that, I copied AndroidManifest.xml and the code of MainActivity and sent it to Gemini to help me extract valuable information.  
Gemini suggested I look at the function `Utils`.

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

![image](https://github.com/user-attachments/assets/b749f2fb-635d-4038-b142-4684b109ecce)

3. Next, I imported libnative-lib.so into Ghidra and found this:
   
![image](https://github.com/user-attachments/assets/4440086c-cd33-4b5d-a98e-97aabec83370)

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

All three functions (getHiddenFlag, getJoke, getUVTCTF) follow a very similar pattern:

FUN_00010a50("91.99.1.179", 0xa4fa, "/some-path");: This line strongly suggests a call to a function at address 0x00010a50. This function takes three arguments:

A string: "91.99.1.179" - This looks like an IP address.
A hexadecimal value: 0xa4fa - This translates to the decimal value 42234. This is very likely a port number.
A string representing a path:
"/somebody-found-a-random-flag-path" for getHiddenFlag
"/jokes" for getJoke
"/uvt-ctf" for getUVTCTF
This strongly indicates that the application is making network requests to the IP address 91.99.1.179 on port 42234 using different API endpoints.

http://91.99.1.179:42234/somebody-found-a-random-flag-path
{"flag":"UVT{m0b1l3_.s0_m4y_c0nt4in_s3ns1tiv3_1nf0}"}
