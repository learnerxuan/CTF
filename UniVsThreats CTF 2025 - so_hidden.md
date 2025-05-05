Learned a bit of Android Pentest a while ago before this CTF. I solved this challenge with the help of AI (Gemini).

DESCRIPTION: We found an APK. It is useless, or isn't it?  
An APK named "jokes_and_info.apk" was given.

1. First thing, I opened the APK using jadx-gui, which decompiles Android APKs and DEX files into readable Java source code.  
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
http://91.99.1.179:42234/somebody-found-a-random-flag-path
{"flag":"UVT{m0b1l3_.s0_m4y_c0nt4in_s3ns1tiv3_1nf0}"}
