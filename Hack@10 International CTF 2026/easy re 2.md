# easy re 2 - Detailed Writeup

Challenge: `easy re 2`  
Flag: `hack10{minato-namikaze}`

## 0. Why this writeup is long

This writeup is meant to be a future reference document, not just a short solve note.

It covers:

- the correct solve path
- the wrong direction / bait path
- the reasoning process phase by phase
- the beginner confusions that came up during analysis
- exact commands to run
- extra native-analysis notes, including a pwndbg workflow for the bait path

This challenge is a good example of a common reversing lesson:

> the hardest part is often not understanding assembly; it is choosing the correct layer to inspect first.

## 1. Final Answer

Flag:

```text
hack10{minato-namikaze}
```

## 2. Beginner glossary for this challenge

This section exists because these terms were easy to get confused about during the solve.

### 2.1 What is an APK?

An Android APK is basically a ZIP archive containing:

- app code
- native libraries
- resources
- assets
- metadata

That means the first thing to do is usually:

```bash
file chall.apk
unzip -l chall.apk
```

### 2.2 What is `classes.dex`?

`classes.dex` is Android bytecode.  
This is where Java/Kotlin app logic usually lives after compilation.

Tools like JADX can decompile it back into readable Java-like code.

### 2.3 What are `.so` files?

Files like:

- `lib/arm64-v8a/libdummy.so`
- `lib/x86_64/libdummy.so`

are native shared libraries.

`.so` means:

- shared object
- roughly the Linux/Android equivalent of a Windows `.dll`

These usually come from C or C++ code compiled directly into machine code.

This is called **native code** because the CPU runs it directly.

### 2.4 What is native reversing?

Native reversing means reversing compiled machine code from a binary like `.so`.

Compared to Java reversing:

- Java / DEX is easier to decompile
- native binaries are lower-level
- symbols may be stripped
- types may be unclear
- you often read assembly or imperfect decompiled C

So when triaging an APK:

1. `assets/` is usually cheapest
2. `classes.dex` is medium difficulty
3. `.so` native libraries are usually the most expensive

### 2.5 What is a `.bkp` file?

`.bkp` is just a filename extension. It is not a guaranteed format.

Usually it suggests:

- backup
- stored copy
- custom app data

In CTFs, a file like `background.bkp` often means:

- obfuscated image
- encoded blob
- encrypted data

Never trust the extension. Inspect the bytes.

### 2.6 Are `background.txt` and `background.bkp` inside the APK?

Yes.

Their paths are:

- `assets/background.txt`
- `assets/background.bkp`

inside `chall.apk`.

### 2.7 What is an MD5 collision?

An MD5 collision means:

> two different inputs produce the same MD5 hash

Example conceptually:

- input A != input B
- but `MD5(A) == MD5(B)`

MD5 is cryptographically broken, so collisions can be constructed.

In this challenge, the inner login logic wants:

- `username != password`
- but `md5(username) == md5(password)`

That is a collision-style bait condition.

## 3. High-level solve strategy

I broke the challenge into phases.

### Phase 1

Triage the APK and list the attack surface.

### Phase 2

Inspect the cheapest suspicious artifacts first.

### Phase 3

Decode `background.bkp`, recover the image, read the clue.

### Phase 4

Explain the bait path: wrapper APK, hidden payload APK, login logic, JNI/native branch.

### Phase 5

Document optional deeper native-analysis steps and pwndbg notes for future study.

## 4. Phase 1 - Triage the APK

The first rule here:

> Do not start by reversing the hardest-looking thing.

Start with archive inspection.

### 4.1 Basic file inspection

Commands:

```bash
file chall.apk
unzip -l chall.apk | sed -n '1,120p'
aapt dump badging chall.apk | sed -n '1,80p'
```

Important results:

- `chall.apk` is an Android package
- it contains `classes.dex`
- it contains native libs under `lib/`
- it contains `assets/background.txt`
- it contains `assets/background.bkp`

Relevant APK entries:

```text
AndroidManifest.xml
classes.dex
assets/background.txt
assets/background.bkp
lib/armeabi-v7a/libdummy.so
lib/arm64-v8a/libdummy.so
lib/x86/libdummy.so
lib/x86_64/libdummy.so
```

### 4.2 Initial hypotheses

At this point, the likely targets are:

1. assets
2. Java code in `classes.dex`
3. native code in `.so`

Because the challenge is a warmup, the rational priority is:

1. `assets/background.bkp`
2. `assets/background.txt`
3. Java layer
4. native layer

This is the first important interview point:

> the correct initial move was triage, not native reversing.

## 5. Phase 2 - Inspect the suspicious assets first

This phase is where the challenge becomes easy if the triage was good.

### 5.1 Inspect `background.txt`

Command:

```bash
unzip -p chall.apk assets/background.txt | head
```

What it contains:

```text
url(data:image/jpeg;base64,...)
```

Meaning:

- `background.txt` contains a base64-encoded JPEG
- the application clearly uses a JPEG background

This matters because it gives context for `background.bkp`.

### 5.2 Inspect `background.bkp`

Command:

```bash
python3 -c "import zipfile; data=zipfile.ZipFile('chall.apk').read('assets/background.bkp'); print(data[:16].hex())"
```

Beginning of the file:

```text
1037100eef25aa97...
```

That is not an obvious standard file signature.

Common headers to memorize:

- JPEG: `ff d8 ff`
- PNG: `89 50 4e 47`
- ZIP: `50 4b 03 04`
- ELF: `7f 45 4c 46`

So `background.bkp` is likely transformed data.

## 6. Why XOR with `0xEF`?

This was not guessed randomly.

The reasoning was:

1. `background.txt` already proves the app uses a JPEG background
2. `background.bkp` has the same basename, so it may be another copy of that image
3. the first bytes of `background.bkp` are `10 37 10 0e`
4. a JPEG often starts with `ff d8 ff e1`

Now compare byte-by-byte:

```text
0x10 ^ 0xFF = 0xEF
0x37 ^ 0xD8 = 0xEF
0x10 ^ 0xFF = 0xEF
0x0E ^ 0xE1 = 0xEF
```

All four header bytes give the same XOR key: `0xEF`.

That is very strong evidence for a single-byte XOR.

You can verify that directly:

```bash
python3 -c "enc=bytes.fromhex('1037100e'); jpg=bytes.fromhex('ffd8ffe1'); print([hex(a^b) for a,b in zip(enc,jpg)])"
```

Expected output:

```text
['0xef', '0xef', '0xef', '0xef']
```

This is the key known-header attack for the solve.

## 7. Phase 3 - Decode the image and read the clue

### 7.1 Recover the JPEG

Command:

```bash
python3 -c "import zipfile; data=zipfile.ZipFile('chall.apk').read('assets/background.bkp'); open('background_from_bkp.jpg','wb').write(bytes([b^0xEF for b in data]))"
```

### 7.2 Verify that the decode worked

Command:

```bash
file background_from_bkp.jpg
```

Expected result:

```text
background_from_bkp.jpg: JPEG image data ...
```

This verification step matters. Never assume the transform is correct just because the first few bytes look good.

### 7.3 Read the clue from the recovered image

Opening the image shows:

- a Naruto-themed wallpaper
- handwritten red text across the image

The text is arranged spatially, not in one clean line.

The visible parts spell:

```text
hack10{
minato-
namika
ze}
```

Normalized, this becomes:

```text
hack10{minato-namikaze}
```

That is the flag.

### 7.4 Why this is the intended warmup path

Because at this point:

- no dynamic execution was required
- no unpacking was required
- no JNI reversing was required
- no MD5 collision generation was required

The challenge is solved directly from the outer APK asset layer.

## 8. The wrong direction / bait path

This challenge includes a technically real, much harder path that looks like the intended route.

That path is the bait.

### 8.1 Why it looks scary

The APK contains:

- a wrapper application
- encrypted appended payload data in `classes.dex`
- AES-GCM decryption logic
- `DexClassLoader` loading of a hidden `payload.apk`
- native JNI code in `libnative-lib.so`
- a fake login flow involving MD5 collisions

If you blindly follow complexity, you end up spending much more time than necessary.

### 8.2 Why the bait path still matters

It is useful to understand because:

- it shows the challenge structure
- it explains the misdirection
- it is interview-relevant: you can explain both the hard path and why you rejected it

## 9. Phase 4 - Reverse the wrapper manually

This section explains the outer APK as if solving it manually.

### 9.1 Decompile the outer APK

Command:

```bash
jadx -d easyre_jadx chall.apk
```

Useful files:

- `easyre_jadx/sources/com/example/reforceapk/ProxyApplication.java`
- `easyre_jadx/sources/com/example/reforceapk/MainActivity.java`
- `easyre_jadx/sources/com/example/reforceapk/RefInvoke.java`

### 9.2 What `ProxyApplication` is doing

The important class is `ProxyApplication`.

Its job is:

1. read `classes.dex`
2. extract a hidden encrypted blob from the end
3. decrypt it
4. save it as `payload.apk`
5. replace the class loader
6. run the real app from the decrypted payload

This is classic wrapper / shell / packer behavior.

### 9.3 Important functions in `ProxyApplication`

#### `attachBaseContext(...)`

This is the entry point for the shell behavior.

Main actions:

- creates directories for payload files
- sets the path for `payload.apk`
- if `payload.apk` does not exist:
  - read `classes.dex`
  - extract payload bytes
  - decrypt payload
- build a `DexClassLoader`
- replace the app class loader with the payload loader

That means the visible APK is not the real app. It is a launcher shell.

#### `splitPayLoadFromDex(byte[] apkdata)`

This function explains how the hidden payload is stored.

Logic:

- take the last 4 bytes of `classes.dex`
- interpret them as a big-endian integer `payload_len`
- copy the previous `payload_len` bytes
- decrypt that blob
- write the result to `payload.apk`

So the payload is appended to the end of the DEX.

#### `decrypt(byte[] srcdata)`

This is the key derivation logic.

It:

- reads `classes.dex`
- copies the first 4096 bytes
- zeroes selected header ranges
- computes `SHA-256` of the modified head
- uses a hardcoded 32-byte pepper
- derives:
  - AES key from `SHA256(pepper || digest || 0x00)`
  - nonce from `SHA256(pepper || digest || 0x01)` and takes the first 12 bytes
- decrypts the payload using `AES/GCM/NoPadding`

This is a real unpacking routine, not fake code.

## 10. Recovering the inner payload manually

This is not needed for the flag, but useful for understanding the bait path.

### 10.1 Extract `classes.dex`

Command:

```bash
unzip -p chall.apk classes.dex > classes.dex
```

### 10.2 Decrypt the appended payload

Command:

```bash
python3 - <<'PY'
import hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

dex = open('classes.dex','rb').read()
enc_len = struct.unpack('>I', dex[-4:])[0]
enc = dex[-4-enc_len:-4]

head = bytearray(dex[:min(4096, len(dex))])
for start, end in [(8,12),(12,32),(32,36)]:
    for i in range(start, min(end, len(head))):
        head[i] = 0

pepper = bytes([
    109, 242, 71, 168, 224, 200, 58, 179,
    222, 88, 133, 30, 23, 195, 169, 80,
    214, 151, 38, 29, 18, 52, 86, 120,
    154, 188, 222, 240, 171, 205, 239, 17
])

dex_digest = hashlib.sha256(head).digest()
key = hashlib.sha256(pepper + dex_digest + b'\x00').digest()
nonce = hashlib.sha256(pepper + dex_digest + b'\x01').digest()[:12]

payload = AESGCM(key).decrypt(nonce, enc, None)
open('payload.apk','wb').write(payload)
print('payload written:', len(payload), 'bytes')
PY
```

### 10.3 Decompile the inner APK

Command:

```bash
jadx -d payload_jadx payload.apk
```

Useful files:

- `payload_jadx/sources/com/example/myapk/MainActivity.java`
- `payload_jadx/sources/com/example/myapk/ImageEncryptor.java`

## 11. Inner APK logic explained

### 11.1 `MainActivity` summary

The inner app:

- loads a background image from `assets/background.txt`
- lets the user pick a background image
- takes username and password
- checks a weird MD5 condition
- on success, encrypts the selected image using `ImageEncryptor`

### 11.2 The login logic

The relevant logic is effectively:

```java
String username = ...
String password = ...

if (username.equals(password)) fail;

if (!md5(username).equals(md5(password))) fail;

success;
```

What this means:

- if username and password are the same exact string -> reject
- if their MD5 digests are different -> reject
- success only happens when:
  - username != password
  - but MD5(username) == MD5(password)

That is exactly a collision-style condition.

### 11.3 Why this is bait

This path can work in principle, but it is a bad solve path because:

- generating usable collision inputs is more work
- Android text fields are an awkward place for raw collision payloads
- even after bypassing login, you still need to analyze the native image transform
- the flag is already exposed in the outer asset path

So the bait path is not impossible; it is simply the wrong cost/benefit choice for a warmup.

## 12. Native branch summary

The inner APK has:

- `lib/arm64-v8a/libnative-lib.so`
- `lib/x86_64/libnative-lib.so`

Java side:

- `ImageEncryptor.encryptData(...)`
- which calls native `encryptDataNative(...)` if the native library loads

This is the natural place to start native reversing if you had not already solved the challenge from assets.

## 13. Manual native-analysis notes

Again, this was not required to get the flag, but it is useful study material.

### 13.1 Extract the x86_64 native library

Command:

```bash
unzip -p payload.apk lib/x86_64/libnative-lib.so > libnative-lib.so
file libnative-lib.so
```

Expected:

```text
ELF 64-bit LSB shared object, x86-64, ...
```

### 13.2 First-pass static checks

Commands:

```bash
strings -a -n 4 libnative-lib.so | head -n 80
readelf -S libnative-lib.so | sed -n '1,120p'
strings -a -n 4 libnative-lib.so | grep -i native
```

Things to look for:

- JNI symbol names
- hardcoded strings
- file-format markers
- custom keys or labels

Typical target function:

```text
Java_com_example_myapk_ImageEncryptor_encryptDataNative
```

That tells you the Java-to-native bridge point.

## 14. Pwndbg workflow for the native bait path

This section is here because it was explicitly requested for future study.

The actual flag solve did not require pwndbg, but if you wanted to continue down the native branch manually, this is the workflow I would use.

### 14.1 Important caveat

`libnative-lib.so` is a JNI library, not a standalone executable.

That means to debug it properly you would typically need one of:

- an Android emulator/device running the app
- a local JNI harness that loads the library and calls the target JNI function

So the commands below are a future reference workflow for the native branch, not the required solve path.

### 14.2 If debugging on an emulator/device

Typical setup outline:

```bash
adb install -r payload.apk
adb shell ps -A | grep example
adb shell run-as com.example.forceapkobj
adb shell gdbserver :1234 --attach <pid>
adb forward tcp:1234 tcp:1234
```

Then locally:

```bash
gdb -q
target remote :1234
```

If pwndbg is configured in your GDB setup, you can then use pwndbg commands.

### 14.3 Core pwndbg commands to remember

Once attached:

```gdb
checksec
vmmap
info sharedlibrary
info functions Java_com_example_myapk_ImageEncryptor_encryptDataNative
break Java_com_example_myapk_ImageEncryptor_encryptDataNative
continue
bt
context
disassemble
ni
si
finish
x/32bx $rdi
x/32bx $rsi
x/64bx $rsp
```

Useful pwndbg-specific helpers:

```gdb
nearpc
hexdump $rdi 64
telescope $rsp 16
```

What these are for:

- `checksec`: see protections
- `vmmap`: memory map overview
- `info sharedlibrary`: confirm library load
- `break ...`: stop at the JNI entry
- `bt`: see call stack
- `context`: registers + code + stack
- `ni` / `si`: step
- `x/..`: inspect memory
- `nearpc`: instructions around current RIP

### 14.4 What I would look for inside the JNI function

I would want to answer:

1. Does it prepend a custom header?
2. Does it XOR or stream-encrypt the image bytes?
3. Does it reuse or modify `background.bkp`?
4. Are there obvious constants like `BKP1`, `key`, `chk`, or magic values?

### 14.5 If using a local harness

If I wrote a small JNI test harness to load `libnative-lib.so`, the workflow would be:

```bash
gdb -q ./harness
```

Then inside pwndbg:

```gdb
checksec
break Java_com_example_myapk_ImageEncryptor_encryptDataNative
run
bt
context
disassemble
ni
si
finish
```

Again, this was not needed to solve the challenge. It is included here as a learning appendix.

## 15. Why the hard path was rejected

This is the most important strategic point in the solve.

The bait path had all of this:

1. wrapper APK analysis
2. payload extraction
3. payload decryption
4. inner APK decompilation
5. MD5-collision login condition
6. JNI/native analysis
7. possible dynamic debugging

The cheap path had:

1. inspect suspicious asset
2. infer single-byte XOR from JPEG header
3. decode file
4. read clue

For a warmup challenge, that cost comparison is decisive.

This is the real hacker mindset:

> do not follow complexity just because it exists

Instead:

- build hypotheses
- test the cheapest strong one first
- stop when the evidence is sufficient

## 16. Interview-friendly summary

If I had to explain this challenge quickly in an interview, I would say:

1. I triaged the APK first instead of diving into native code.
2. I found both a wrapper/native path and suspicious assets.
3. I verified the wrapper existed and recognized it as an expensive path.
4. I prioritized the `assets/background.bkp` artifact because it was cheaper and high-signal.
5. I inferred a single-byte XOR key from a known JPEG header:
   - observed bytes: `10 37 10 0e`
   - expected JPEG bytes: `ff d8 ff e1`
   - all XORs gave `0xEF`
6. I decoded the file, recovered a valid JPEG, and read the handwritten clue.
7. The flag was `hack10{minato-namikaze}`.

That explanation shows both:

- technical correctness
- decision-making quality

## 17. Minimal command log

If I only wanted the shortest reproducible command list:

```bash
file chall.apk
unzip -l chall.apk | sed -n '1,120p'
unzip -p chall.apk assets/background.txt | head
python3 -c "import zipfile; data=zipfile.ZipFile('chall.apk').read('assets/background.bkp'); print(data[:16].hex())"
python3 -c "enc=bytes.fromhex('1037100e'); jpg=bytes.fromhex('ffd8ffe1'); print([hex(a^b) for a,b in zip(enc,jpg)])"
python3 -c "import zipfile; data=zipfile.ZipFile('chall.apk').read('assets/background.bkp'); open('background_from_bkp.jpg','wb').write(bytes([b^0xEF for b in data]))"
file background_from_bkp.jpg
```

## 18. Full command log used for deeper manual analysis

### APK triage

```bash
file chall.apk
unzip -l chall.apk | sed -n '1,120p'
aapt dump badging chall.apk | sed -n '1,80p'
```

### Outer APK decompilation

```bash
jadx -d easyre_jadx chall.apk
```

### Search interesting strings

```bash
grep -Rni "native\|flag\|check\|secret\|password\|md5" easyre_jadx/sources
```

### Extract `classes.dex`

```bash
unzip -p chall.apk classes.dex > classes.dex
```

### Decrypt the hidden payload

```bash
python3 - <<'PY'
import hashlib, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

dex = open('classes.dex','rb').read()
enc_len = struct.unpack('>I', dex[-4:])[0]
enc = dex[-4-enc_len:-4]

head = bytearray(dex[:min(4096, len(dex))])
for start, end in [(8,12),(12,32),(32,36)]:
    for i in range(start, min(end, len(head))):
        head[i] = 0

pepper = bytes([
    109, 242, 71, 168, 224, 200, 58, 179,
    222, 88, 133, 30, 23, 195, 169, 80,
    214, 151, 38, 29, 18, 52, 86, 120,
    154, 188, 222, 240, 171, 205, 239, 17
])

dex_digest = hashlib.sha256(head).digest()
key = hashlib.sha256(pepper + dex_digest + b'\x00').digest()
nonce = hashlib.sha256(pepper + dex_digest + b'\x01').digest()[:12]

payload = AESGCM(key).decrypt(nonce, enc, None)
open('payload.apk','wb').write(payload)
print('payload written:', len(payload))
PY
```

### Decompile the payload APK

```bash
jadx -d payload_jadx payload.apk
```

### Extract and inspect the native library

```bash
unzip -p payload.apk lib/x86_64/libnative-lib.so > libnative-lib.so
file libnative-lib.so
strings -a -n 4 libnative-lib.so | grep -i native
readelf -S libnative-lib.so | sed -n '1,120p'
```

### Actual flag solve

```bash
python3 -c "import zipfile; data=zipfile.ZipFile('chall.apk').read('assets/background.bkp'); open('background_from_bkp.jpg','wb').write(bytes([b^0xEF for b in data]))"
file background_from_bkp.jpg
```

## 19. Final takeaways

The challenge intentionally mixes:

- real wrapper logic
- real payload decryption
- real JNI/native code
- fake-hard login logic
- a trivial outer asset-based leak

The important lesson is:

> complexity is not automatically the correct path

The solve came from:

- triage
- recognizing suspicious assets
- applying known file-header reasoning
- validating the cheapest hypothesis first

Final flag:

```text
hack10{minato-namikaze}
```
