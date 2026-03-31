# hack@10 CTF 2026 easy_re Writeup

## Challenge Summary

- Challenge type: Android APK reverse engineering
- Main skills:
  - APK triage
  - shell/packer detection
  - Java decompilation
  - JNI/native triage
  - reducing noisy native code into a simple crypto model
  - validating a candidate key by decrypting the real embedded artifact
- Final lesson:
  - the challenge looks like an Android login app
  - it is actually a staged loader that hides the real APK, then hides the real clue inside an encrypted image blob

## Files You Start With

- `chall.apk`

Useful hashes:

```bash
sha256sum chall.apk
sha256sum payload.apk
sha256sum user_key_candidate.bin
```

Expected values from my solve:

- `chall.apk`: `e9d9cbe0587a1a7e12853f97a28ca5a59440724615aa67acac798a4d969b05f5`
- `payload.apk`: `d87cc80d2828d828560b53f40f1c5abc5ca2db0626a316703dbae1162c3835a9`
- `user_key_candidate.bin`: `ea8b61a27d03d4554898da99d985d05ca3d255bcddcd7d6b7648377d42479dad`

---

## How To Think About This Challenge

This challenge is a good example of why beginners get stuck when they reverse Android apps:

- they open the first `MainActivity`
- they assume the visible app is the real app
- they focus too early on UI code

The correct mindset is:

1. What runs first?
2. Is the visible code the real code?
3. Is anything being unpacked or dynamically loaded?
4. What file actually contains the flag path?

For this challenge, the shortest honest solve path is:

```text
chall.apk
-> ProxyApplication
-> hidden payload.apk
-> real MainActivity + ImageEncryptor
-> native libnative-lib.so
-> encrypted background.bkp
-> decrypted image
-> handwritten flag text
```

---

## Phase 0 - Quick APK Triage

Goal:

- treat the APK as a container
- list its contents
- identify suspicious entry points

Commands:

```bash
file chall.apk
unzip -l chall.apk | head -n 50
apktool d -f chall.apk -o apktool_out
jadx -d jadx_out chall.apk
```

What to notice:

- an APK is basically a ZIP archive
- the archive contains:
  - `AndroidManifest.xml`
  - `classes.dex`
  - resources
  - libraries
- the visible Java package is `com.example.reforceapk`

At this stage, do not try to solve anything. Just map the surface.

---

## Phase 1 - Prove The Outer APK Is A Loader

### Step 1. Read the visible activity

Command:

```bash
sed -n '1,120p' jadx_out/sources/com/example/reforceapk/MainActivity.java
```

What you see:

```java
public class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
}
```

This is almost empty.

Meaning:

- no login logic
- no crypto
- no flag handling
- no interesting behavior

Important lesson:

- the first `MainActivity` you see is not always the real target

### Step 2. Check the custom Application class

Commands:

```bash
sed -n '1,220p' jadx_out/resources/AndroidManifest.xml
sed -n '1,320p' jadx_out/sources/com/example/reforceapk/ProxyApplication.java
```

This is the real pivot.

`ProxyApplication` runs before activities, and it does the following:

- reads its own `classes.dex`
- extracts hidden bytes from the end of that file
- XOR-decrypts them with `0xff`
- writes a new APK called `payload.apk`
- loads that APK dynamically with `DexClassLoader`

That means the outer APK is only a wrapper.

### The confusing line: `System.arraycopy(apkdata, (ablen - 4) - readInt, newdex, 0, readInt);`

This is the part that usually confuses beginners, so here is the slow explanation.

Variables:

- `apkdata`: the full byte content of `classes.dex`
- `ablen`: total size of `classes.dex`
- `readInt`: payload length, read from the last 4 bytes
- `newdex`: output buffer that will hold the hidden payload

Think of `classes.dex` like this:

```text
[ normal dex bytes ][ hidden payload bytes ][ 4-byte payload length ]
```

So:

- the last 4 bytes store the size of the payload
- if the payload length is `readInt`
- then the payload starts at:

```text
(total_size - 4) - readInt
```

That is exactly what the code does.

Example:

- total size = `1000`
- last 4 bytes = `200`
- payload starts at `1000 - 4 - 200 = 796`

So the copy becomes:

```text
copy 200 bytes starting from byte 796
```

In plain English:

- go to the end
- skip the last 4 bytes
- move backward by the payload length
- copy those bytes out

### Reproduce the extraction manually

Command:

```bash
python3 - <<'PY'
from pathlib import Path
import zipfile

with zipfile.ZipFile('chall.apk') as zf:
    data = zf.read('classes.dex')

L = int.from_bytes(data[-4:], 'big')
enc = data[-4-L:-4]
payload = bytes(b ^ 0xff for b in enc)

Path('payload.apk').write_bytes(payload)

print('classes.dex size =', len(data))
print('payload length =', L)
print('payload start offset =', len(data) - 4 - L)
print('wrote payload.apk')
PY
file payload.apk
```

Expected values:

- `classes.dex size = 1725566`
- `payload length = 1711362`
- `payload start offset = 14200`

Important conclusion of Phase 1:

- `chall.apk` is not the real app
- it is a shell/loader APK
- `payload.apk` is the real reversing target

---

## Phase 2 - Decompile The Real APK

Goal:

- stop working on the shell APK
- inspect the hidden payload APK
- identify the real app logic

Commands:

```bash
file payload.apk
unzip -l payload.apk | head -n 50
jadx -d payload_jadx payload.apk
find payload_jadx/sources -type f | sort
```

Interesting Java files:

- `com/example/myapk/MainActivity.java`
- `com/example/myapk/ImageEncryptor.java`
- `com/example/myapk/MyApplication.java`
- `com/example/myapk/SubActivity.java`

### Read the real MainActivity

Command:

```bash
sed -n '1,320p' payload_jadx/sources/com/example/myapk/MainActivity.java
```

What this activity does:

1. Loads a wallpaper from `background.txt`
2. Lets the user choose an image
3. Takes username and password
4. Runs a weird MD5-based login check
5. Encrypts image data and writes `background.bkp`

### First important confusion: "Is the login the real challenge?"

Not exactly.

The login condition is:

- username must not equal password
- `MD5(username)` must equal `MD5(password)`

Code idea:

```java
if (username.equals(password)) fail;
if (!md5(username).equals(md5(password))) fail;
```

Meaning:

- the app wants two different strings that collide under MD5

That tells you the login is a gate, not the final prize.

The real challenge continues after successful login.

### Extract the wallpaper from `background.txt`

Command:

```bash
python3 - <<'PY'
from pathlib import Path
import base64

txt = Path('payload_jadx/resources/assets/background.txt').read_text().strip()
prefix = 'url(data:image/jpeg;base64,'
if txt.startswith(prefix):
    txt = txt[len(prefix):]
if txt.endswith(')'):
    txt = txt[:-1]

raw = base64.b64decode(txt)
Path('background_from_txt.jpg').write_bytes(raw)
print('wrote background_from_txt.jpg')
PY

file background_from_txt.jpg
```

Important lesson:

- the plain background image is visible and easy to extract
- but it is not the final hidden artifact we care about

### What happens after login?

This is the key line in `performLogin()`:

```java
byte[] encrypted = ImageEncryptor.encryptData(this.originalImageBytes);
```

And then:

```java
File file = new File(getExternalFilesDir(null), "background.bkp");
fos.write(encrypted);
```

Meaning:

- the app encrypts image bytes
- saves the result as `background.bkp`

At this point the real flag path becomes:

```text
image bytes -> ImageEncryptor.encryptData() -> background.bkp
```

Important conclusion of Phase 2:

- `payload.apk` contains the real logic
- the login is a gate based on MD5 collisions
- the real artifact to recover is `background.bkp`

---

## Phase 3 - Understand `ImageEncryptor`

Command:

```bash
sed -n '1,320p' payload_jadx/sources/com/example/myapk/ImageEncryptor.java
```

This class matters because it sits between Java UI logic and native crypto.

### The important native method

```java
private static native byte[] encryptDataNative(byte[] bArr);
```

This means:

- Java is not doing the real encryption itself
- the interesting logic is inside a native library

### The fallback path

If native loading fails, Java does this:

```java
result[i] = (byte) (data[i] ^ (-559038737));
```

`-559038737` is `0xDEADBEEF`, so the low byte is `0xEF`.

That means the fallback path is just:

```text
byte ^ 0xEF
```

This is weak and clearly not the interesting part.

### The confusing helper methods: `c`, `d`, `e`, `f`, and `x`

These are mostly anti-analysis support.

`x(int[])`:

- decodes hidden strings using XOR `0x5A`
- example: the library name decodes to `native-lib`

`d()`:

- checks build tags for `test-keys`

`e()`:

- checks common root paths such as `/system/xbin/su`

`f()`:

- runs `which su`

`c()`:

- combines the above checks

Meaning:

- the app tries to detect rooted/emulated/suspicious environments
- this is anti-analysis noise

Important conclusion of Phase 3:

- `ImageEncryptor.encryptData()` is the crypto entrypoint
- if native loads, the real path is native
- the next real target is `libnative-lib.so`

---

## Phase 4 - Native Library Triage

Goal:

- confirm the native library exists
- identify its exported functions
- avoid blindly reversing everything

Commands:

```bash
find payload_apktool/lib -type f | sort
file payload_apktool/lib/x86/libnative-lib.so
file payload_apktool/lib/x86_64/libnative-lib.so
readelf -Ws payload_apktool/lib/x86/libnative-lib.so | rg 'Java_|generateKeyBuf|getEncryptionKey'
strings -a payload_apktool/lib/x86/libnative-lib.so | head -n 50
```

Key export names:

- `_Z14generateKeyBufv`
- `Java_com_example_myapk_ImageEncryptor_encryptDataNative`
- `Java_com_example_myapk_ImageEncryptor_getEncryptionKey`

Expected `readelf` output fragment:

```text
_Z14generateKeyBufv
Java_com_example_myapk_ImageEncryptor_encryptDataNative
Java_com_example_myapk_ImageEncryptor_getEncryptionKey
```

Important thought process:

- `encryptDataNative` is the exact function Java calls
- `getEncryptionKey` strongly suggests there is a generated key path
- `generateKeyBuf` is probably the core helper used by both

Important conclusion of Phase 4:

- the problem is now a native crypto/keygen problem, not a Java problem

---

## Phase 5 - Reduce The Native Code To A Simple Model

This is the phase where many people get lost because native code looks noisy.

Correct mindset:

- do not try to understand every single instruction immediately
- follow the data
- reduce the code into a simple model

### What the native code is doing conceptually

After working through `encryptDataNative` and `generateKeyBuf`, the useful simplified model is:

1. generate a 32-byte key buffer
2. XOR the image bytes with that key in repeating fashion

So the effective cipher is:

```text
cipher[i] = plain[i] ^ key[i % 32]
```

This is the single most important simplification in the whole solve.

### What `generateKeyBuf` conceptually does

The full decompilation is messy, but the core behavior is:

- builds a byte array from hardcoded constants
- sorts those bytes
- mixes them with SHA1 output
- mixes in bytes from an LCG-like generator
- returns a 32-byte result

For this challenge, the exact high-level model was enough to move forward.

Important conclusion of Phase 5:

- the native encryption is not general-purpose AES or anything huge
- it is a custom 32-byte repeating XOR keystream

---

## Phase 6 - Focus On The Real Embedded Artifact

The important embedded files are:

- `background.txt`
- `background.bkp`

At this point:

- `background.txt` is just the visible wallpaper
- `background.bkp` is the encrypted artifact worth attacking

Check it:

```bash
file apktool_out/assets/background.bkp
```

You can also do a quick periodicity check:

```bash
python3 - <<'PY'
from pathlib import Path
from collections import Counter

data = Path('apktool_out/assets/background.bkp').read_bytes()
print('size =', len(data))

cnt = Counter(data)
n = len(data)
ic = sum(v*(v-1) for v in cnt.values()) / (n*(n-1))
print('IC =', ic)

for lag in [1,2,4,8,16,32,64]:
    same = sum(data[i] == data[i+lag] for i in range(len(data)-lag))
    print(f'lag {lag}: {same/(len(data)-lag):.6f}')
PY
```

Why this matters:

- repeating-key XOR often leaks periodic structure
- if lag `32` is noticeably stronger than nearby lags, that supports the 32-byte model

Important conclusion of Phase 6:

- `background.bkp` is consistent with the native key model
- it is the file that must be decrypted

---

## Phase 7 - Recover And Validate A Working Key

At this point, the question becomes:

- what 32-byte key turns `background.bkp` back into a real file?

The working key from this solve was:

```text
e7c35ac886acdbfe24cf7b7a68883cae27b5d67f2033f785f7b7349a29f32f9a
```

### Decrypt the blob

Command:

```bash
python3 - <<'PY'
from pathlib import Path

key = bytes.fromhex('e7c35ac886acdbfe24cf7b7a68883cae27b5d67f2033f785f7b7349a29f32f9a')
data = Path('apktool_out/assets/background.bkp').read_bytes()
out = bytes(b ^ key[i % 32] for i, b in enumerate(data))

Path('user_key_candidate.bin').write_bytes(out)

print('first 32 bytes =', out[:32].hex())
print('wrote user_key_candidate.bin')
PY

file user_key_candidate.bin
exiftool user_key_candidate.bin
```

Expected first 32 bytes:

```text
ffd8ffe10ffe4578696600004d4d002a00000008000601120003000000010001
```

Expected result:

- `file` recognizes it as a valid JPEG
- `exiftool` shows sane JPEG/Exif metadata

This validation is critical.

Do not say "the key looks right" until the decrypted output becomes a real structured object.

Important conclusion of Phase 7:

- the decryption works
- the hidden artifact is a real JPEG image
- the solve path is correct

---

## Phase 8 - Read The Hidden Message

Open the recovered image:

```bash
python3 - <<'PY'
from PIL import Image
img = Image.open('user_key_candidate.bin')
print(img.size)
img.save('decrypted_background.jpg')
print('wrote decrypted_background.jpg')
PY
```

Then inspect it visually.

What appears:

- the cyberpunk wallpaper
- red handwritten text over the image

The visible text reads approximately:

```text
hack
10{
t3r_p2_
x0r
3
```

The final image contains the flag text, but note one complication:

- there is a black horizontal band covering part of the handwriting

So the solve reached the hidden image cleanly, but the last step still required visual reading of partially obscured handwriting.

Best-effort reconstructed flag format from the recovered image:

```text
hack10{t3r_p2_x0r_3}
```

If you want to be maximally strict in a formal writeup, phrase it like this:

- the recovered decrypted image contains the handwritten flag text
- the visible characters strongly indicate `hack10{t3r_p2_x0r_3}`

---

## Optional Dynamic Validation With `gdb` / `pwndbg`

This solve did not require full runtime instrumentation, but if you want to practice the native mindset, this is the kind of dynamic work you would do.

### Native triage

```bash
gdb -q payload_apktool/lib/x86/libnative-lib.so
```

Inside `gdb` / `pwndbg`:

```gdb
set disassembly-flavor intel
info functions generateKeyBuf
info functions Java_com_example_myapk_ImageEncryptor_encryptDataNative
info functions Java_com_example_myapk_ImageEncryptor_getEncryptionKey
disassemble _Z14generateKeyBufv
disassemble Java_com_example_myapk_ImageEncryptor_encryptDataNative
disassemble Java_com_example_myapk_ImageEncryptor_getEncryptionKey
quit
```

### If you use a local harness later

If you write a tiny harness to call the native functions, typical `pwndbg` flow would be:

```gdb
start
break _Z14generateKeyBufv
break Java_com_example_myapk_ImageEncryptor_encryptDataNative
continue
context
bt
ni
si
x/32bx $eax
x/64bx $esp
finish
```

Good habits during dynamic work:

- break on the exact exported JNI functions
- inspect input and output buffers
- do not step randomly through library startup noise
- verify whether the generated key is 32 bytes and how it is consumed

For this challenge, static reduction plus artifact validation was enough, but dynamic validation would be a good training exercise.

---

## Common Beginner Confusions And The Correct Answers

### "Why not reverse the first MainActivity?"

Because it was empty. A reverser must notice when a class is too trivial to be the real challenge.

### "Why should I care about Application?"

Because custom `Application` classes run before activities and are a common place for packers/loaders.

### "Why is `payload.apk` important?"

Because the shell APK extracts it from the end of `classes.dex` and loads it dynamically. That means the real logic lives there.

### "I still do not get the payload extraction line"

Use this mental picture:

```text
[ dex ][ hidden payload ][ 4-byte payload size ]
```

The code reads the size from the last 4 bytes, then copies exactly that many bytes from just before the end.

### "Is the MD5 login the flag?"

No. It is a gate that tells you the app wants an MD5 collision-style input pair. The real artifact recovery happens afterward.

### "Why not just use the Java fallback XOR path?"

Because the intended path is the native one. The fallback is weak and mainly there as a backup if native loading fails.

### "How do I know `background.bkp` matters?"

Because the real `MainActivity` writes encrypted image data to that exact file after successful login.

### "How do I know the key is right?"

Because decrypting `background.bkp` with it yields a valid JPEG recognized by `file` and `exiftool`.

---

## Minimal Solve Script

If you already know the key, the shortest solve is:

```bash
python3 - <<'PY'
from pathlib import Path

key = bytes.fromhex('e7c35ac886acdbfe24cf7b7a68883cae27b5d67f2033f785f7b7349a29f32f9a')
data = Path('apktool_out/assets/background.bkp').read_bytes()
out = bytes(b ^ key[i % 32] for i, b in enumerate(data))
Path('flag.jpg').write_bytes(out)
print('wrote flag.jpg')
PY
```

Then open `flag.jpg` and read the handwritten flag text.

---

## What This Challenge Teaches

This challenge is good practice for:

- not trusting the visible app
- checking custom `Application` classes early
- understanding APK staging/loaders
- following data flow instead of UI flow
- reducing complex native code into a simple model
- validating hypotheses with actual output files

The most important mindset shift is:

- do not reverse "whatever file looks important"
- reverse the exact path that transforms the flag-bearing data

For this challenge, that path was:

```text
ProxyApplication
-> hidden payload.apk
-> MainActivity.performLogin()
-> ImageEncryptor.encryptData()
-> libnative-lib.so
-> background.bkp
-> decrypted JPEG
```

Once you learn to build that path, the challenge becomes much smaller and much clearer.
                                                                                          
