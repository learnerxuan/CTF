---
ctf: ScarletCTF 2026
category: game-hacking
difficulty: medium
points: 150
flag: RUSEC{sp4cetime_flagt1me_w3lcome_t0_th3_g4me_th1s_1s_0nly_th3_b3g1nn1ng_fr1end}
techniques:
  - il2cpp-reverse-engineering
  - unity-game-hacking
  - aes-decryption
tools:
  - il2cppdumper
  - ghidra
  - python
---

# Peculiar Code (Level1)

## Description

We have a Unity IL2CPP game called "SpaceTime" that communicates with a server at `https://melstudios.ctf.rusec.club`. The `/flagtime` endpoint returns encrypted data with an IV and ciphertext. The goal is to reverse engineer the game to find the AES decryption key.

## Solution

### 1. Extract Game Files

The game is a Unity IL2CPP build. Key files:
- `GameAssembly.dll` - Native compiled game code
- `global-metadata.dat` - IL2CPP metadata

### 2. Use Il2CppDumper

Extract class definitions from the IL2CPP binary:

```bash
Il2CppDumper.exe GameAssembly.dll global-metadata.dat output/
```

This reveals a `RUSEC` class with:
- `EncryptedData` inner class with `iv` and `ct` fields
- A closure class `<>c__DisplayClass2_0` with a `byte[] key` field

### 3. Get Encrypted Data

```bash
curl https://melstudios.ctf.rusec.club/flagtime
```

Returns:
```json
{
  "iv": "...",
  "ct": "..."
}
```

### 4. Reverse Engineer Key Generation

Using Ghidra to decompile `RUSEC.Start()` at VA `0x1803E3800`:

1. **Get Unity Application names:**
   - `Application.get_companyName()` → "RUSEC CTF"
   - `Application.get_productName()` → "SpaceTime"

2. **Concatenate with separator:**
   - A string concatenation function combines: `companyName + separator + productName`
   - The separator is a newline character (`\n`)

3. **Derive key:**
   - The concatenated string is hashed with SHA256
   - Result: `SHA256("RUSEC CTF\nSpaceTime")` = 32 bytes (AES-256 key)

### 5. Decrypt

```python
from Crypto.Cipher import AES
import hashlib
import base64

# Derive key
plaintext = "RUSEC CTF\nSpaceTime"
key = hashlib.sha256(plaintext.encode()).digest()

# Decrypt
iv = base64.b64decode("...")
ct = base64.b64decode("...")

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct).decode()
print(flag)
```

## Key Insight

The "peculiar code" derives the AES key from Unity's `Application.companyName` and `Application.productName` settings, concatenated with a newline and hashed with SHA256. These values are set in the Unity project settings and stored in `globalgamemanagers`.

