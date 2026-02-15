---
ctf: ScarletCTF 2026
category: game-hacking
difficulty: medium
points: 250
flag: RUSEC{trust_me_br0_im_t0tally_admin_y0ur_s3cret_is_s4fe_with_m3}
techniques:
  - cfb-mac-attack
  - keystream-recovery
  - authentication-bypass
tools:
  - python
  - pycryptodome
---

# Mac n' Cheese (Level3)

## Description

A wittle birdy once told meh that Amels was really really scared about something regarding authentication :O

She responded saying that there's a critical flaw in authentication that could be VERYY bad!!! It was something about the vulnerabilites of "CBC-MAC" and how she wanted to try "another mode"? Something with "feedback" in the name.

I also saw on stream that she was playing with an account called `amels_gamedev_123X`, the X is a number that i couldn't quite catch (so u might need to bruteforce for it) :c

## Solution

This challenge involves exploiting a vulnerability in a **CFB-MAC** (Cipher Feedback Mode MAC) authentication system.

### 1. Discovering the API

The MelStudios API endpoints:
- `/login` - Create/authenticate users
- `/stats` - View user stats (requires auth)
- `/purchased_flag` - Get purchased flags (requires auth)

Authentication uses a cookie: `token="base64(username).hex_mac"`

### 2. Understanding the MAC Scheme

By creating test accounts and analyzing their MACs:

- For usernames ≤15 bytes: `MAC = username || PKCS7_padding XOR keystream_1`
- The keystream for block 1 is constant: `4da6ace75d6b24a8f6f2735d369d6a87`

### 3. The Critical Vulnerability

All **16-byte usernames** produce the **same MAC** (`33a5f6142561e2605fd834d1fa5b00cb`), regardless of content. This means `keystream_2` is constant and independent of the first block's content.

This is a severe implementation flaw - in proper CFB mode, `keystream_2 = E_K(C_1)` where `C_1` depends on block 1.

Extracting `keystream_2`:
```python
# Any 16-byte username has MAC = keystream_2
keystream_2 = bytes.fromhex("33a5f6142561e2605fd834d1fa5b00cb")
```

### 4. Forging Authentication Tokens

For target `amels_gamedev_123X` (18 bytes):
- Block 1: `amels_gamedev_12` (16 bytes)
- Block 2: `3X\x0e*14` (PKCS7 padded)

The MAC only depends on block 2:

```python
def forge_mac(digit):
    block2 = f"3{digit}".encode() + b'\x0e' * 14
    mac = bytes(b ^ k for b, k in zip(block2, keystream_2))
    return mac.hex()

# Try all digits 0-9
for x in range(10):
    username = f"amels_gamedev_123{x}"
    mac = forge_mac(x)
    # Test token
```

### 5. Getting the Flag

Testing revealed `amels_gamedev_1233` had purchased flags:

```bash
curl -b "token=YW1lbHNfZ2FtZWRldl8xMjMz.{forged_mac}" \
     https://melstudios.ctf.rusec.club/purchased_flag
```

## Key Takeaways

- CFB-MAC is fundamentally broken when keystream blocks don't depend on previous ciphertext
- Constant keystreams allow trivial MAC forgery
- Always use authenticated encryption (GCM, ChaCha20-Poly1305) instead of custom MAC constructions

