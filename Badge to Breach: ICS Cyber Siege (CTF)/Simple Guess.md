# Simple Guess - CTF Writeup

## Challenge Overview
**Challenge Name:** Simple Guess  
**Category:** Mobile Reverse Engineering, Cryptography  

**Description:**
> Let's see how cool you are on pulling things ("Get Over Here!!!!")

The challenge presents a simple Android application with a single input field asking for a "code". The goal is to reverse engineer the APK to find the correct code that unlocks the flag.

## Initial Analysis

### APK Acquisition and Setup

First, we need to extract the APK from the Android emulator and prepare it for analysis.

**List connected devices:**
```bash
$ adb devices
List of devices attached
emulator-5554   device
```

**Find the package name:**
```bash
$ adb shell pm list packages | grep simpleguess
package:com.example.simpleguess
```

**Get APK path and extract:**
```bash
$ adb shell pm path com.example.simpleguess
package:/data/app/~~_6cNRH5twMPrEj7MI4TgDA==/com.example.simpleguess-E8sQBagfGDDll02ngaw43Q==/base.apk

$ adb pull /data/app/~~_6cNRH5twMPrEj7MI4TgDA==/com.example.simpleguess-E8sQBagfGDDll02ngaw43Q==/base.apk base.apk
```

### Decompilation

**Decompile using apktool:**
```bash
$ apktool d base.apk -o decompiled_simpleguess
```

This extracts the application resources and converts the DEX bytecode to Smali assembly language for analysis.

## Static Analysis

### Application Structure

The decompiled APK reveals the standard Android application structure:
- `AndroidManifest.xml` - Application configuration
- `res/values/strings.xml` - String resources
- `smali_classes2/com/example/simpleguess/MainActivity.smali` - Main application logic

### Code Analysis

#### MainActivity Logic Flow

Analyzing the MainActivity reveals three critical functions:

**1. Input Processing Function (`cutf`)**
```kotlin
// Simplified logic from MainActivity.kt
fun cutf(co: Context, c: String): String {
    // Extract only digits from input
    val digits = c.filter { it.isDigit() }
    // Take first 4 digits
    return digits.take(4)
}
```

**Key Observations:**
- Only accepts digit characters
- Truncates input to exactly 4 digits
- This immediately limits our search space to 0000-9999 (10,000 possibilities)

**2. Decryption Function (`decp`)**
```kotlin
// Simplified decryption logic
fun decp(cot: Context, p: String): String {
    // Retrieve cryptographic parameters from resources
    val salt = getString(R.string.salt)      // Base64 encoded
    val iv = getString(R.string.iv)          // Base64 encoded  
    val ecp = getString(R.string.ecp)        // Base64 encoded ciphertext
    
    // Use 4-digit PIN as password for key derivation
    val key = deriveKey(p, salt)
    
    // Decrypt using AES/CBC/PKCS5Padding
    val decrypted = decryptAES(ecp, key, iv)
    
    return if (decrypted.contains("Thank You")) "Thank You" else "Failed"
}
```

**3. Key Derivation Function (`gk`)**
```kotlin
// PBKDF2 key derivation
fun gk(password: String, salt: ByteArray): ByteArray {
    return PBKDF2WithHmacSHA256(
        password = password,
        salt = salt,
        iterations = 65536,
        keyLength = 256  // 32 bytes
    )
}
```

### Cryptographic Parameters Extraction

Examining `res/values/strings.xml` reveals hardcoded cryptographic secrets:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="salt">S7n8CyjFt28W6JOssy1OPg==</string>
    <string name="iv">KF/M4Oz7SyDQOY5PWF76yw==</string>
    <string name="ecp">M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW</string>
</resources>
```

## Vulnerability Analysis

### Critical Security Flaws

**1. Hardcoded Cryptographic Secrets**
- Salt, IV, and encrypted data stored in plaintext within the APK
- Any attacker can extract these values through basic reverse engineering
- Violates fundamental security principle: never trust the client

**2. Weak Password Space**
- Password limited to 4-digit numbers (0000-9999)
- Only 10,000 possible combinations
- Even with strong KDF (PBKDF2), small keyspace enables brute force attacks

**3. Client-Side Security Logic**
- All cryptographic operations performed on the client
- Success condition ("Thank You") embedded in client code
- No server-side verification or rate limiting

### Cryptographic Implementation Details

**Algorithm Stack:**
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 65,536
- **Key Length:** 256 bits (32 bytes)
- **Encryption:** AES-256-CBC
- **Padding:** PKCS5

While the cryptographic primitives are sound, the implementation is fatally flawed due to the weak password space and client-side secrets.

## Exploitation

### Attack Strategy

The vulnerability allows for a straightforward offline brute force attack:

1. Extract cryptographic parameters from APK resources
2. Iterate through all 10,000 possible 4-digit combinations
3. For each PIN, derive AES key using PBKDF2
4. Attempt decryption of the ciphertext
5. Check if decrypted plaintext contains "Thank You"

### Exploit Implementation

```python
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import binascii

# Cryptographic parameters extracted from strings.xml
salt_b64 = "S7n8CyjFt28W6JOssy1OPg=="
iv_b64 = "KF/M4Oz7SyDQOY5PWF76yw=="
encrypted_b64 = "M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW"

# Decode Base64 values
salt = base64.b64decode(salt_b64)
iv = base64.b64decode(iv_b64)
encrypted_data = base64.b64decode(encrypted_b64)

print(f"Salt (hex): {binascii.hexlify(salt).decode()}")
print(f"IV (hex): {binascii.hexlify(iv).decode()}")
print(f"Encrypted data (hex): {binascii.hexlify(encrypted_data).decode()}")

def try_decrypt(pin_str):
    """
    Attempt decryption with given 4-digit PIN
    Returns decrypted string if successful, None otherwise
    """
    try:
        # PBKDF2 key derivation matching Android implementation
        key = PBKDF2(
            pin_str.encode('utf-8'), 
            salt, 
            dkLen=32,           # 256 bits
            count=65536,        # iterations
            hmac_hash_module=SHA256
        )
        
        # AES-CBC decryption
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove PKCS5 padding
        pad_len = decrypted_padded[-1]
        if 1 <= pad_len <= AES.block_size:
            if decrypted_padded.endswith(bytes([pad_len]) * pad_len):
                decrypted_unpadded = decrypted_padded[:-pad_len]
                
                try:
                    result = decrypted_unpadded.decode('utf-8')
                    return result
                except UnicodeDecodeError:
                    return None
        
        return None
        
    except Exception:
        return None

# Brute force attack
print("\nStarting brute force attack (0000-9999)...")

found_pin = None
decrypted_message = None

for i in range(10000):
    pin = f"{i:04d}"  # Format as 4-digit string with leading zeros
    
    if i % 1000 == 0:
        print(f"Trying PIN range: {pin} - {min(i + 999, 9999):04d}...")
    
    result = try_decrypt(pin)
    if result and "Thank You" in result:
        found_pin = pin
        decrypted_message = result
        break

if found_pin:
    print(f"\n🎉 SUCCESS! 🎉")
    print(f"Found PIN: {found_pin}")
    print(f"Decrypted message: {decrypted_message}")
else:
    print("No valid PIN found in range 0000-9999")
```

### Execution Results

Running the brute force script:

```bash
$ python3 exploit.py
Salt (hex): 4bb9fc0b28c5b76f16e893acb32d4e3e
IV (hex): 285fcce0ecfb4b20d0398e4f585efacb
Encrypted data (hex): 33810a0136a3b4f7b8af2e15b375b449034da08752667...

Starting brute force attack (0000-9999)...
Trying PIN range: 0000 - 0999...
Trying PIN range: 1000 - 1999...
Trying PIN range: 2000 - 2999...
...

🎉 SUCCESS! 🎉
Found PIN: [REDACTED]
Decrypted message: Thank You [FLAG_CONTENT]
```

The script successfully identifies the correct 4-digit PIN through exhaustive search.

## Security Implications

### Why This Attack Works

**1. Information Disclosure**
- All cryptographic secrets exposed in client-side resources
- No obfuscation or protection of sensitive data
- Reverse engineering tools make extraction trivial

**2. Weak Authentication**
- 4-digit PIN provides insufficient entropy
- ~13.3 bits of security (log₂(10000))
- Modern hardware can exhaust this space in seconds

**3. No Rate Limiting**
- Offline attack eliminates server-side protections
- No attempt throttling or account lockouts
- Attacker can try unlimited combinations

### Proper Security Measures

**Client-Side Applications Should:**
- Never store sensitive cryptographic material
- Use secure enclaves or hardware security modules
- Implement certificate pinning for server communication
- Employ code obfuscation and anti-tampering measures

**Authentication Should Include:**
- Longer, complex passwords or passphrases
- Multi-factor authentication
- Server-side validation and rate limiting
- Secure session management

## Conclusion

The "Simple Guess" challenge demonstrates critical vulnerabilities common in mobile applications:

1. **Hardcoded secrets** enable trivial extraction of cryptographic parameters
2. **Weak password policies** make brute force attacks feasible
3. **Client-side security logic** can be easily bypassed through reverse engineering

The successful exploitation involved:
- APK decompilation and static analysis
- Extraction of hardcoded cryptographic secrets
- Implementation of offline brute force attack
- Exhaustive search of 4-digit PIN space

This challenge highlights the importance of proper secure coding practices in mobile development and the risks of implementing security controls purely on the client side.

### Key Takeaways

- Never embed secrets in client-side applications
- Use sufficiently complex authentication mechanisms
- Implement server-side validation and rate limiting  
- Apply defense-in-depth security principles
- Regular security audits can identify such vulnerabilities

**Flag obtained through successful brute force attack against weak authentication mechanism.**
