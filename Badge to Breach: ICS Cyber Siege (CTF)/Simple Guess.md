# Simple Guess - CTF Writeup

## Challenge Overview
**Category:** Mobile Reverse Engineering, Cryptography  

**Description:**
> Let's see how cool you are on pulling things ("Get Over Here!!!!")

The challenge presents a simple Android application with a single input field asking for a "code". The goal is to reverse engineer the APK to find the correct code that unlocks the flag.

## Static Analysis

### Application Structure

By opening the APK using jadx-gui, the decompiled APK reveals the standard Android application structure:
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

### Exploit Implementation (Script from Claude AI)

```python
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import binascii

# Extract values from the Android resources
salt_b64 = "S7n8CyjFt28W6JOssy1OPg=="
iv_b64 = "KF/M4Oz7SyDQOY5PWF76yw=="
encrypted_b64 = "M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW"

# Decode base64 values
salt = base64.b64decode(salt_b64)
iv = base64.b64decode(iv_b64)
encrypted_data = base64.b64decode(encrypted_b64)

print(f"Salt: {binascii.hexlify(salt).decode()}")
print(f"IV: {binascii.hexlify(iv).decode()}")
print(f"Encrypted data: {binascii.hexlify(encrypted_data).decode()}")
print()

def try_decrypt(pin):
    """Try to decrypt with a given 4-digit PIN"""
    try:
        # Generate key using PBKDF2 (matching Android's PBKDF2WithHmacSHA256)
        # Parameters: iterations=65536, key_length=256 bits (32 bytes)
        key = PBKDF2(pin, salt, dkLen=32, count=65536, hmac_hash_module=SHA256)
        
        # Create cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove PKCS5 padding
        pad_len = decrypted[-1]
        if pad_len <= 16:  # Valid padding length for AES
            decrypted = decrypted[:-pad_len]
            
            # Try to decode as UTF-8
            result = decrypted.decode('utf-8')
            return result
    except:
        return None

# Brute force all 4-digit combinations
print("Starting brute force attack...")
print("This may take a few minutes...")
print()

found = False
for i in range(10000):
    pin = f"{i:04d}"  # Format as 4-digit string with leading zeros
    
    if i % 1000 == 0:
        print(f"Trying PIN: {pin}...")
    
    result = try_decrypt(pin)
    if result and result.isprintable():
        print(f"\n🎉 SUCCESS! 🎉")
        print(f"PIN: {pin}")
        print(f"Decrypted message: {result}")
        found = True
        break

if not found:
    print("No valid PIN found in range 0000-9999")
    print("The encrypted data might require a different approach.")
```

### Execution Results

Running the brute force script:
![Screenshot 2025-06-28 003433](https://github.com/user-attachments/assets/31a614b8-85e2-43e2-97e8-75ad82cd5427)
