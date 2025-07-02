CTF Writeup: Mobile Challenge - Simple Guess
Challenge Points: 452
Category: Mobile Reverse Engineering, Cryptography
Tools Used: adb, apktool, Python 3, pycryptodome library

1. Challenge Description
The challenge presented a simple Android application titled "Simple Guess" with a single input field. The prompt hinted: "Let's see how cool you are on pulling things ("Get Over Here!!!!")". The goal was to find a specific "code" to insert, presumably to unlock a hidden flag or message.

Initial app interface with an "Enter Code" field.

2. Initial Reconnaissance & APK Acquisition
First, I needed to get the APK file from the running Android emulator.

List Devices:

adb devices

Output confirmed emulator-5554 was connected.

Find Package Name: From prior analysis of the provided Java code, the package name was com.example.simpleguess. I confirmed this on the device:

adb shell pm list packages | grep simpleguess
# On PowerShell, this would be:
# adb shell pm list packages | Select-String simpleguess

Output: package:com.example.simpleguess

Get APK Path:

adb shell pm path com.example.simpleguess

Example Output: /data/app/~~_6cNRH5twMPrEj7MI4TgDA==/com.example.simpleguess-E8sQBagfGDDll02ngaw43Q==/base.apk
(The ~~_... and -... parts are unique to each installation).

Pull APK:

adb pull /data/app/~~_6cNRH5twMPrEj7MI4TgDA==/com.example.simpleguess-E8sQBagfGDDll02ngaw43Q==/base.apk base.apk

This successfully pulled base.apk to my current working directory.

3. Decompilation and Code Analysis
With the base.apk file in hand, the next step was to decompile it to inspect the application's logic and resources.

Decompile with apktool:

apktool d base.apk -o decompiled_simpleguess

This created a directory decompiled_simpleguess containing the app's resources and Smali code (which can be converted to Java/Kotlin for easier reading).

Locate Key Files: Based on the challenge name "Simple Guess" and common Android development patterns, I suspected the core logic would be in MainActivity. I navigated to decompiled_simpleguess/smali_classes2/com/example/simpleguess/ and found MainActivity.smali.

Analyze MainActivity.kt (Original Source Provided):
Reviewing the provided MainActivity.kt (which represents the decompiled logic), I identified the following critical functions:

cutf(Context co, String c): This function takes user input c, extracts only the digits, and then takes the first 4 digits. This is a crucial observation, as it immediately limits our potential password space to 4-digit numbers (0000-9999). It then passes this 4-digit string to decp.

decp(Context cot, String p): This is the decryption function.

It retrieves salt, iv (named f183iv in code, iv in strings.xml), and ecp (encrypted content) from the app's strings.xml resources. These are Base64 encoded.

It uses p (our 4-digit input) as the password for key derivation.

Key Derivation: The gk function, called via gk$default, uses SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"). The default parameters, derived from gk$default(..., 12, ...), are 65536 iterations and 256 bits (32 bytes) for the key size.

Decryption Algorithm: Cipher.getInstance("AES/CBC/PKCS5Padding").

Success Check: The decrypted data is logged, and the function ultimately returns "Thank You" if decryption is successful.

Extract Cryptographic Secrets from strings.xml:
The cryptographic parameters were hardcoded in decompiled_simpleguess/res/values/strings.xml.

<?xml version="1.0" encoding="utf-8"?>
<resources>
    <!-- ... other strings ... -->
    <string name="ecp">M4EKATajtPe4ry4Vs3W0SQNNoIdSZnDdtdAArgeVZRX1WVod+/IOHiQ8uz3XeAJW</string>
    <!-- ... other strings ... -->
    <string name="iv">KF/M4Oz7SyDQOY5PWF76yw==</string>
    <!-- ... other strings ... -->
    <string name="salt">S7n8CyjFt28W6JOssy1OPg==</string>
    <!-- ... other strings ... -->
</resources>

4. Vulnerability and Exploitation Strategy
Vulnerability:

Hardcoded Secrets: The salt, IV, and ecp (ciphertext) are stored directly within the APK's strings.xml file. This means anyone can easily extract them through reverse engineering. In a real-world scenario, sensitive data and cryptographic parameters should never be hardcoded in client-side applications.

Small Keyspace: The "password" (the 4-digit input) is restricted to 10,000 possible combinations (0000-9999). Even with a strong Key Derivation Function (KDF) like PBKDF2, this small keyspace makes the system vulnerable to brute-force attacks. A standard computer can iterate through this many possibilities in a matter of seconds or minutes.

Exploitation Strategy:

The strategy is a straightforward offline brute-force attack:

Extract all necessary cryptographic parameters (salt, IV, ecp, PBKDF2 iterations, key size, algorithm).

Write a script that attempts to derive an AES key for each of the 10,000 possible 4-digit passwords.

For each derived key, attempt to decrypt the ecp.

Check if the decrypted plaintext contains the expected success string ("Thank You"). The first password that yields "Thank You" is our solution.

5. Brute-Force Script
I used Python with the pycryptodome library to implement the brute-force attack.

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

print(f"Salt (hex): {binascii.hexlify(salt).decode()}")
print(f"IV (hex): {binascii.hexlify(iv).decode()}")
print(f"Encrypted data (hex): {binascii.hexlify(encrypted_data).decode()}")
print()

def try_decrypt(pin_str):
    """
    Attempts to decrypt the data using the given 4-digit PIN string.
    Returns the decrypted string if successful and valid, otherwise None.
    """
    try:
        # Key derivation: PBKDF2WithHmacSHA256, iterations=65536, key_length=256 bits (32 bytes)
        # The 'pin_str' is directly used as the password for PBKDF2.
        key = PBKDF2(pin_str.encode('utf-8'), salt, dkLen=32, count=65536, hmac_hash_module=SHA256)
        
        # Create cipher (AES/CBC/PKCS5Padding)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        
        # Decrypt ciphertext
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove PKCS5 padding
        pad_len = decrypted_padded[-1]
        if 1 <= pad_len <= AES.block_size and decrypted_padded.endswith(bytes([pad_len]) * pad_len):
            decrypted_unpadded = decrypted_padded[:-pad_len]
            
            # Try to decode as UTF-8
            try:
                result = decrypted_unpadded.decode('utf-8')
                return result
            except UnicodeDecodeError:
                # Not valid UTF-8, likely incorrect key
                return None
        else:
            # Invalid padding, likely incorrect key
            return None
    except ValueError:
        # Common error for incorrect key/IV size during cipher initialization, etc.
        return None
    except Exception as e:
        # Catch any other unexpected errors during decryption
        # print(f"Error during decryption for PIN {pin_str}: {e}")
        return None

# Brute force all 4-digit combinations
print("Starting brute force attack (0000-9999)...")
print("This may take a few moments...")
print()

found_pin = None
decrypted_message = None
for i in range(10000):
    pin = f"{i:04d}"  # Format as 4-digit string with leading zeros
    
    if i % 1000 == 0:
        print(f"Trying PIN range: {pin} - {min(i + 999, 9999):04d}...")
    
    result = try_decrypt(pin)
    if result and "Thank You" in result: # Check for the specific success string
        found_pin = pin
        decrypted_message = result
        break

if found_pin:
    print(f"\n🎉 SUCCESS! 🎉")
    print(f"Found PIN: {found_pin}")
    print(f"Decrypted message: {decrypted_message}")
    print("\nSubmit this PIN to the app to get the flag!")
else:
    print("No valid PIN found in range 0000-9999")
    print("The encrypted data might require a different approach or parameters.")

6. Solution and Flag
Running the Python script successfully found the correct 4-digit PIN.

[Insert the actual PIN you found here, e.g., if it was 1234]

The script output provided the precise PIN, which when entered into the Android application's "Enter Code" field, should trigger the "Thank You" message and reveal the flag.

Flag (Example Placeholder - Replace with your actual flag from the app): CTF{Success_You_Guessed_It_Right_Easy_Peasy}
7. Lessons Learned
Never Hardcode Secrets: Cryptographic keys, salts, IVs, or encrypted data should never be hardcoded directly into a client-side application. Attackers can easily extract them through reverse engineering.

Strong KDFs Don't Mitigate Small Keyspaces: While PBKDF2 is a good choice for key derivation, its strength against brute-force attacks is significantly diminished when the underlying password's keyspace is small and predictable. A 4-digit PIN is insufficient for security, even with many iterations.

Importance of APK Reverse Engineering: This challenge highlights how decompilation and static analysis of an APK are fundamental skills in mobile penetration testing and CTFs to uncover hidden logic and secrets.

This challenge was a great
