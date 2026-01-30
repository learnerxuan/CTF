# HTTPS is the Most Secure Browsing - Writeup

## Challenge Information
- **Category:** Crypto

- **Description:** We finally updated our web server to the last version of Debian! Now they say we need to use HTTPS as the new standard... I'm pretty sure it is not that secure... Are you able to retrieve the secret information in this capture?

- **Flag format:** HACKDAY{flag}

- **SHA1:** fced195b8f3a3530f861c0aaf4eed7430c7dbb2b

## Solution Overview

This challenge involves breaking weak RSA encryption used in HTTPS/TLS. The vulnerability lies in an extremely weak RSA public exponent (e=35) combined with a factorable modulus.

## Step 1: Initial Reconnaissance

First, verify the PCAP file and examine its contents:

```bash
# Verify SHA1 hash
sha1sum capture.pcap
# Output: fced195b8f3a3530f861c0aaf4eed7430c7dbb2b  capture.pcap

# Check PCAP statistics
tshark -r capture.pcap -q -z conv,tcp
```

We can see HTTPS traffic between `172.18.0.3:33898` and `172.18.0.2:443`.

## Step 2: Extract the TLS Certificate

Extract the server certificate from the TLS handshake:

```bash
# Extract certificate in hex format
tshark -r capture.pcap -Y "ssl.handshake.certificate" -T fields -e ssl.handshake.certificate | xxd -r -p > cert.der

# View certificate details
openssl x509 -in cert.der -inform DER -text -noout
```

**Key Discovery:** The certificate uses an **extremely weak RSA public exponent of 35** instead of the standard 65537!

```
Public-Key: (2048 bit)
Modulus:
    00:b1:34:3a:f0:2f:44:eb:6f:0b:66:82:09:6f:2c:
    d6:9e:87:ab:aa:fb:f9:3e:98:b7:23:89:d2:14:18:
    ...
Exponent: 35 (0x23)  ← VULNERABLE!
```

## Step 3: Extract the Encrypted Pre-Master Secret

The encrypted pre-master secret is sent during the Client Key Exchange message:

```bash
# Find the Client Key Exchange packet
tshark -r capture.pcap -Y "ssl.handshake.type == 16" -V | grep -A 5 "Encrypted PreMaster"
```

Extract the encrypted data:

```bash
# Extract TCP payload from frame 13 (Client Key Exchange)
tshark -r capture.pcap -Y "frame.number == 13" -T fields -e tcp.payload | xxd -r -p > frame13.bin

# Extract the encrypted pre-master secret (skip TLS headers)
dd if=frame13.bin bs=1 skip=11 count=256 2>/dev/null | xxd -p | tr -d '\n' > encrypted_premaster.hex
```

The encrypted pre-master secret starts with: `7bbd4152ba4e3bfb59d78a4d...`

## Step 4: Extract Public Key

Extract the public key for analysis:

```bash
openssl x509 -in cert.der -inform DER -pubkey -noout > pubkey.pem
```

## Step 5: Attack the Weak RSA Key

### Understanding the Vulnerability

The RSA public exponent e=35 is extremely weak. Combined with potentially factorable modulus, this makes the encryption breakable. We'll use RsaCtfTool, which automates multiple RSA attacks including:

- Small exponent attacks
- FactorDB lookups (online database of factored numbers)
- Fermat factorization
- Pollard's p-1
- Wiener's attack
- And many more...

### Install RsaCtfTool

```bash
cd ~
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool
pip3 install -r requirements.txt --break-system-packages
```

### Run the Attack

```bash
cd ~/RsaCtfTool/src
python3 -m RsaCtfTool.main --publickey ~/hackday2026/https_is_the_most_secure_browsing/pubkey.pem --private --timeout 300
```

**Success!** RsaCtfTool finds the private key using FactorDB, which has the factors for this modulus stored in its database.

The tool outputs the complete RSA private key:

```
[*] Attack success with factordb method !

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsTQ68C9E628LZoIJbyzWnoerqvv5Ppi3I4nSFBg0El69jHC6
0DNtPOPu+DdJjxsf346Snc30oytdQvaDi8rJkTk4VprHiJeAuePZJblJS6ukby5o
TUwX+vAR02nUzkKNV9qiwwv07DhRvguncqc+YJqS0U+od1C/CovmVgi3qZXXB9/2
RSFHBoy3780N7QXFijbptVyGHDhNPd4/tyzYytAThsanhiJFuHAv+pCj5lS0yBBI
3EoQiR2PJ7o9NCFBZqugI71fJGdVv0XxFbSG+Do6PsnHNBbcgk7Mbt0tqnu1HC2X
pe+5cTHGs/dTtsN2dHvMGcYhecUx3yVHMmZ3rQIBIwKCAQEAogPeHW0Lz/B/c6oX
...
-----END RSA PRIVATE KEY-----
```

## Step 6: Save the Private Key

Save the private key to a file:

```bash
cd ~/hackday2026/https_is_the_most_secure_browsing

cat > server_private_key.pem << 'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAsTQ68C9E628LZoIJbyzWnoerqvv5Ppi3I4nSFBg0El69jHC6
0DNtPOPu+DdJjxsf346Snc30oytdQvaDi8rJkTk4VprHiJeAuePZJblJS6ukby5o
TUwX+vAR02nUzkKNV9qiwwv07DhRvguncqc+YJqS0U+od1C/CovmVgi3qZXXB9/2
RSFHBoy3780N7QXFijbptVyGHDhNPd4/tyzYytAThsanhiJFuHAv+pCj5lS0yBBI
3EoQiR2PJ7o9NCFBZqugI71fJGdVv0XxFbSG+Do6PsnHNBbcgk7Mbt0tqnu1HC2X
pe+5cTHGs/dTtsN2dHvMGcYhecUx3yVHMmZ3rQIBIwKCAQEAogPeHW0Lz/B/c6oX
QRMNXb3eyDbVQIugIH4B5nyHYUCtTTPeAC8EyfT3vl5vI8EHMst+vCoEPWl51tLB
ad36HmAzgmGgfOJJzocs70pRpEUooCpt/YdmYcWMpAj9FFoa0/sYd9Bq5pnkVfwG
zznSoXdhqW1m030GcArhOLeDWTcDwBK0fwclSlaiqLDQhFPonOitq1jwSmCve2RN
mzAODJx1kwjqEG7ZBm6CAioSSg6/sD3YOuawWADACd//QuJalBBfXHnanQ2Vx0e8
4gliO7LPgUUlCMHXYUbZjx9JeQ9BcJK/R++XwI9PAxWZ9aXLVinu6y6RbFKhhASr
rYpriwKBgQDHOOlzaH/SPNmR7fqRq9QcfKGRe0HTjHx/kTrt8YodHmSpQUYxK8s+
r24u8idMQCJnbU5dqSnDOUbi90WSO4O/ksMZj1wwTYvSSJ7E4bADb2U6jTOvw7i8
0URs+AGF8rtyKNBnTjepw3UxowHIAmR/yst6iDnHlGA42HwBf1kgZQKBgQDjtOIN
cbGkAGRkGVEYMHXiofbaRrFrvmINva2c4+YsTqBJrK62WF3Jqfki1gtTpTIrsf5G
srP8b5XaJaerx3XuwfaeRzvnuxSnpLC1nMpAF4lsvDJ27socHqThglFvW1eTYDyv
IQoBsx/WpZXrT7GgQ3J0QFFq1uqYXkQp7T3xqQKBgQCZr4+E6ja4IFARfRHA1QK2
480YdQblBfmkPNWwPfzUomro99cP/TZjjqV0rCzxrdFlurjL6OWz27pXUQnIlE+x
CtEFFtIWojipiHp6n3knOK0tKxk+cmnwvrEg3JN19cPNGCu9aDmRlsge+hdRJmrI
+4cGwNwdnljbZSx2Lwo9jwKBgBoGCzS8iVSSVJ25wCAFidDCDZVJ6GQVwhAy70Uh
XCJSIPJ6Iph/IKlVQQtLqYXm/mtkzJpdkOmmWkTRGnoIKrwzbKRf6ZbTjVT84P7Q
Fx1EhLv4QEgbSkxbRgsk1hta5W/tvcrfNFf3Ntaz1p6Mw9fNMabix3nsrRi6UO7Z
SOhrAoGAMYtZHo1ayYlbIWa4epaETAsZXOs8ZHoF8iykYvCoNGqCD3oUHAu6F3nv
bK3APaVf0C0tdm7KR1ZIccHMZOTlkkZ5qv7+Tn7OjtUIuFfVm27kjeeHkJnIxdU8
nwDg+3MkAOIAvPTjFDV5LJeZSt5TTEb50IC5IZQKvmq9+T0WFtc=
-----END RSA PRIVATE KEY-----
EOF
```

## Step 7: Decrypt the HTTPS Traffic

Use tshark to decrypt the TLS traffic with the recovered private key:

```bash
tshark -r capture.pcap \
  -o "tls.keys_list:172.18.0.2,443,http,server_private_key.pem" \
  -Y "http" \
  -T fields \
  -e http.file_data 2>/dev/null | xxd -r -p
```

**Output:**

```html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gros Texte</title>
    <style>
        body {
            margin: 0;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            font-family: sans-serif;
            background-color: #f0f0f0;
        }
        h1 {
            font-size: 10vw;
            color: #333;
            text-align: center;
        }
    </style>
</head>
<body>

    <h1>HACKDAY{pRn9_1S_wE@K_AsF_no?}</h1>

</body>
</html>
```

## Flag

```
HACKDAY{pRn9_1S_wE@K_AsF_no?}
```

## Vulnerability Explanation

### Why was this vulnerable?

1. **Weak RSA Exponent (e=35):**
   - Standard RSA uses e=65537 (0x10001)
   - Using e=35 makes the encryption much weaker
   - Small exponents can be vulnerable to various attacks

2. **Factorable Modulus:**
   - The 2048-bit modulus was already factored and stored in FactorDB
   - Once the modulus is factored into primes p and q, the private key can be computed
   - With p and q known: φ(n) = (p-1)(q-1), then d = e^(-1) mod φ(n)

3. **RSA Math:**
   - Public key: (n, e) where n=p×q
   - Private key: (n, d)
   - Encryption: c = m^e mod n
   - Decryption: m = c^d mod n
   - If we can factor n or find d, we can decrypt everything

### The Attack Chain

```
1. Extract certificate with weak e=35
2. Extract encrypted pre-master secret from TLS handshake
3. Factor the modulus n (via FactorDB)
4. Compute private key d
5. Decrypt pre-master secret
6. Derive TLS session keys
7. Decrypt HTTPS traffic
8. Get the flag!
```

## Key Takeaways

1. **Never use small RSA exponents** - Always use e=65537
2. **RSA key size matters** - Use at least 2048 bits (preferably 4096)
3. **Check if your modulus is factorable** - Use FactorDB or similar before deployment
4. **HTTPS is only as strong as its crypto** - Weak keys = No security
5. **The challenge title was ironic** - "HTTPS is the most secure" with broken crypto

## Tools Used

- **tshark/Wireshark** - Network packet analysis
- **openssl** - Certificate and key manipulation
- **RsaCtfTool** - Automated RSA attack framework
- **xxd** - Hex dump utilities

## References

- [FactorDB](http://factordb.com/) - Integer factorization database
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) - RSA attack tool
- [RFC 5246](https://tools.ietf.org/html/rfc5246) - TLS 1.2 Specification
- [RSA Cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) - Wikipedia

---

**Challenge Author's Intent:** This challenge demonstrates that HTTPS/TLS is only secure if proper cryptographic parameters are used. Even with "updated Debian" and HTTPS, weak RSA configuration completely breaks the security.
