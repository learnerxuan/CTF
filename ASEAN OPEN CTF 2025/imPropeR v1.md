# ImPropeR v1 - CTF Writeup

**Challenge Category:** Cryptography  
**Points:** 100  
**Flag:** `flag{bbbd90996f79ff9dd591aa1c08e62def}`

## Challenge Description

> Hanni, a newbie in cryptography, is trying to implement the Stickel Key Exchange protocol. I gave her some advice, but it seems she forgot to do it properly.

## Initial Analysis

We're given a Python script that implements a variant of the Stickel Key Exchange protocol. Let's examine the key components:

```python
# Generate two 5x5 matrices over GF(p)
A = random_matrix(Fp, 5, 5)
B = random_matrix(Fp, 5, 5)

# Alice computes and sends
u = vector(A**n).pairwise_product(vector(B**m))

# Bob computes and sends  
v = vector(A**r).pairwise_product(vector(B**s))

# Shared key computation
Ka = vector(A**n).pairwise_product(vector(v).pairwise_product(vector(B**m)))
Kb = vector(A**r).pairwise_product(vector(u).pairwise_product(vector(B**s)))
```

The challenge title "imPropeR" hints that there's something improper about this implementation.

## Understanding the Stickel Key Exchange

The Stickel Key Exchange is a cryptographic protocol that should work as follows:

1. **Public Parameters:** Two matrices A and B over a finite field
2. **Alice's Secret:** Exponents n and m
3. **Bob's Secret:** Exponents r and s
4. **Alice Sends:** u = A^n ⊙ B^m (where ⊙ is pairwise product)
5. **Bob Sends:** v = A^r ⊙ B^s
6. **Shared Key:** Both parties compute the same value using their secrets

## The Critical Vulnerability

The vulnerability lies in how the shared key is computed. Let's analyze the mathematical relationships:

### Alice's Computation
```
u[i] = A^n[i] * B^m[i]
Ka[i] = A^n[i] * (A^r[i] * B^s[i]) * B^m[i]
Ka[i] = A^n[i] * A^r[i] * B^m[i] * B^s[i]
```

### Bob's Computation  
```
v[i] = A^r[i] * B^s[i]
Kb[i] = A^r[i] * (A^n[i] * B^m[i]) * B^s[i]
Kb[i] = A^r[i] * A^n[i] * B^s[i] * B^m[i]
```

### The Fatal Flaw
Since multiplication in a finite field is **commutative**, we have:
```
Ka[i] = A^n[i] * A^r[i] * B^m[i] * B^s[i]
      = A^r[i] * A^n[i] * B^s[i] * B^m[i] 
      = Kb[i]
```

But more importantly, an attacker can compute this directly:
```
u[i] * v[i] = (A^n[i] * B^m[i]) * (A^r[i] * B^s[i])
            = A^n[i] * A^r[i] * B^m[i] * B^s[i]
            = Ka[i] = Kb[i]
```

**The shared key is simply the pairwise product of the public values u and v!**

## The Root Cause

The flag message reveals the issue: "Remember Hanni, if I said it needs to be non-commutative, then IT HAS TO BE NON-COMMUTATIVE, OK??"

The security of the Stickel protocol relies on using **non-commutative operations** (like matrix multiplication), but this implementation uses commutative field operations, completely breaking the security.

## Exploitation

### Step 1: Extract the Public Values
From the challenge output, we have:
- `p = 242465658163462405324993003447648550123`
- `u = [136363031559837104081527699705343878982, ...]` (25 elements)
- `v = [100502267405363070530957820417309497680, ...]` (25 elements)
- `ciphertext = '5e2bb1c14943c3c2d5ba629f65abe7a3...'`

### Step 2: Compute the Shared Key
```python
shared_key = []
for i in range(25):
    shared_key.append((u[i] * v[i]) % p)
```

### Step 3: Derive the AES Key
```python
key_string = str(tuple(shared_key))
aes_key = sha256(key_string.encode()).digest()[:16]
```

### Step 4: Decrypt the Message
```python
ciphertext = bytes.fromhex(ciphertext_hex)
cipher = AES.new(aes_key, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext)

# Remove PKCS7 padding
padding_length = decrypted[-1]
message = decrypted[:-padding_length].decode('utf-8')
```

### Step 5: Format the Flag
```python
import hashlib
flag_hash = hashlib.md5(message.encode()).hexdigest()
flag = f"flag{{{flag_hash}}}"
```

## Complete Exploit Code

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from hashlib import sha256
import hashlib

# Given values from the challenge
p = 242465658163462405324993003447648550123
u = [136363031559837104081527699705343878982, 10167651930671645416984438049044546412, ...]
v = [100502267405363070530957820417309497680, 53017708193518699424392288168907240526, ...]
ciphertext_hex = '5e2bb1c14943c3c2d5ba629f65abe7a30804f635ee8c0376c1cd06b170992d27...'

def exploit_stickel():
    # Compute shared key as u ⊙ v
    shared_key = []
    for i in range(25):
        shared_key.append((u[i] * v[i]) % p)
    
    # Generate AES key
    key_string = str(tuple(shared_key))
    aes_key = sha256(key_string.encode()).digest()[:16]
    
    # Decrypt
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    
    # Remove padding and get message
    padding_length = decrypted[-1]
    message = decrypted[:-padding_length].decode('utf-8')
    
    # Format flag
    flag_hash = hashlib.md5(message.encode()).hexdigest()
    return f"flag{{{flag_hash}}}"

if __name__ == "__main__":
    print(exploit_stickel())
```
**Final Flag:** `flag{bbbd90996f79ff9dd591aa1c08e62def}`
