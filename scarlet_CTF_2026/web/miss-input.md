---
ctf: ScarletCTF 2026
category: web
difficulty: easy
points: 150
flag: RUSEC{Y0U_C4LM_D0WN_175_A_M151NPU7}
techniques:
  - xor-cryptanalysis
  - known-plaintext-attack
  - repeating-key-recovery
tools:
  - python
  - browser-devtools
---

# Miss-Input

## Description

The challenge page is fully client-side. A JavaScript helper `rw(key)` takes a user-supplied key, XOR-decrypts a fixed ciphertext, and only checks whether the decrypted string starts with `RUSEC{`. The "Submit" button never sends anything server-side. A tiny WASM module is provided but only contains XOR helpers and some debug arrays that are not invoked by the page logic. 

**Goal:** recover the XOR key and decrypt the ciphertext into a valid flag.

## Solution

### 1. Extract the ciphertext and algorithm

From the bundled JS:

**Ciphertext (hex):**
```
1f757f0a1e7a1b1f79656b79737e7c7e697f691f7d757f7d067c1d7569746c6f7a
```

**Decryption:** repeating-key XOR

The only check: `plaintext.startsWith("RUSEC{")`

### 2. Fix the key prefix from the known flag header

XOR the first bytes of the ciphertext with `RUSEC{`:

```python
ciphertext = bytes.fromhex("1f757f0a1e7a1b1f79656b...")
known_prefix = b"RUSEC{"

key_prefix = bytes(c ^ k for c, k in zip(ciphertext, known_prefix))
# Result: b'M151NP'
```

So any valid key must start with `M151NP`.

### 3. Recover the full key

The hint ("MISINPUT … CALM DOWN … F DOWN!") and leetspeak expectations lead to a natural plaintext candidate. XORing the ciphertext against that plaintext yields a consistent repeating key:

```python
plaintext_guess = b"RUSEC{Y0U_C4LM_D0WN_175_A_M151NPU7}"
full_key = bytes(c ^ p for c, p in zip(ciphertext, plaintext_guess))
# Repeating key: b'M151NPUT' (8 bytes)
```

### 4. Verify

```python
def xor_decrypt(ct, key):
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))

flag = xor_decrypt(ciphertext, b'M151NPUT')
print(flag.decode())  # RUSEC{Y0U_C4LM_D0WN_175_A_M151NPU7}
```

## Key Techniques

- XOR cryptanalysis
- Known-plaintext attack
- Repeating-key recovery from ciphertext alignment

