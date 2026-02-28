# Starfield Relay — Detailed Reverse Engineering Writeup

This writeup documents the full solve path for **Starfield Relay**, including every stage fragment, how each was recovered, where I got confused, and the final assembly that yields the correct flag:

`UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}`

The goal of the binary is to validate a staged unlock phrase and then decrypt an embedded payload that contains extra fragments. The tricky parts were:

- Stage2 output is **ChaCha20**, not AES (this was the main confusion).
- The payload password includes an extra 16‑byte suffix derived from the **last 5 bytes** of the accumulator.
- The payload contains **multiple fragment sources** (pings, logs, void) and a decoy island in the void.

Below is a clean, repeatable process with commands and reasoning.

---

## 0. Recon / Classification

Commands:

```bash
ls -la
file crackme.exe
strings crackme.exe | head -100
strings crackme.exe | rg -i "stage|flag|uvt|token"
```

Findings:

- `crackme.exe` is a 64‑bit PE (Windows, x86_64).
- Strings show prompts like `enter base prefix`, `enter fragment`, `enter stage2 token`, and `stage5: payload decrypt/auth failed`.
- The flag format is `UVT{...}`.

---

## 1. Stage Architecture

From the main dispatcher in the binary, there are **staged calls**:

1. `stage1` — base prefix (4 chars)
2. `stage1b` — fragment (3 chars)
3. `stage2` — token (8 chars)
4. `stage3` — token (8 chars)
5. `stage4` — no input, internal VM
6. `stage5` — decrypt embedded payload if everything is consistent

Each stage pushes a fragment into an accumulator used later.

---

## 2. Stage1 and Stage1b (Prefix + Fragment)

### Stage1
- Prompt: `enter base prefix (4 chars):`
- Direct compare against a static 4‑byte string.

Recovered:

```
UVT{
```

### Stage1b
- Prompt: `enter fragment (3 chars):`
- Compared against internal value built by a helper function.

Recovered:

```
Kr4
```

Stage1 output:

```
UVT{Kr4
```

---

## 3. Stage2 Token (8 chars)

Prompt: `enter stage2 token (8 chars):`

The validator checks each byte via:

```
((i*0x11 + 0x6d) ^ input[i]) + 0x13 + i*7 == expected[i]
```

Expected bytes are the two dwords `0xfadc2431` and `0xc5e42c25` (little‑endian) →

```
[0x31, 0x24, 0xdc, 0xfa, 0x25, 0x2c, 0xe4, 0xc5]
```

Solving for `input[i]` yields:

```
st4rG4te
```

---

## 4. Stage3 Token (8 chars)

Prompt: `enter token (8 chars):`

Validator formula:

```
((0xa7 - 0x0b*i) ^ input[i]) + 3*i == expected[i]
```

Expected bytes from `0xeda7d1d7` and `0x49683954` →

```
[0xd7, 0xd1, 0xa7, 0xed, 0x54, 0x39, 0x68, 0x49]
```

Recovered:

```
pR0b3Z3n
```

---

## 5. Stage4 VM (No Input)

Stage4 builds a bytecode program, runs a simple stack VM, and compares SHA256 of the output.

The VM yields:

```
THEN-
```

This is also the prefix for the next password derivation step.

---

## 6. Stage2 Output (PBKDF2 + ChaCha20)

After token validation, Stage2 derives an output string used later.

### Params extracted

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::s2::pbkdf2::v2`
- Iterations: `60000`
- Output length: `48` bytes → `32` key + `16` nonce

Then it encrypts a **fixed 6‑byte plaintext** with **ChaCha20**:

Plaintext bytes:

```
CC 05 6F DA B9 BE
```

Output:

```
cK_M3_
```

**This was a major confusion point.**
I initially assumed AES, but the EVP cipher pointer resolves to **NID 1019 → ChaCha20**. This is why the earlier AES attempts failed.

Command to confirm NID (Linux with OpenSSL):

```bash
python3 - <<'PY'
import ctypes, ctypes.util
lib = ctypes.CDLL(ctypes.util.find_library('crypto'))
lib.OBJ_nid2sn.restype = ctypes.c_char_p
print(lib.OBJ_nid2sn(1019))
PY
```

---

## 7. Stage3 Output (PBKDF2 + AES‑GCM)

Stage3 uses AES‑256‑GCM:

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::s3::pbkdf2::v4`
- Iterations: `90000`
- Output length: `44` bytes → `32` key + `12` nonce
- AAD: `uvt::stage3::aad::v4`
- Ciphertext: `8f 99 8d 30 eb 80 8c 85 8b 8f 01`
- Tag: `e0 c3 1b 05 65 d6 a3 eb 07 d5 7c b9 16 b5 92 c4`

Recovered plaintext:

```
N0w-cR4Km3_
```

---

## 8. Stage5 Password Derivation

Accumulator before Stage5:

```
UVT{Kr4 + cK_M3_ + N0w-cR4Km3_ + THEN-
```

This is:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-
```

**Extra 16‑byte suffix** is computed from the **sum of the last 5 bytes** of the accumulator:

```
b = sum(acc[-5:]) & 0xff
suffix[i] = b ^ const[i]
```

Constants:

```
69 08 68 2E 3A 6D 6F 10 38 03 2C 35 12 3B 0F 03
```

Suffix result:

```
5T4rf13Ld_piNgS_
```

Final Stage5 password:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_
```

---

## 9. Stage5 Payload Decrypt (AES‑256‑GCM)

The embedded resource (id 101) is a `UVTBLOB4` container:

```
magic: 8 bytes
version: 1 byte
nonce: 12 bytes
tag: 16 bytes
ciphertext: rest
```

Key derivation:

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::stage2blob::v4`
- Iterations: `120000`
- Output length: `32` bytes
- AAD: `uvt::stage2blob::aad::v4|id=101`

Decryption yields a ZIP containing:

```
logs/system.log
starfield_pings/pings.txt
void/zen_void.bin
...
```

---

## 10. Payload Fragment Extraction

### A. Pings (5‑bit map)

File: `starfield_pings/pings.txt`

- Use only lines with `ttl=1337`.
- Convert `time=64..76` → values `0..12`.
- Build alphabet from two maps:

```
# map_even_xor52=270d62612a1c7f3036343a383e3c2220
# map_odd_rev_xor13=60627c7e787a74767072574749716341
```

Mapping:

- `even = bytes(map_even_xor52) ^ 0x52`
- `odd_rev = bytes(map_odd_rev_xor13) ^ 0x13`
- `odd = reverse(odd_rev)`
- index 0..31 → `[even0, odd0, even1, odd1, ...]`

Fragment:

```
uR_pR0b3Z_xTND-
```

### B. Logs (zen fragments)

File: `logs/system.log`

Each `subsys=zen` entry has `slot`, `k`, `fragx`.
Compute:

```
frag = xor(fragx, k)
```

Order by slot, concatenate, then base64 decode.

Result:

```
I_h1D3_in_l0Gz_
```

### C. Void (two islands + decoy)

File: `void/zen_void.bin`

- Stage8: XOR each non‑zero island with key `0x2a`.
- Two readable candidates contain `v01D`:

```
7n_v01D_
1n_v01D_
```

- Stage9 key = `sum(bytes(stage8)) % 256`.
- For `1n_v01D_`, the decoded islands include:

```
iN_FAIL}
(iN_ZEN})
```

`iN_ZEN}` is the correct one; `iN_FAIL}` is the decoy.

Fragments:

```
1n_v01D_
iN_ZEN}
```

---

## 11. Final Flag Assembly

All fragments in order:

```
UVT{Kr4
cK_M3_
N0w-cR4Km3_
THEN-
5T4rf13Ld_piNgS_
(uR_pR0b3Z_xTND-)
(I_h1D3_in_l0Gz_)
(1n_v01D_)
(iN_ZEN})
```

Final flag:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}
```

---

## 12. Dynamic Analysis (pwndbg) — Optional Commands

I solved most of this statically, but these are useful dynamic commands if you want to verify comparisons at runtime:

```gdb
# Start and run
pwndbg> file crackme.exe
pwndbg> break *0x140115c90   # stage2 byte check loop
pwndbg> break *0x1401164d0   # stage3 byte check loop
pwndbg> run

# Inspect compared bytes
pwndbg> x/8bx $rcx    # input buffer
pwndbg> x/8bx $rbp-0x38  # expected bytes

# Stage5 decrypt failure point
pwndbg> break *0x14011b16d
pwndbg> continue

# Examine derived password buffer
pwndbg> x/s $rdi  # adjust register once stopped in stage5
```

Notes:
- This binary is Windows PE, so runtime debugging is easier under WinDbg or x64dbg, but pwndbg can still be useful under Wine with gdb.

---

## 13. Confusions & Corrections (Important)

1. **AES vs ChaCha20 in Stage2**
   - Initial assumption: AES (CBC/CTR/CFB) because EVP functions look similar.
   - Correction: Cipher NID = 1019 → ChaCha20. This resolved the stage2 mismatch.

2. **Missing 16‑byte suffix in Stage5**
   - Decryption kept failing even with correct accumulator.
   - Found an extra suffix derived from the last 5 bytes (sum) and XOR constants.

3. **Void decoy**
   - Two stage8 candidates; one leads to `iN_FAIL}`.
   - Correct final island is `iN_ZEN}`.

---

## 14. Minimal Solver (Reference)

A full solver script is in `solve_starfield.py` (in this repo). Use it to re‑derive everything quickly.

---

## 15. Commands Summary (Quick Reference)

```bash
# Recon
file crackme.exe
strings crackme.exe | rg -i "stage|uvt|token"

# Extract and decrypt payload (via solver)
python3 solve_starfield.py

# Inspect payload
unzip -l /tmp/stage5_payload.zip
rg -n "zen" /tmp/starfield_payload/logs/system.log
rg -n "ttl=1337" /tmp/starfield_payload/starfield_pings/pings.txt
```

---
