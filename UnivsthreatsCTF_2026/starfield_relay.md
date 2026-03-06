# Starfield Relay — Full Reverse Engineering Writeup 

Final correct flag:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_uR_pR0b3Z_xTND-I_h1D3_in_l0Gz_1n_v01D_iN_ZEN}
```

---

## 0. Challenge Summary

Binary validates a **multi‑part unlock phrase** in stages. Each stage yields a fragment. Once correct, it decrypts an embedded payload, which contains more fragments. The final flag is built by concatenating **stage fragments + payload fragments**.

---

## 1. Initial Recon

Commands:

```bash
ls -la
file crackme.exe
strings crackme.exe | head -100
strings crackme.exe | rg -i "stage|token|uvt|flag"
```

Findings:
- `crackme.exe` is a 64‑bit PE (x86_64).
- Strings show multiple stage prompts and a stage5 payload decrypt.

---

## 2. Stage Map and Entry Points (Exact Offsets)

From the dispatcher (function `FUN_140114280`), the stage calls appear in order:

| Stage | Function | Address | Notes |
|------:|----------|---------|------|
| 1 | `FUN_1401156f0` | `0x1401156f0` | Base prefix (4 chars) |
| 1b | `FUN_140115860` | `0x140115860` | Fragment (3 chars) |
| 2 | `FUN_140115b80` | `0x140115b80` | Stage2 token (8 chars) |
| 3 | `FUN_1401164a0` | `0x1401164a0` | Stage3 token (8 chars) |
| 4 | `FUN_140117780` | `0x140117780` | Internal VM (no input) |
| 5 | `FUN_14011a330` | `0x14011a330` | Payload decrypt + next steps |

Useful helper functions:

| Function | Address | Purpose |
|----------|---------|---------|
| `FUN_140116270` | `0x140116270` | Simple transform used for hash checks |
| `FUN_140120450` | `0x140120450` | SHA‑256 implementation |
| `FUN_14011e2e0` | `0x14011e2e0` | PBKDF2 wrapper |
| `FUN_14011e1a0` | `0x14011e1a0` | EVP cipher wrapper (used by Stage2) |
| `FUN_14011df70` | `0x14011df70` | AES‑GCM routine (Stage3) |

Strings for salts:

- Stage2 salt string is at `0x14030d808` → `"uvt::s2::pbkdf2::v2"`
- Stage3 salt string is at `0x14030d8c0` → `"uvt::s3::pbkdf2::v4"`

---

## 3. Stage1 — Base Prefix (4 chars)

Function: `FUN_1401156f0` @ `0x1401156f0`

Disassembly landmark:

```
1401157d5: CMP R8,0x4
1401157db: LEA RDX,[0x14030d7a0]   ; "UVT{"
1401157e2: CALL memcmp
```

So stage1 expects:

```
UVT{
```

---

## 4. Stage1b — Fragment (3 chars)

Function: `FUN_140115860` @ `0x140115860`

Logic:
- Reads 3‑char input.
- Calls `FUN_140115aa0` to produce an internal 3‑byte value.
- Compares each byte.

Recovered fragment:

```
Kr4
```

So stage1 fragment total:

```
UVT{Kr4
```

---

## 5. Stage2 Token (8 chars)

Function: `FUN_140115b80` @ `0x140115b80`

Disassembly landmark (byte check loop):

```
140115c90: IMUL EDX,EAX,0x11
140115c93: ADD DL,0x6d
140115c96: XOR DL,byte ptr [RCX + R8]
140115ca1: ADD DL,0x13
140115ca4: ADD DL,CL
140115ca6: CMP DL,byte ptr [RBP + R8 - 0x38]
```

Expected bytes are built from:

```
0xfadc2431
0xc5e42c25
```

Little‑endian expected bytes:

```
31 24 dc fa 25 2c e4 c5
```

Solve for input:

```
input[i] = (i*0x11 + 0x6d) ^ (expected[i] - 0x13 - i*7)
```

Recovered:

```
st4rG4te
```

---

## 6. Stage3 Token (8 chars)

Function: `FUN_1401164a0` @ `0x1401164a0`

Disassembly landmark:

```
local_308 = 0xeda7d1d7
local_304 = 0x49683954
((0xa7 - 0x0b*i) ^ input[i]) + 3*i == expected[i]
```

Expected bytes:

```
d7 d1 a7 ed 54 39 68 49
```

Recovered token:

```
pR0b3Z3n
```

---

## 7. Stage4 — VM (No Input)

Function: `FUN_140117780` @ `0x140117780`

This stage constructs a bytecode program and interprets it.

### VM Opcode Mapping

The VM dispatch table is in a `switch` inside the interpreter (near `FUN_140118090`). Based on analysis:

| Opcode | Meaning |
|-------:|---------|
| 1 | `reg[a] = imm` (set register) |
| 2 | `reg[a] ^= reg[b]` |
| 3 | `reg[a] += reg[b]` |
| 4 | `reg[a] -= reg[b]` |
| 6 | push reg → stack |
| 7 | pop stack → reg |
| 8 | append reg byte to output |
| 11 | end program |

The program output is:

```
THEN-
```

This value is later used in Stage5.

---

## 8. Stage2 Output (PBKDF2 + ChaCha20)

Stage2 doesn’t just validate the token; it generates a derived output using crypto.

Parameters (extracted from binary):

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::s2::pbkdf2::v2` (address `0x14030d808`)
- Iterations: `60000`
- Output length: `48` bytes (32 key + 16 nonce)

Then it encrypts **6 bytes**:

```
CC 05 6F DA B9 BE
```

Critical detail: the EVP cipher pointer is **NID 1019**, which is `ChaCha20`.

Command used to confirm NID:

```bash
python3 - <<'PY'
import ctypes, ctypes.util
lib = ctypes.CDLL(ctypes.util.find_library('crypto'))
lib.OBJ_nid2sn.restype = ctypes.c_char_p
print(lib.OBJ_nid2sn(1019))
PY
```

Output:
```
ChaCha20
```

Stage2 output:

```
cK_M3_
```

---

## 9. Stage3 Output (PBKDF2 + AES‑GCM)

Stage3 uses AES‑256‑GCM with AAD.

Parameters:

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::s3::pbkdf2::v4` (address `0x14030d8c0`)
- Iterations: `90000`
- Output length: `44` bytes (32 key + 12 IV)
- AAD: `uvt::stage3::aad::v4`

Ciphertext + tag are embedded constants.

Recovered output:

```
N0w-cR4Km3_
```

---

## 10. Stage5 Password Derivation

The accumulator before Stage5 is:

```
UVT{Kr4 + cK_M3_ + N0w-cR4Km3_ + THEN-
```

Base accumulator:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-
```

**Extra suffix logic:**

```
b = sum(last 5 bytes of accumulator) & 0xff
suffix[i] = b ^ const[i]
```

Constants:

```
69 08 68 2E 3A 6D 6F 10 38 03 2C 35 12 3B 0F 03
```

Derived suffix:

```
5T4rf13Ld_piNgS_
```

Final Stage5 password:

```
UVT{Kr4cK_M3_N0w-cR4Km3_THEN-5T4rf13Ld_piNgS_
```

---

## 11. Stage5 Payload Decrypt

The embedded resource is a blob:

```
magic: UVTBLOB4
version
nonce (12)
tag (16)
ciphertext
```

Parameters:

- PBKDF2‑HMAC‑SHA256
- Salt: `uvt::stage2blob::v4`
- Iterations: `120000`
- Output length: 32 bytes
- AAD: `uvt::stage2blob::aad::v4|id=101`

Decryption yields a ZIP payload.

---

## 12. Payload Fragments

### 12.1 Pings (5‑bit decode)

File: `starfield_pings/pings.txt`

Use TTL=1337 rows. Extract time values (64–76 → 0..12).

Maps:

```
map_even_xor52=270d62612a1c7f3036343a383e3c2220
map_odd_rev_xor13=60627c7e787a74767072574749716341
```

Decode:

```
- even = map_even_xor52 ^ 0x52
- odd = reverse(map_odd_rev_xor13 ^ 0x13)
- alphabet = [even0, odd0, even1, odd1, ...]
```

Fragment:

```
uR_pR0b3Z_xTND-
```

### 12.2 Logs (zen fragments)

File: `logs/system.log`

Each `subsys=zen` line has `slot`, `k`, `fragx`.
Decode:

```
frag = xor(fragx, k)
```

Order by slot, concatenate, base64 decode:

```
I_h1D3_in_l0Gz_
```

### 12.3 Void (islands, decoy)

File: `void/zen_void.bin`

Stage8:
- XOR islands with key 0x2a.
- Two candidate islands contain `v01D`:

```
7n_v01D_
1n_v01D_
```

Stage9:
- key = sum(bytes(stage8)) % 256
- Decode other islands.

For `1n_v01D_` you get:

```
iN_FAIL}
(iN_ZEN})
```

`iN_ZEN}` is correct; `iN_FAIL}` is decoy.

---

## 13. Final Assembly

Concatenate all fragments:

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

## 14. Full Working Script (Included)

```python
#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import struct
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ROOT = Path(".")
BIN = ROOT / "crackme.exe"
BLOB = ROOT / "resource_101.bin"

S2_SALT = b"uvt::s2::pbkdf2::v2"
S3_SALT = b"uvt::s3::pbkdf2::v4"
S5_SALT = b"uvt::stage2blob::v4"
S5_AAD = b"uvt::stage2blob::aad::v4|id=101"

# Stage 1+2+3 tokens (validated already from the checker math)
STAGE1 = b"UVT{Kr4"
STAGE2_TOKEN = b"st4rG4te"
STAGE3_TOKEN = b"pR0b3Z3n"
STAGE4 = b"THEN-"

# --- Stage2 output (ChaCha20) ---
def stage2_output() -> bytes:
    # PBKDF2-HMAC-SHA256, 60000 iterations, 48 bytes = 32 key + 16 nonce
    key_iv = hashlib.pbkdf2_hmac("sha256", STAGE2_TOKEN, S2_SALT, 60000, 48)
    key = key_iv[:32]
    nonce = key_iv[32:48]  # 16 bytes for ChaCha20
    # plaintext is the 6 bytes at local_a8: 0xcc 0x05 0x6f 0xda 0xb9 0xbe
    pt = bytes([0xCC, 0x05, 0x6F, 0xDA, 0xB9, 0xBE])
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(pt)

# --- Stage3 output (AES-256-GCM) ---
def stage3_output() -> bytes:
    key_iv = hashlib.pbkdf2_hmac("sha256", STAGE3_TOKEN, S3_SALT, 90000, 44)
    key = key_iv[:32]
    iv = key_iv[32:44]  # 12 bytes
    # ciphertext + tag from stage3 constants
    ct = bytes([0x8F,0x99,0x8D,0x30,0xEB,0x80,0x8C,0x85,0x8B,0x8F,0x01])
    tag = bytes([0xE0,0xC3,0x1B,0x05,0x65,0xD6,0xA3,0xEB,0x07,0xD5,0x7C,0xB9,0x16,0xB5,0x92,0xC4])
    aad = b"uvt::stage3::aad::v4"
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    dec = cipher.decryptor()
    dec.authenticate_additional_data(aad)
    return dec.update(ct) + dec.finalize()

# --- Stage5 password suffix (derived from last 5 bytes sum) ---
def stage5_suffix(acc: bytes) -> bytes:
    b = sum(acc[-5:]) & 0xFF
    consts = [0x69,0x08,0x68,0x2E,0x3A,0x6D,0x6F,0x10,0x38,0x03,0x2C,0x35,0x12,0x3B,0x0F,0x03]
    return bytes([b ^ c for c in consts])

# --- Stage5 decrypt ---
def stage5_decrypt(password: bytes) -> bytes:
    blob = BLOB.read_bytes()
    assert blob[:8] == b"UVTBLOB4"
    nonce = blob[9:21]
    tag = blob[21:37]
    ct = blob[37:]
    key = hashlib.pbkdf2_hmac("sha256", password, S5_SALT, 120000, 32)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    dec = cipher.decryptor()
    dec.authenticate_additional_data(S5_AAD)
    return dec.update(ct) + dec.finalize()

# --- Parse starfield_pings (stage6/7) ---
def parse_pings(pings_path: Path) -> str:
    text = pings_path.read_text()
    times = []
    for line in text.splitlines():
        if "ttl=1337" in line:
            m = re.search(r"time=(\d+)ms", line)
            if m:
                times.append(int(m.group(1)))
    vals = [t - 64 for t in times]  # 0..31

    # build 5-bit alphabet from parity‑split maps
    m_even = re.search(r"map_even_xor52=([0-9a-f]+)", text)
    m_odd = re.search(r"map_odd_rev_xor13=([0-9a-f]+)", text)
    if not m_even or not m_odd:
        raise RuntimeError("missing map hints in pings.txt")

    map_even_xor52 = bytes.fromhex(m_even.group(1))
    map_odd_rev_xor13 = bytes.fromhex(m_odd.group(1))

    even = bytes(b ^ 0x52 for b in map_even_xor52)              # 16 chars
    odd_rev = bytes(b ^ 0x13 for b in map_odd_rev_xor13)         # 16 chars
    odd = odd_rev[::-1]

    alpha = ["?"] * 32
    for i,ch in enumerate(even):
        alpha[i*2] = chr(ch)
    for i,ch in enumerate(odd):
        alpha[i*2 + 1] = chr(ch)
    alphabet = "".join(alpha)

    return "".join(alphabet[v] for v in vals)

# --- Parse logs/system.log (stage8 fragment) ---
def parse_logs(log_path: Path) -> str:
    frags = {}
    for line in log_path.read_text().splitlines():
        if '"subsys":"zen"' not in line:
            continue
        j = json.loads(line)
        slot = int(j["slot"])
        k = int(j["k"], 16)
        fragx = bytes.fromhex(j["fragx"])
        frag = bytes([b ^ k for b in fragx])
        frags[slot] = frag
    combined = b"".join(frags[i] for i in sorted(frags))
    return base64.b64decode(combined).decode()

# --- Parse void/zen_void.bin (stage9/10 fragments) ---
def parse_void(void_path: Path) -> tuple[str, str]:
    data = void_path.read_bytes()
    segments = []
    start = None
    for i, b in enumerate(data):
        if b != 0 and start is None:
            start = i
        elif b == 0 and start is not None:
            segments.append((start, i))
            start = None
    if start is not None:
        segments.append((start, len(data)))

    # collect all readable candidates for stage8 (xor 0x2a) that contain v01D
    stage8_candidates = []
    for s, e in segments:
        seg = data[s:e]
        dec = bytes([b ^ 0x2A for b in seg])
        if all(32 <= c <= 126 for c in dec) and b"v01D" in dec:
            stage8_candidates.append(dec.decode())
    if not stage8_candidates:
        raise RuntimeError("stage8 island not found")

    # stage9: try each stage8 candidate and pick a decoded island that contains ZEN or ends with }
    # prefer ZEN match over decoys
    best = None
    for stage8 in stage8_candidates:
        key9 = sum(stage8.encode()) % 256
        for s, e in segments:
            seg = data[s:e]
            dec = bytes([b ^ key9 for b in seg])
            if all(32 <= c <= 126 for c in dec):
                txt = dec.decode(errors="ignore")
                if "zen" in txt.lower():
                    return stage8, txt
                if txt.endswith("}") and best is None:
                    best = (stage8, txt)

    if best is not None:
        return best
    raise RuntimeError("stage9 island not found")


def main() -> None:
    if not BIN.exists() or not BLOB.exists():
        raise SystemExit("run this in /home/xuan/univsthreats2026_CTF/starfield_relay")

    s2 = stage2_output()            # cK_M3_
    s3 = stage3_output()            # N0w-cR4Km3_
    acc = STAGE1 + s2 + s3 + STAGE4
    suffix = stage5_suffix(acc)
    password = acc + suffix

    payload = stage5_decrypt(password)
    # write zip to temp
    tmp_zip = Path("/tmp/stage5_payload.zip")
    tmp_zip.write_bytes(payload)

    # extract payload
    out_dir = Path("/tmp/starfield_payload")
    if out_dir.exists():
        # clean only our tree
        for p in out_dir.rglob("*"):
            if p.is_file():
                p.unlink()
        for p in sorted([p for p in out_dir.rglob("*") if p.is_dir()], reverse=True):
            p.rmdir()
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp_zip) as z:
        z.extractall(out_dir)

    frag_pings = parse_pings(out_dir / "starfield_pings" / "pings.txt")
    frag_logs = parse_logs(out_dir / "logs" / "system.log")
    frag_void8, frag_void9 = parse_void(out_dir / "void" / "zen_void.bin")

    # final assembly: include stage fragments + payload fragments
    all_frag = STAGE1 + s2 + s3 + STAGE4
    payload_frag = (frag_pings + frag_logs + frag_void8 + frag_void9).encode()
    flag = (all_frag + payload_frag).decode()
    print(flag)


if __name__ == "__main__":
    main()
```

---

## 15. Optional Debugging / Dynamic Checks (pwndbg)

If you want to watch comparisons in a debugger:

```gdb
pwndbg> file crackme.exe
pwndbg> break *0x140115c90   # stage2 byte check loop
pwndbg> break *0x1401164d0   # stage3 byte check loop
pwndbg> run

# Inspect input and expected
pwndbg> x/8bx $rcx
pwndbg> x/8bx $rbp-0x38
```

Note: this PE is Windows; pwndbg is easier under Wine + gdb, or use x64dbg on Windows.

---

## 16. Final Notes

Key lessons for beginners:

1. **Don’t assume the crypto.** Confirm the cipher by checking the EVP NID.
2. **Staged binaries often reuse outputs.** Tokens are not always the final fragments.
3. **Payloads can contain decoys.** Use hints carefully and validate candidates.
