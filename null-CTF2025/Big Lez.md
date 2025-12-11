# Big Lez - Reverse Engineering Challenge Writeup

**Challenge**: Big Lez  
**Category**: Reverse Engineering (Hard)  
**Author**: xrp  
**Description**: Ya fucken' druggo  
**Flag**: `nullctf{dns_is_br0k3n_why_is_i7_4lw4ys_dns}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding XOR Encryption](#understanding-xor-encryption)
4. [Reverse Engineering the Binary](#reverse-engineering-the-binary)
5. [The Encryption Scheme](#the-encryption-scheme)
6. [Writing the Decryption Script](#writing-the-decryption-script)
7. [Getting the Flag](#getting-the-flag)
8. [Key Takeaways](#key-takeaways)
9. [Common Confusions Explained](#common-confusions-explained)

---

## Challenge Overview

### Files Provided

```bash
$ ls
nightmare  traffic.pcap

$ file nightmare 
nightmare: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=440f1e117fef472e3f394786d9817047548b0560, 
for GNU/Linux 3.2.0, stripped
```

- **`nightmare`**: A stripped 64-bit Linux executable
- **`traffic.pcap`**: Network packet capture file

### Challenge Concept

This challenge involves:
1. A binary that intercepts DNS traffic using Linux Netfilter
2. Encrypts domain names using XOR cipher
3. The encrypted domains are hex-encoded and sent as DNS queries
4. The flag is hidden in specific domains ending with `.ro`

---

## Initial Analysis

### Step 1: Examining the PCAP

First, let's look at the network traffic:

```bash
$ tshark -r traffic.pcap | head -20
1   0.000000 192.168.58.10 → 192.168.58.2 DNS 81 Standard query 0x5010 A EEEB713DFBFF75.E8FC7D
2   0.038289 192.168.58.10 → 192.168.58.2 DNS 120 Standard query 0xbfb2 A CDACD0D6CCA6.C5B5D7D1D4B0...
3   0.038426 192.168.58.10 → 192.168.58.2 DNS 120 Standard query 0xeeb5 AAAA CDACD787CCA6.C5B5D080D4B0...
```

**Key Observations:**
- All DNS queries are to port 53 (standard DNS)
- Domain names look like hex strings: `EEEB713DFBFF75.E8FC7D`
- Each query has a unique DNS transaction ID (e.g., `0x5010`, `0xbfb2`)
- These aren't real domains → must be encoded!

### Step 2: Extracting DNS Queries

```bash
$ tshark -r traffic.pcap -Y "dns" -T fields -e dns.qry.name | head -10
EEEB713DFBFF75.E8FC7D
CDACD0D6CCA6.C5B5D7D1D4B0.C4A2C6DE.CDAAD1CDCFB0DDD9D4.C3ACDF
CDACD787CCA6.C5B5D080D4B0.C4A2C18F.CDAAD69CCFB0DA88D4.C3ACD8
ABDABF03A0D0.AFDABD
E6E9B579F4E2.E2EFAC
```

All domains are **uppercase hex characters** (A-F, 0-9) separated by dots.

---

## Understanding XOR Encryption

### What is XOR?

**XOR (Exclusive OR)** is a bitwise operation with this truth table:

```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

**Rule**: Result is `1` only when bits are **different**.

### XOR on Bytes - Example

```
Letter 'A' = 01000001 (binary) = 0x41 (hex) = 65 (decimal)
Key byte  = 00001111 (binary) = 0x0F (hex) = 15 (decimal)

'A' XOR Key:
  01000001  ('A')
XOR 00001111  (Key)
-----------
  01001110  = 0x4E = 'N'
```

So: `'A' XOR 0x0F = 'N'`

### Why Do We Need a Key?

**Without a key:**
```
'A' XOR 'A' = 0x00  ← Useless, everyone knows this!
```

**With a key (XOR cipher):**
```
Original:  "hello"
Key:       [0x12, 0x34, 0x56, 0x78]

'h' XOR 0x12 = encrypted_byte_1
'e' XOR 0x34 = encrypted_byte_2
'l' XOR 0x56 = encrypted_byte_3
'l' XOR 0x78 = encrypted_byte_4
'o' XOR 0x12 = encrypted_byte_5  ← key repeats!
```

Without the key `[0x12, 0x34, 0x56, 0x78]`, you can't decrypt!

### XOR's Magic Property

XOR is **reversible** with the same key:

```
Encryption: Plaintext XOR Key = Ciphertext
Decryption: Ciphertext XOR Key = Plaintext

Example:
'h' (0x68) XOR Key (0x12) = 0x7A  (encrypt)
0x7A XOR Key (0x12) = 0x68 ('h')  (decrypt)
```

**The same operation encrypts AND decrypts!**

### Full Word Example

Encrypting "cat":

```python
plaintext = "cat"
key = [0xAB, 0xCD, 0xEF, 0x12]

# Encryption:
'c' (0x63) XOR 0xAB = 0xC8
'a' (0x61) XOR 0xCD = 0xAC  
't' (0x74) XOR 0xEF = 0x9B

Encrypted = [0xC8, 0xAC, 0x9B]
Hex string = "C8AC9B"

# Decryption:
0xC8 XOR 0xAB = 0x63 = 'c'
0xAC XOR 0xCD = 0x61 = 'a'
0x9B XOR 0xEF = 0x74 = 't'

Result = "cat"  ← Got it back!
```

---

## Reverse Engineering the Binary

### Tools Used

- **Ghidra**: Open-source reverse engineering tool
- **GDB**: GNU Debugger for dynamic analysis
- **strings**: Extract readable strings from binary

### Static Analysis

```bash
$ strings nightmare | grep -i dns
# Look for DNS-related strings

$ strings nightmare | grep -i socket
# Look for network functions
```

### Disassembly in Ghidra

After loading the binary into Ghidra, we find two main functions:

#### Function 1: `FUN_00101b59` - Main Loop

```c
// Simplified pseudocode
long lVar2 = nfq_open();  // Open netfilter queue
nfq_bind_pf(lVar2, 2);    // Bind to IPv4 (AF_INET = 2)

// Create queue with callback function
long lVar3 = nfq_create_queue(lVar2, 0, FUN_0010134e, 0);

// Main loop - receive and process packets
while(true) {
    recv(iVar1, auStack_10028, 0x10000, 0);
    nfq_handle_packet(lVar2, auStack_10028, uVar4);
}
```

**What it does**: Uses **Linux Netfilter Queue** to intercept network packets and calls `FUN_0010134e` to process each packet.

#### Function 2: `FUN_0010134e` - Packet Handler (THE IMPORTANT ONE)

This function contains the encryption logic!

##### Part A: Filter for DNS Packets

```c
// Check if IPv4
if ((*local_40[0] & 0xf0) != 0x40) {
    return nfq_set_verdict(...);  // Skip if not IPv4
}

// Check if UDP (protocol 17 = 0x11)
if (local_40[0][9] != 0x11) {
    return nfq_set_verdict(...);  // Skip if not UDP
}

// Check if destination port is 53 (DNS)
if (puVar13[1] != 0x3500) {  // 0x3500 = port 53 in network byte order
    return nfq_set_verdict(...);  // Skip if not DNS
}
```

##### Part B: Extract Key Components

```c
// Extract DNS transaction ID
bVar2 = *(byte *)(puVar13 + 4);
bVar3 = *(byte *)((long)puVar13 + 9);
uVar24 = *puVar13;

// Combine into key structure
local_750 = CONCAT22(CONCAT11(bVar2, bVar3), uVar24 << 8 | uVar24 >> 8);
```

This creates a **4-byte key** from DNS metadata!

##### Part C: THE ENCRYPTION LOOP

```c
do {
    bVar2 = local_748[lVar26];  // Label length
    lVar20 = local_648[lVar26];  // Label data pointer
    
    uVar16 = 0;
    do {
        // THIS IS THE ENCRYPTION!
        sprintf((char *)((long)&local_6c8 + uVar16 * 2), "%02X",
                (ulong)(*(byte *)((long)&local_750 + (ulong)((uint)uVar16 & 3)) ^
                       *(byte *)(lVar20 + uVar16)));
        uVar16 = uVar16 + 1;
    } while (bVar2 != uVar16);
    
    lVar26 = lVar26 + 1;
} while (lVar26 != lVar17);
```

**Breaking down the encryption line:**

```c
sprintf(..., "%02X",  // Format as 2-digit uppercase hex
    
    *(byte *)((long)&local_750 + (ulong)((uint)uVar16 & 3))
    // ↑ Get byte from 4-byte key, cycling through bytes 0,1,2,3
    // (uVar16 & 3) is modulo 4: 0,1,2,3,0,1,2,3...
    
    ^  // XOR operator!
    
    *(byte *)(lVar20 + uVar16)
    // ↑ Get byte from domain label
)
```

---

## The Encryption Scheme

### Key Generation

The key is derived from **DNS packet metadata**:

```python
key = (dns_id << 16) | source_port
```

**Visual representation:**

```
DNS_ID = 0x5010 (16 bits)
Source Port = 0x1234 (16 bits)

Step 1: Shift DNS_ID left 16 bits
0x5010 << 16 = 0x50100000

Binary:
Before: 0101 0000 0001 0000
After:  0101 0000 0001 0000 0000 0000 0000 0000
        └─────DNS_ID─────┘ └──empty 16 bits──┘

Step 2: OR with source port
0x50100000 | 0x1234 = 0x50101234

        0101 0000 0001 0000 0000 0000 0000 0000
OR      0000 0000 0000 0000 0001 0010 0011 0100
        ─────────────────────────────────────────
        0101 0000 0001 0000 0001 0010 0011 0100
        └─────DNS_ID─────┘ └───Source Port───┘

Result: 0x50101234 (4-byte key)
```

### Converting to Key Bytes (Little Endian)

```python
key_bytes = key.to_bytes(4, 'little')

0x50101234 becomes: [0x34, 0x12, 0x10, 0x50]
                      ↑     ↑     ↑     ↑
                     byte0 byte1 byte2 byte3
```

### Encryption Process

```
For domain "google.com":

Labels: ["google", "com"]

For each label:
  For each byte in label:
    encrypted_byte = byte XOR key_bytes[i % 4]
    hex_string += sprintf("%02X", encrypted_byte)

Example for "google":
'g' (0x67) XOR key_bytes[0] (0x34) = 0x53 → "53"
'o' (0x6F) XOR key_bytes[1] (0x12) = 0x7D → "7D"
'o' (0x6F) XOR key_bytes[2] (0x10) = 0x7F → "7F"
'g' (0x67) XOR key_bytes[3] (0x50) = 0x37 → "37"
'l' (0x6C) XOR key_bytes[0] (0x34) = 0x58 → "58"
'e' (0x65) XOR key_bytes[1] (0x12) = 0x77 → "77"

Encrypted: "537D7F375877"
```

### Why This Key System?

1. ✅ **Available**: Both DNS_ID and source_port are in every DNS packet
2. ✅ **Dynamic**: Changes for each query (different key every time!)
3. ✅ **Extractable**: The receiver can get these values from the packet
4. ✅ **Stealthy**: Makes encrypted domains look random

---

## Writing the Decryption Script

### Complete Script

```python
import struct

def iter_pcap_records(buf):
    """Parse PCAP file and yield individual packets"""
    magic = struct.unpack("<I", buf[:4])[0]
    endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
    off = 24  # Skip PCAP global header
    
    while off + 16 <= len(buf):
        # Read packet header (timestamp, lengths)
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian+"IIII", buf[off:off+16])
        off += 16
        
        # Read packet data
        pkt = buf[off:off+incl_len]
        off += incl_len
        yield pkt

def parse_eth(pkt):
    """Parse Ethernet frame, return type and payload"""
    if len(pkt) < 14: return None
    etype = struct.unpack("!H", pkt[12:14])[0]
    return etype, pkt[14:]

def parse_ipv4(pkt):
    """Parse IPv4 header"""
    if len(pkt) < 20: return None
    vihl = pkt[0]
    ver = vihl >> 4  # IP version (should be 4)
    ihl = (vihl & 0x0F) * 4  # Header length in bytes
    
    if ver != 4 or len(pkt) < ihl: return None
    
    total_len = struct.unpack("!H", pkt[2:4])[0]
    proto = pkt[9]  # Protocol number (17 = UDP)
    
    return ihl, total_len, proto, pkt[ihl:total_len]

def parse_udp(pkt):
    """Parse UDP header and extract source/dest ports"""
    if len(pkt) < 8: return None
    sport, dport, length, csum = struct.unpack("!HHHH", pkt[:8])
    payload = pkt[8: length] if length <= len(pkt) else pkt[8:]
    return sport, dport, payload

def parse_dns_name(payload, offset):
    """Parse DNS domain name into labels"""
    labels = []
    while True:
        l = payload[offset]  # Length of next label
        offset += 1
        
        if l == 0:  # End of domain name
            break
        
        label = payload[offset:offset+l]
        labels.append(label)
        offset += l
    
    return labels, offset

def decode_label(enc_label, key_bytes):
    """Decrypt a single domain label"""
    s = enc_label.decode("ascii")  # "ABDABF03A0D0"
    enc = bytes.fromhex(s)  # Convert hex string to bytes
    
    # XOR decrypt with repeating 4-byte key
    out = bytes(b ^ key_bytes[i % 4] for i, b in enumerate(enc))
    return out

def decode_qname(labels, dnsid, sport):
    """Decrypt entire domain name"""
    # Generate the 4-byte XOR key
    key_val = (dnsid << 16) | sport
    key_bytes = key_val.to_bytes(4, "little")
    
    # Decrypt each label
    dec = [decode_label(l, key_bytes) for l in labels]
    
    # Join with dots
    return b".".join(dec).decode()

# ============= MAIN SCRIPT =============

pcap = open("traffic.pcap", "rb").read()
domains = []

for pkt in iter_pcap_records(pcap):
    # Parse Ethernet frame
    eth = parse_eth(pkt)
    if not eth: continue
    etype, rest = eth
    if etype != 0x0800: continue  # Only IPv4
    
    # Parse IPv4 packet
    ip = parse_ipv4(rest)
    if not ip: continue
    ihl, total_len, proto, ip_payload = ip
    if proto != 17: continue  # Only UDP
    
    # Parse UDP packet
    udp = parse_udp(ip_payload)
    if not udp: continue
    sport, dport, udppayload = udp
    if dport != 53: continue  # Only DNS (port 53)
    
    # Parse DNS header
    if len(udppayload) < 12: continue
    dnsid, flags, qdcount, *_ = struct.unpack("!HHHHHH", udppayload[:12])
    
    # Skip DNS responses or queries with no questions
    if (flags & 0x8000) != 0 or qdcount == 0:
        continue
    
    # Parse and decrypt domain name
    labels, off = parse_dns_name(udppayload, 12)
    
    try:
        decrypted = decode_qname(labels, dnsid, sport)
        domains.append(decrypted)
        print(decrypted)
    except:
        pass

# Find flag pieces
print("\n=== FLAG PIECES (.ro domains) ===")
for d in domains:
    if d.endswith(".ro") and any(c in d for c in "{}_"):
        print(d)
```

### Running the Script

```bash
$ python3 exploit.py
example.com
mobile.events.data.microsoft.com
mobile.events.data.microsoft.com
google.com
github.com
cloudflare.com
openai.com
wikipedia.org
...
nullctf{dns_.ro
...
is_br0k3n_.ro
...
why_is_i7.ro
...
_4lw4ys_dns}.ro

=== FLAG PIECES (.ro domains) ===
nullctf{dns_.ro
is_br0k3n_.ro
why_is_i7.ro
_4lw4ys_dns}.ro
```

---

## Getting the Flag

### Assembling the Flag Pieces

The flag pieces are in the `.ro` domains:

```
nullctf{dns_.ro       → Remove .ro → nullctf{dns_
is_br0k3n_.ro         → Remove .ro → is_br0k3n_
why_is_i7.ro          → Remove .ro → why_is_i7
_4lw4ys_dns}.ro       → Remove .ro → _4lw4ys_dns}
```

Join them together:

```
nullctf{dns_is_br0k3n_why_is_i7_4lw4ys_dns}
```

**Final Flag**: `nullctf{dns_is_br0k3n_why_is_i7_4lw4ys_dns}`

---

## Key Takeaways

### What We Learned

1. **Linux Netfilter Queue**: Used to intercept and modify network packets
2. **DNS Packet Structure**: Understanding headers, fields, and domain encoding
3. **XOR Cipher**: Simple but effective encryption when key is unknown
4. **Dynamic Key Generation**: Using packet metadata (DNS_ID, source_port) as encryption key
5. **Network Protocol Analysis**: Parsing Ethernet → IP → UDP → DNS layers
6. **Reverse Engineering Process**: Static analysis (Ghidra) → Understanding algorithm → Writing decoder

### Skills Developed

- ✅ Reading and understanding decompiled C code
- ✅ Parsing binary network protocols
- ✅ Understanding bitwise operations (XOR, shifts, AND, OR)
- ✅ Cryptanalysis of custom encryption schemes
- ✅ PCAP analysis with tshark/Wireshark and Python

### CTF Methodology

**Without a writeup, you would:**

1. **Static Analysis**: Disassemble binary in Ghidra/IDA
   - Look for crypto operations (XOR, shifts)
   - Identify network functions (socket, sendto, recvfrom)
   - Find key generation code

2. **Dynamic Analysis**: Run binary with monitoring
   - Capture traffic with tcpdump/Wireshark
   - Use debugger (GDB) to inspect values at runtime
   - Set breakpoints on suspicious functions

3. **Pattern Recognition**: 
   - Notice hex-encoded domains
   - Realize encryption must be reversible
   - Identify what changes between packets (DNS_ID, ports)

4. **Hypothesis Testing**:
   - Try different key generation methods
   - Test decryption on sample domains
   - Verify results make sense

5. **Solution Development**:
   - Write parser for PCAP
   - Implement decryption algorithm
   - Extract and assemble flag

---

## Common Confusions Explained

### Q1: "I understand XOR, but why do we need a KEY?"

**Answer**: 

XOR by itself is just: `A XOR B = C`

Without a key, anyone can reverse it if they know what operation was used. The **key** is what makes it secure:

```
Without key:
'A' XOR 'B' = 0x03  ← Anyone can figure this out

With secret key:
'A' XOR 0x12 = 0x53  ← Can't reverse without knowing 0x12 is the key!
```

The key is the **secret** that only the sender and receiver know.

### Q2: "How do we know to use (dns_id << 16) | sport as the key without the writeup?"

**Answer**:

You discover this by **reverse engineering the binary**:

1. **In Ghidra**, you see this code:
   ```c
   local_750 = CONCAT22(CONCAT11(bVar2,bVar3), uVar24 << 8 | uVar24 >> 8);
   ```

2. You trace where these variables come from:
   - `bVar2`, `bVar3` → extracted from DNS/UDP header
   - `uVar24` → DNS transaction ID

3. You see `local_750` is used in the XOR operation:
   ```c
   *(byte *)((long)&local_750 + (ulong)((uint)uVar16 & 3))
   ```

4. You recognize this pattern: combining two 16-bit values into one 32-bit key

5. You test your hypothesis by writing a decoder and checking if output makes sense

### Q3: "What is `(uVar16 & 3)` doing?"

**Answer**:

This is **modulo 4** using bitwise AND:

```
& 3 is the same as % 4 (but faster)

uVar16 = 0:  0 & 3 = 0  (binary: 0000 & 0011 = 0000)
uVar16 = 1:  1 & 3 = 1  (binary: 0001 & 0011 = 0001)
uVar16 = 2:  2 & 3 = 2  (binary: 0010 & 0011 = 0010)
uVar16 = 3:  3 & 3 = 3  (binary: 0011 & 0011 = 0011)
uVar16 = 4:  4 & 3 = 0  (binary: 0100 & 0011 = 0000) ← wraps!
uVar16 = 5:  5 & 3 = 1  (binary: 0101 & 0011 = 0001)
...
```

This cycles through key bytes: `key[0], key[1], key[2], key[3], key[0], key[1], ...`

### Q4: "Why little-endian for key_bytes?"

**Answer**:

Little-endian stores the **least significant byte first**:

```python
key = 0x50101234

Big-endian:    [0x50, 0x10, 0x12, 0x34]  (most significant first)
Little-endian: [0x34, 0x12, 0x10, 0x50]  (least significant first)
```

The binary code accesses the key like this:
```c
*(byte *)((long)&local_750 + offset)
```

This reads bytes in memory order. Since x86-64 is little-endian, the bytes are stored as `[0x34, 0x12, 0x10, 0x50]`.

### Q5: "How do we know which domains contain the flag?"

**Answer**:

After decrypting all domains, you look for **anomalies**:

```
example.com          ← Normal
google.com           ← Normal
mobile.events...     ← Normal
nullctf{dns_.ro      ← SUSPICIOUS! Has { and .ro
is_br0k3n_.ro        ← SUSPICIOUS! Flag-like
```

Characteristics of flag domains:
- End with unusual TLD (`.ro` instead of common ones)
- Contain flag format characters: `{`, `}`, `_`
- Look like partial flag pieces

### Q6: "What if the writeup didn't exist?"

**Answer**: The investigation process would be:

```
1. Run strings on binary → Find clues
2. Disassemble in Ghidra → Find XOR + key generation
3. Identify packet interception (netfilter functions)
4. Run binary + capture traffic → See hex domains
5. Find where key comes from in code
6. Write decoder based on understanding
7. Test decoder on samples
8. Decrypt all domains → find flag
```

**Time estimate**: 4-8 hours for an experienced CTF player, 10-20 hours for beginners.

---

## Additional Resources

### Tools Used

- **Ghidra**: https://ghidra-sre.org/
- **Wireshark**: https://www.wireshark.org/
- **tshark**: Command-line Wireshark
- **Python struct**: https://docs.python.org/3/library/struct.html

### Learning Resources

- **XOR Cipher**: https://en.wikipedia.org/wiki/XOR_cipher
- **DNS Protocol**: https://www.ietf.org/rfc/rfc1035.txt
- **Netfilter Queue**: https://netfilter.org/projects/libnetfilter_queue/
- **Binary Analysis**: "Practical Binary Analysis" by Dennis Andriesse

### Similar Challenges

Look for CTF challenges tagged with:
- Network protocol manipulation
- DNS exfiltration
- XOR encryption
- Packet capture analysis
- Custom encryption schemes

---

## Conclusion

This challenge demonstrates how **custom encryption**, **network protocol manipulation**, and **reverse engineering** combine to create an interesting CTF problem. The key insights were:

1. Recognizing hex-encoded domains in PCAP
2. Reverse engineering the binary to find XOR encryption
3. Understanding dynamic key generation from packet metadata
4. Writing a parser to extract and decrypt all domains
5. Identifying flag pieces among decrypted results

The challenge teaches important skills in **network security**, **cryptanalysis**, and **binary reverse engineering** that are fundamental to cybersecurity work.

---
