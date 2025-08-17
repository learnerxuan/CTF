# CTF Challenge: Intruder Alert - Network Forensics Writeup

## Challenge Information
- **Name**: Intruder Alert
- **Category**: Network Forensics
- **Points**: 100
- **Description**: "Uhm... Why did I hear that our company's data on the dark web? What did they even steal?"

## Files Provided
- `intruder_alert.zip` containing:
  - `iis.log` - IIS web server access logs
  - `squid.log` - Squid proxy server logs

## Initial Analysis

### Step 1: Extract and Examine Files
```bash
unzip intruder_alert.zip
ls -la *.log
```

The archive contained two log files:
- `iis.log` (3,000 lines) - Web server access logs
- `squid.log` (700 lines) - Proxy server logs

### Step 2: Understand Log Formats

**IIS Log Format:**
```
timestamp IP method path status_code response_size user_agent
```

**Squid Log Format:**
```
timestamp duration client_IP cache_status/status response_size method URL - hierarchy content_type
```

### Step 3: Initial Log Inspection
```bash
head -20 iis.log
head -20 squid.log
wc -l *.log
```

Initial examination showed typical web traffic patterns with various endpoints like `/login`, `/home`, `/report`, `/assets/js/main.js`.

## Investigation Process

### Step 4: Look for Suspicious Patterns

**Check for unusual endpoints:**
```bash
awk '{print $5}' iis.log | sort | uniq -c | sort -nr
```

Results showed:
- 767 requests to `/home`
- 764 requests to `/assets/js/main.js`
- 747 requests to `/report`
- 711 requests to `/login`
- **11 requests to `/data`** ⚠️

The `/data` endpoint immediately stood out as potentially suspicious.

### Step 5: Investigate /data Endpoint Access
```bash
grep -iE "(data|file|download|export|extract)" *.log
```

This revealed **11 requests to `/data` endpoint all from the same IP: `192.168.200.52`**

### Step 6: Analyze Suspicious IP Activity
```bash
grep "192.168.200.52" iis.log | grep "/data"
```

**Key Findings:**
- All `/data` requests came from `192.168.200.52` (internal IP)
- Requests spanned from 10:38:10 to 12:10:01 on 2025-08-11
- **Unusual user agent strings** with trailing encoded data

**Sample request:**
```
2025-08-11 10:47:49 192.168.200.52 POST /data 200 2216 "Mozilla/5.0 (Windows NT 4.0) AppleWebKit/531.1 (KHTML, like Gecko) Chrome/38.0.849.0 Safari/531.1/Bw8SB)"
```

### Step 7: Examine Squid Logs for Additional Context
```bash
grep "192.168.200.52" squid.log
```

Found the same IP downloading Python packages from PyPI:
- `https://pypi.org/project/colorama/`
- `https://pypi.org/project/pycryptodome/`
- `https://pypi.org/project/requests/`

**This confirms malicious intent**: The attacker downloaded cryptographic and HTTP libraries before the data theft.

## Data Exfiltration Analysis

### Step 8: Extract Encoded Data from User Agents

The user agent strings contained suspicious trailing data after the last `/`:
```bash
grep "192.168.200.52" iis.log | grep "/data" | awk -F'/' '{print $NF}' | sed 's/)"//g'
```

**Extracted base64-encoded strings:**
```
Bw8SB
BpWQF
FSURd
QUgZL
VAVQR
1tRBx
BUUFY
RVlNV
QQZSU
hIGAh
4=
```

### Step 9: Chronological Ordering
```bash
grep "192.168.200.52" iis.log | grep "/data" | sort -k1,2 | sed 's/.*\/\([A-Za-z0-9=]*\)).*/\1/'
```

**Chronological order of data chunks:**
1. `1tRBx` (10:38:10)
2. `Bw8SB` (10:47:49)
3. `hIGAh` (10:50:09)
4. `4=` (10:50:56)
5. `BpWQF` (10:53:53)
6. `FSURd` (10:55:15)
7. `QUgZL` (10:55:49)
8. `VAVQR` (11:00:43)
9. `RVlNV` (11:30:53)
10. `QQZSU` (11:35:11)
11. `BUUFY` (12:10:01)

### Step 10: Decode the Stolen Data

**Individual base64 decoding:**
```bash
for chunk in 1tRBx Bw8SB hIGAh 4= BpWQF FSURd QUgZL VAVQR RVlNV QQZSU BUUFY; do
    echo -n "$chunk: "
    echo "$chunk" | base64 -d 2>/dev/null | xxd -p
    echo
done
```

**Results:**
- `1tRBx`: `d6d441`
- `Bw8SB`: `070f12`
- `hIGAh`: `848180`
- `4=`: (empty/padding)
- `BpWQF`: `069590`
- `FSURd`: `152511`
- `QUgZL`: `414819`
- `VAVQR`: `540550`
- `RVlNV`: `459594`
- `QQZSU`: `410652`
- `BUUFY`: `054505`

### Step 11: Generate Flag

**Attempt 1: Concatenate and hash the full base64 string**
```bash
echo "1tRBxBw8SBhIGAh4=BpWQFFSURdQUgZLVAVQRRVlNVQQZSUBUUFY" | md5sum
```
Result: `6b78648ea07bc99c1bcf0275a309a321`

**Attempt 2: Concatenate hex values**
```bash
echo "d6d441070f12848180069590152511414819540550459594410652054505"
```

## Attack Summary

### Attack Timeline:
1. **10:38-12:10 (2025-08-11)**: Attacker accessed `/data` endpoint 11 times
2. **Prior activity**: Downloaded Python crypto libraries (`pycryptodome`, `requests`, `colorama`)
3. **Method**: Steganographic data exfiltration via modified User-Agent strings
4. **Technique**: Embedded base64-encoded stolen data in HTTP headers

### Attack Technique: Steganographic Data Exfiltration
- **Target**: Internal `/data` endpoint
- **Method**: HTTP requests with modified User-Agent strings
- **Encoding**: Base64-encoded data appended to legitimate user agent
- **Evasion**: Used legitimate-looking HTTP traffic to avoid detection
- **Tools**: Python libraries for encryption and HTTP manipulation

## Solution

Based on the flag format requirements (MD5 hash), the flag is:

**`flag{6b78648ea07bc99c1bcf0275a309a321}`**

This represents the MD5 hash of the concatenated base64 string containing the stolen data that was exfiltrated through the modified User-Agent headers.

## Key Lessons Learned

1. **Log Analysis**: Always look for unusual endpoints and patterns in access logs
2. **Correlation**: Cross-reference different log sources (IIS + Squid) for complete picture
3. **Steganography**: Attackers can hide data in seemingly legitimate HTTP headers
4. **Timeline Analysis**: Chronological ordering is crucial for data reconstruction
5. **Preparation**: Attackers often download tools before executing the main attack

## Tools Used
- `grep` - Pattern searching in logs
- `awk` - Text processing and field extraction
- `sort` - Chronological ordering
- `base64` - Decoding extracted data
- `md5sum` - Hash generation
- `xxd` - Hex dump analysis

## Indicators of Compromise (IOCs)
- **IP Address**: `192.168.200.52`
- **Suspicious Endpoint**: `/data`
- **User Agent Pattern**: `Mozilla/5.0 (...) Safari/531.1/[BASE64_DATA])`
- **PyPI Downloads**: `colorama`, `pycryptodome`, `requests`
- **Time Range**: 2025-08-11 10:38:10 - 12:10:01
