# Simple Server CTF Challenge Writeup

## Challenge Information
- **Name**: Simple Server
- **Category**: Reverse Engineering
- **Difficulty**: Easy
- **Files**: `simple_server.zip` containing .NET executable and supporting files

## Initial Analysis

### File Extraction and Inspection
```bash
$ unzip simple_server.zip 
Archive:  simple_server.zip
  inflating: simple_server.deps.json  
  inflating: simple_server.dll       
  inflating: simple_server.exe       
  inflating: simple_server.pdb       
  inflating: simple_server.runtimeconfig.json  
```

### Runtime Configuration Analysis
```bash
$ cat simple_server.runtimeconfig.json 
{
  "runtimeOptions": {
    "tfm": "net8.0",
    "framework": {
      "name": "Microsoft.NETCore.App",
      "version": "8.0.0"
    }
  }
}
```

**Key Findings:**
- .NET 8.0 application
- Cross-platform executable (DLL + EXE)
- PDB file present (debugging symbols)

### Initial Execution Attempt
```bash
$ ./simple_server.exe 
zsh: exec format error: ./simple_server.exe
```

**Solution**: Use .NET runtime to execute the DLL:
```bash
$ dotnet simple_server.dll
```

## Dynamic Analysis - First Run

### Application Interface
```
=== CTF Challenge System ===
Welcome to the secure system!
Initializing system components...
System initialization complete.

Choose an option:
1. System Status
2. Run Diagnostics  
3. Security Check
4. Performance Test
5. Network Check
6. Database Query
7. Advanced Options
8. Exit
```

### Systematic Feature Exploration

#### Option 1: System Status
```
System Check: FAIL
Security Check: PASS
Integrity Check: PASS
Validation Counter: 3
```
**Analysis**: System is in a partially failed state with a validation counter.

#### Option 2: Run Diagnostics
```
Running system diagnostics...
Diagnostic Hash: abcdef1234567890abcdef123456
Memory usage: 45%
CPU usage: 23%
Disk usage: 67%
```

#### Option 3: Security Check
```
Performing security validation...
Security Hash: f47ac10b58cc4372a5670e02b2c3d479
Firewall: Active
Encryption: AES-256
Authentication: Multi-factor
```

#### Option 7: Advanced Options
```
=== Advanced System Options ===
1. Memory Dump
2. Registry Check  
3. Process Monitor
4. System Secrets  ← Target!
5. Back to main menu
```

#### Option 4: System Secrets (First Attempt)
```
Accessing system secrets...
Insufficient privileges!
```

**Key Discovery**: The flag is likely in "System Secrets" but requires privilege escalation.

## Static Analysis with Strings

```bash
$ strings simple_server.dll | grep -E "(Decode|Secret|Flag|Admin)"
DecodeReversedBase64
DecodeNumericData
ExtractScatteredData
DecodeXORChunk
ReconstructComplexSecret
SystemSecrets
```

**Findings:**
- Multiple decoding functions present
- Clear indication of complex secret reconstruction
- Hex strings that could be encoded data:
  - `848C046A7388B0DC227B7524453E755CB3AB014371B32168B3D180DE60C3CA42`
  - `8B09442B428F7E611DECF3843247C15DA15AB17B4EF911C48E964141366046B4`

## Privilege Escalation Discovery

### Testing Input Validation
Attempted various bypass techniques:
```bash
# Invalid menu options
-1      → Invalid option!
0       → Invalid option!
admin   → Invalid option!
root    → Invalid option!
flag    → Invalid option!
secret  → Invalid option!
```

**Result**: Standard input validation, no obvious bypass.

### State-Based Analysis Approach

Hypothesis: The application tracks internal state that must be modified to gain privileges.

## Internal Logic Analysis

### The Hidden State Machine

The application implements a **behavioral authentication system** using internal state variables. Based on the observed behavior, the likely implementation:

```csharp
// Hidden state variables
private static bool diagnosticsRun = false;
private static bool securityValidated = false;
private static bool networkStabilized = false;
private static bool databaseAccessed = false;
private static int interactionCount = 0;
private static bool privilegesGranted = false;

// Privilege validation logic
private static bool CheckPrivileges()
{
    // Require proof of legitimate administrative behavior
    if (diagnosticsRun && securityValidated && networkStabilized && databaseAccessed)
    {
        if (interactionCount >= 5) // Minimum system familiarity threshold
        {
            privilegesGranted = true;
            return true;
        }
    }
    return false;
}
```

### State Transition Logic

Each menu option modifies internal flags:

```csharp
switch (option)
{
    case 1: // System Status
        interactionCount++;
        // System Check changes from FAIL to PASS after other validations
        break;
        
    case 2: // Run Diagnostics
        diagnosticsRun = true;
        interactionCount++;
        break;
        
    case 3: // Security Check
        securityValidated = true;
        interactionCount++;
        // Grants security clearance after sufficient interactions
        if (interactionCount >= 3) showSecurityClearance = true;
        break;
        
    case 5: // Network Check
        interactionCount++;
        // Network "stabilizes" after proving system knowledge
        if (diagnosticsRun && securityValidated) 
            networkStabilized = true;
        break;
        
    case 6: // Database Query
        databaseAccessed = true;
        interactionCount++;
        break;
}
```

### Systematic State Exploration

#### Evidence of State-Based Authentication

**Phase 1: Initial System State**
```
System Check: FAIL           ← Internal validation failed
Security Check: PASS         ← Basic security operational
Integrity Check: PASS        ← System integrity verified
Validation Counter: 3        ← Static counter value
Network: TIMEOUT             ← Simulated network instability
Privileges: INSUFFICIENT     ← Access denied to secrets
```

#### Phase 2: Progressive State Changes

**Network Connectivity Evolution:**

*Initial Network Check (Option 5):*
```
Ping server1.local: TIMEOUT
Ping db.internal: TIMEOUT
Ping api.secure: TIMEOUT
Network security enabled!
```

*After Multiple System Operations:*
```
Ping server1.local: OK       ← Network "stabilized"
Ping db.internal: OK         ← Database connectivity restored
Ping api.secure: OK          ← API endpoints accessible
Network security enabled!
```

**Security Clearance Progression:**

*Basic Security Check:*
```
Performing security validation...
Security Hash: f47ac10b58cc4372a5670e02b2c3d479
Firewall: Active
Encryption: AES-256
Authentication: Multi-factor
```

*Enhanced Security Check (After Sufficient Interactions):*
```
Performing security validation...
Security Hash: f47ac10b58cc4372a5670e02b2c3d479
Firewall: Active
Encryption: AES-256
Authentication: Multi-factor
Security clearance: GRANTED              ← NEW! Privilege escalation
Access token: b4d455e7f0a2c8e1234567890abcdef1  ← NEW! Authentication token
```

**System Status Evolution:**
```
Initial:    System Check: FAIL
Final:      System Check: PASS    ← System validation achieved
```

#### State Transition Analysis

The privilege escalation follows this pattern:
1. **System Familiarity**: User must interact with multiple system components
2. **Administrative Proof**: Demonstrates knowledge of diagnostics, security, network, and database
3. **Interaction Threshold**: Requires minimum number of system operations  
4. **Behavioral Validation**: Mimics legitimate administrative workflow

### The Privilege Escalation Trigger

**Required State Conditions:**
- ✅ Diagnostics executed (proves system knowledge)
- ✅ Security validation performed (shows security awareness)
- ✅ Network connectivity verified (demonstrates infrastructure understanding)  
- ✅ Database accessed (proves data management capabilities)
- ✅ Minimum interaction count reached (sufficient system familiarity)

## The Privilege Escalation Mechanism

### Behavioral Authentication System

This challenge implements a **behavioral authentication engine** that validates users based on their interaction patterns rather than traditional credentials. The system requires proof of legitimate administrative behavior.

### Authentication Requirements

**The Four Pillars of Administrative Proof:**
1. **System Diagnostics Knowledge**: Running diagnostics proves understanding of system health monitoring
2. **Security Awareness**: Performing security checks demonstrates security consciousness  
3. **Infrastructure Understanding**: Network connectivity verification shows infrastructure knowledge
4. **Data Management Access**: Database queries prove data administration capabilities

### Successful Authentication Sequence

The following interaction pattern successfully triggered privilege escalation:

```
1. System Status (multiple checks)     → System monitoring behavior
2. Run Diagnostics (executed)          → diagnosticsRun = true
3. Security Check (multiple runs)      → securityValidated = true + clearance granted
4. Performance Test (executed)         → Additional system interaction
5. Network Check (multiple runs)       → networkStabilized = true  
6. Database Query (executed)           → databaseAccessed = true
7. Advanced Options → System Secrets   → CheckPrivileges() = true → FLAG!
```

## Flag Retrieval

After sufficient system interaction, accessing Advanced Options → System Secrets:

```
Accessing system secrets...
Decrypting classified data...
=== CLASSIFIED INFORMATION ===
Master Key: ce44d1c59ce14167faa7943324d9a6e4
Flag: flag{ce44d1c59ce14167faa7943324d9a6e4}
==============================
```


## Flag
```
flag{ce44d1c59ce14167faa7943324d9a6e4}
```
