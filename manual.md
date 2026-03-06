● Here are the exact commands run in Phase 0, in order:                                                                                                                                                                                       
                                                                                                                                                                                                                                              
  ---                                                                                                                                                                                                                                         
  File listing & identification                                                                                                                                                                                                               
  ls -la /home/xuan/bitsctf/midnight_relay/midnight_relay/                                                                                                                                                                                    
  file /home/xuan/bitsctf/midnight_relay/midnight_relay/*                                                                                                                                                                                     
                                                                                                                                                                                                                                              
  Protections
  checksec --file=/home/xuan/bitsctf/midnight_relay/midnight_relay/midnight_relay

  Libc version + one_gadgets
  strings /home/xuan/bitsctf/midnight_relay/midnight_relay/libc.so.6 | grep "GNU C Library"
  one_gadget /home/xuan/bitsctf/midnight_relay/midnight_relay/libc.so.6

  Win/flag/shell functions + PLT checks
  objdump -t midnight_relay | grep -iE "win|flag|shell|secret"
  objdump -d midnight_relay | grep -E "system|execve"
  strings midnight_relay | grep -E "/bin/sh|flag|system|exec"
  ROPgadget --binary midnight_relay | grep "pop rdi"

  Section + segment layout
  readelf -S /home/xuan/bitsctf/midnight_relay/midnight_relay/midnight_relay
  readelf -l /home/xuan/bitsctf/midnight_relay/midnight_relay/midnight_relay

  Run the binary
  echo "quit" | timeout 5 ./midnight_relay_patched 2>&1
  printf '\n\n\n\n\n' | timeout 5 ./midnight_relay_patched 2>&1

  Strings + description
  strings midnight_relay | head -80
  cat description.md
  cat docker-compose.yaml
  cat run

  Full PLT dump
  objdump -d midnight_relay | grep -A5 "plt>"

  All ROP gadgets
  ROPgadget --binary midnight_relay | grep -E "ret|pop rsi|pop rdx|pop rsp"

  Symbol table
  nm midnight_relay

  rodata dump
  objdump -s -j .rodata midnight_relay

  Existing solve + flag + Dockerfile
  cat solve.py
  cat flag.txt
  cat Dockerfile
  grep -r "bitsctf|nc |netcat|remote|host" . --include="*.md" --include="*.txt" --include="*.py"
