
# PicoCTF 2024: Guess My Cheese (Part 2) Write-up
![[Pasted image 20250316135350.png]]
## Challenge Description

	We are given a challenge where a remote server provides us with a SHA-256 hash of a cheese name that has been salted. Our task is to reverse this process by identifying the original cheese name and the salt used, and then submit them to retrieve the flag.

The salt is a **single byte (0x00 to 0xFF)** and can be **prepended or appended** to the cheese name before hashing.

## Approach

### 1. **Understanding the Hashing Mechanism**

- The server provides a SHA-256 hash of a **cheese name + salt**.
    
- The salt is a **1-byte (2 hexadecimal digits)** and can be either **prepended or appended**.
    
- We need to identify the correct cheese name and the exact salt used.
    

### 2. **Generating a Hash Map for Quick Lookup**

To efficiently reverse the hash, we **precompute hashes** for all cheese names with all possible salt values (both prepended and appended). This allows for **constant-time lookup** when we receive a hash from the server.

### 3. **Steps Taken**

1. **Load the cheese names** from a given file (`cheese_list.txt`).
    
2. **Generate all possible case variations** (lowercase, uppercase, title case) to account for formatting differences.
    
3. **Compute SHA-256 hashes** for:
    
    - Salt prepended (`sha256(salt + cheese)`).
        
    - Salt appended (`sha256(cheese + salt)`).
        
4. **Store the computed hashes in a dictionary (**`**hash_map**`**)**.
    
5. **Interact with the server**, retrieve the target hash, and find a match from our hash map.
    
6. **Send the correct cheese name and salt** back to the server to retrieve the flag.
    

---

## **Solve Script (solv.py)**

```
import hashlib
from pwn import *

def load_cheeses(filename):
    with open(filename, 'r') as file:
        cheeses = [line.strip() for line in file if line.strip()]
    return cheeses

def generate_hash_map(cheeses):
    hash_map = {}
    for cheese_var in cheeses:
        variations = {cheese_var, cheese_var.lower(), cheese_var.upper(), cheese_var.title()}
        for variation in variations:
            cheese_bytes = variation.encode('utf-8')
            for salt_int in range(256):
                salt_hex = "{:02x}".format(salt_int)
                salt_bytes = bytes.fromhex(salt_hex)
                prepended_hash = hashlib.sha256(salt_bytes + cheese_bytes).hexdigest()
                hash_map[prepended_hash] = (variation, salt_hex, "prepended")
                appended_hash = hashlib.sha256(cheese_bytes + salt_bytes).hexdigest()
                hash_map[appended_hash] = (variation, salt_hex, "appended")
    return hash_map

def find_cheese(target_hash, hash_map):
    return hash_map.get(target_hash, (None, None, None))

def main():
    cheeses = load_cheeses('cheese_list.txt')
    log.info(f"Loaded {len(cheeses)} cheeses from cheese_list.txt")
    
    log.info("Generating hash map with 1-byte salt and variations...")
    hash_map = generate_hash_map(cheeses)
    log.info(f"Generated hash map with {len(hash_map)} entries")
    
    conn = remote('verbal-sleep.picoctf.net', 54455, timeout=5)
    log.info("Connected to the server")
    
    conn.sendlineafter(b"What would you like to do?", b'g')
    conn.recvuntil(b"cheese:  ")
    target_hash = conn.recvline().strip().decode()
    log.info(f"Target hash: {target_hash}")
    
    cheese, salt, position = find_cheese(target_hash, hash_map)
    
    if cheese is None:
        log.error("Failed to find matching cheese and salt!")
        conn.close()
        return
    log.success(f"Found cheese: '{cheese}' with salt: {salt} ({position})")
    
    conn.sendlineafter(b"cheese?", cheese.encode())
    conn.sendlineafter(b"salt?", salt.encode())
    
    response = conn.recvline(timeout=5).decode()
    log.info(f"Server response: {response}")
    
    if "picoCTF" in response:
        log.success(f"Flag: {response.strip()}")
    else:
        extra_response = conn.recvall(timeout=5).decode()
        if "picoCTF" in extra_response:
            log.success(f"Flag: {extra_response.strip()}")
        else:
            log.warning("Flag not found in server response.")
    
    conn.close()

if __name__ == "__main__":
    main()
```

---

## **Optimization Ideas**

1. **Multi-threading**:
    
    - Computing the hash map takes time due to the large number of salt variations.
        
    - Using parallel processing can speed up the hash computation.
        
2. **Precomputed Hash Database**:
    
    - Instead of generating hashes every time, store them in a file for quick lookup.
        
3. **Memory Optimization**:
    
    - The script currently loads all hashes into memory.
        
    - Using a database like SQLite could help manage large hash mappings efficiently.
        

---

## **Flag Retrieval Example**

- After running the script, we receive output like:
- ![[Pasted image 20250316135153.png]]![[Pasted image 20250316135214.png]]
    

```
MUNCH.............
    
    YUM! MMMMmmmmMMMMmmmMMM!!! Yes...yesssss! That's my cheese!
    Here's the password to the cloning room:  picoCTF{cHeEsY68be6a0c}
                                                                           
```

## **Conclusion**

This challenge was an interesting demonstration of **hash cracking with known salts**. By leveraging **precomputed hash mappings**, we were able to efficiently retrieve the correct cheese name and salt, ultimately solving the challenge and obtaining the flag.