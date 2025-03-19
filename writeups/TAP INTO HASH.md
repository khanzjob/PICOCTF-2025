
### **Write-up: Tap into Hash (picoCTF 2024)**

#### **Challenge Details**

- **Name:** Tap into Hash
- **Category:** Cryptography
- **Points:** 200
- **Author:** NGIRIMANA Schadrack

#### **Challenge Description**

> Can you make sense of this source code file and write a function that will decode the given encrypted file content?  
> Find the encrypted file here. It might be good to analyze the source file to get the flag.

We are given a Python script (`deep.py`) that contains encryption and decryption logic. The goal is to reverse the encryption process and extract the flag.

---

## **Step 1: Analyzing the Given Script**

The script uses **SHA-256 hashing** and **XOR encryption** for encoding the flag. Let's break it down.
```
import hashlib

def decrypt(ciphertext, key):
    # Compute the SHA-256 hash of the key
    key_hash = hashlib.sha256(key).digest()
    
    # Decrypt the ciphertext using XOR
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted_block = xor_bytes(block, key_hash)
        plaintext += decrypted_block
    
    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    
    return plaintext.decode('utf-8')

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

```

### **Key Observations**

- The function `decrypt()` **computes the SHA-256 hash** of the key and then XORs the encrypted data with it.
- The `xor_bytes()` function performs **byte-wise XOR**.
- After decryption, **padding** is removed from the output.

---

## **Step 2: Extracting Key and Encrypted Data**

The script also provides:

- A **key** (`key` variable).
- The **encrypted flag data** (`encrypted_blockchain` variable).

### **Key (from the script)**


`key=b'\x1d,\x18.\x8a\xe7vt>j\xfb)s\xc4W\xcdD\x83\xa7\xf0\xdfQS\xd7\xec5=zw\x8e(\xec'`

### **Encrypted Flag (from the script)**

`encrypted_blockchain = b'\xdf\x97\xc6\x10k\x00#BN\xbc%\x96\xc8b\'\xc0\x8b\xc9\x96Gk...'`

---

## **Step 3: Running the Decryption Script**

By executing the provided script (`deep.py`), the decryption process runs successfully:


`python3 deep.py`

### **Decryption Output**
![[Pasted image 20250313235211.png]]

`Decrypted Blockchain: f82dc16ad052440c2fb3c6b4035e5dad28d697ec40a3517d44225fb0fe03498e-0050c42901e09c08e3ceb3bbb02e6e404640c6b4e0746b05fc339886449c6c97-009c76cb0cae2a7921bca75313920b71picoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_8bb7bc38}565779e7be6dc1cfc3024ba71ab4b3de-008d7d0b388a3b4bed873ac3965d6841fb03e65cf8bb0517458369e449da694e-00c3e1aaa7e2e6ee980b50ec0061b576e55e1cbcccf50c1b9492dccc764beca2`

Inside this decrypted data, we find the **flag:**


`picoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_8bb7bc38}`

---

## **Step 4: Final Flag**


`picoCTF{block_3SRhViRbT1qcX_XUjM0r49cH_qCzmJZzBK_8bb7bc38}`

---

## **Lessons Learned**

✅ **XOR Encryption**: The encryption was based on XOR operations, which are reversible.  
✅ **SHA-256 Hashing**: The encryption used a SHA-256 hash of the key before applying XOR.  
✅ **Padding Removal**: The decryption step involved removing the padding from the plaintext.  
✅ **Python Byte Manipulation**: Understanding `bytes` operations (`xor_bytes()`) was crucial for solving this challenge.

---

### **Alternative Approach**

If we did not have direct access to the script, we could have:

1. **Analyzed the encryption pattern** by comparing input-output pairs.
2. **Brute-forced potential keys** based on the encryption mechanism.
3. **Reimplemented decryption manually** using XOR operations.

---

### **Conclusion**

This challenge was a **great exercise in cryptographic analysis** and **reversing custom encryption** schemes. 🚀