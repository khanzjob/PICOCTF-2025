
# Bitlocker-1 CTF Challenge Write-up

**Challenge Name:** Bitlocker-1  
**Author:** Venax  
**Points:** 200

## Challenge Description:

Jacky is not very knowledgeable about strong security passwords and has used a simple password to encrypt their BitLocker drive. Our objective is to break through the encryption and retrieve the flag.


`python3 john2bitlocker.py bitlocker-1.dd > hash.txt`

This extracts the BitLocker hash from the disk image and saves it in `hash.txt`, which we will use for cracking.
### **Step 1: Download and Mount the Disk Image**

The challenge provides a BitLocker-encrypted disk image. First, we need to mount the image and access its contents.

**Commands executed:**

```
sudo mkdir /mnt/bitlocker
sudo dislocker -V <disk-image> -u"jacky" -- /mnt/bitlocker
```

**Explanation:**

- `dislocker -V <disk-image> -u"jacky"` – Uses the password "jacky" to decrypt the BitLocker image.
    
- `sudo mkdir /mnt/bitlocker` – Creates a directory to mount the decrypted image.
    
- The decrypted content is stored in `dislocker-file` inside `/mnt/bitlocker`.
    

### **Step 2: Extracting Data from the Decrypted File**

Once decrypted, we use the `strings` command to search for the flag in the decrypted file.

**Command executed:**

```
strings dislocker-file | grep pico
```

### **Step 3: Decrypting and Mounting the BitLocker Volume**

With the cracked password, we can now decrypt and mount the BitLocker volume using `dislocker`:


`sudo mkdir /mnt/bitlocker sudo dislocker -V bitlocker-1.dd -ujacqueline -- /mnt/bitlocker`

Here’s what each flag means:

- `-V bitlocker-1.dd` → Specifies the encrypted BitLocker image file.
- `-u jacqueline` → Uses the recovered password (`jacqueline`) to unlock the volume.
- `-- /mnt/bitlocker` → Specifies the mount point.

Once the volume is decrypted, we can mount it:


`sudo mount -o loop /mnt/bitlocker/dislocker-file /mnt/bitlocker2`

Now, we can navigate to `/mnt/bitlocker2` to explore the contents.

---

### **Step 4: Extracting the Flag**

We use the `strings` command to search for the flag inside the decrypted volume:

`strings /mnt/bitlocker/dislocker-file | grep pico`

This revealed the flag:


`picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`

---

### **Conclusion**

Using **john2bitlocker**, **John the Ripper**, and **dislocker**, we successfully cracked the weak password `jacqueline`, decrypted the BitLocker-protected image, and retrieved the **flag**.

### **Final Flag:**

CopyEdit

`picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}`


