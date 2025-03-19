

## **Write-up: RED (picoCTF 2024)**

### **Challenge Details**

- **Name:** RED
- **Category:** Forensics
- **Points:** 100
- **Author:** Shuailin Pan (LeConjuror)

### **Challenge Description**

> RED, RED, RED, RED  
> Download the image: `red.png`

---

## **Step 1: Analyzing the Image**

Since the challenge name and description emphasize "RED," it suggests that the image may contain **hidden data** embedded within the color channels or metadata.

To extract hidden information, we used `zsteg`, a tool for **analyzing LSB (Least Significant Bit) steganography** in PNG images.

bash

CopyEdit

`zsteg red.png`

### **zsteg Output Analysis**

pgsql

CopyEdit

`meta Poem           .. text: "Crimson heart, vibrant and bold, Hearts flutter at your sight. Evenings glow softly red, Cherries burst with sweet life. Kisses linger with your warmth. Love deep as merlot. Scarlet leaves falling softly, Bold in every stroke."  b1,rgba,lsb,xy      .. text: "cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ=="`

- The **meta** section contains a **poem** that describes the color red, which is likely a red herring.
- The **b1,rgba,lsb,xy** section contains **Base64-encoded** text.

---
![[Pasted image 20250313235558.png]]
## **Step 2: Decoding the Hidden Message**

From the `zsteg` output, we extracted the **Base64-encoded** text:

bash

CopyEdit

`echo "cGljb0NURntyM2RfMXNfdGgzX3VsdDFtNHQzX2N1cjNfZjByXzU0ZG4zNTVffQ==" | base64 -d`

### **Decoded Output:**

CopyEdit

`picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`

---

## **Final Flag**

CopyEdit

`picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}`

---

## **Lessons Learned**

✅ **Steganography in PNG Files**: The challenge involved extracting hidden data using **LSB encoding** in the **RGBA color channels**.  
✅ **Base64 Encoding**: The hidden message was encoded in Base64, a common technique in CTF challenges.  
✅ **zsteg for Steganalysis**: `zsteg` is a powerful tool to detect and extract LSB-encoded hidden text in PNG files.

---

## **Conclusion**

This challenge was an easy steganography problem that required **basic forensic analysis** of an image file. By using `zsteg` and decoding Base64, we successfully extracted the flag. 🚀