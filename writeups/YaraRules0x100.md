![[Pasted image 20250311150313.png]]
# Detecting a Suspicious Executable with YARA

## Challenge Overview

We encountered a suspicious executable file on an employee’s Windows machine. The file bypassed our **Intrusion Detection System (IDS)**, suggesting it was a **new or modified threat** with no existing signatures in our database. Our goal was to analyze the file and create a **YARA rule** to detect similar threats in the future.

## Analysis of the Suspicious File

To analyze the sample, we performed the following steps:

1. **Unzipped the archive** using the provided password: `picoctf`.
    
2. **Checked the file signature** and discovered that it had an `MZ` header, indicating a Windows **PE (Portable Executable)** file.
    
3. **Extracted common malware indicators**, such as:
    
    - **UPX packing** (`UPX0`, `UPX1`, `UPX!`) – Often used for obfuscation.
        
    - **Suspicious function calls**, including:
        
        - `IsDebuggerPresent` (Anti-debugging technique)
            
        - `CreateThread` (Possible multi-threaded execution for evasion)
            
        - `TerminateProcess` (Potentially used to kill security tools)
            
4. **Checked file size** – The file was under **400KB**, typical for small malware executables.
    

## Developing the YARA Rule

Based on our findings, we crafted the following **YARA rule** to detect similar threats:

```
rule SuspiciousExecutable_DarkGate {
    meta:
        description = "GIVE ME THE DAMN FLAG!"
        author = "meowmeownigga"
        date = "2025-03-11"
        hash = "1be9a04fe2e40e8f8244b860ec855df5e491603d2cc87382972a4729e54e7925"

    strings:
        $s2 = "okITOo" ascii wide nocase
        $s3 = "UPX0" ascii
        $s4 = "UPX1" ascii
        $s5 = "This program cannot be run in DOS mode" ascii
        $s6 = "GetCurrentProcessId" ascii
        $s7 = "TerminateProcess" ascii
        $s8 = "CreateThread" ascii
        $s9 = "IsDebuggerPresent" ascii
        $s10 = "MultiByteToWideChar" ascii

        $hex1 = {55 50 58 30} // UPX0
        $hex2 = {55 50 58 31} // UPX1
        $hex3 = {55 50 58 21} // UPX!

    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize <= 400KB and
        (
            (6 of ($s*)) or
            (4 of ($s*) and 2 of ($hex*))
        )
}
```

### Breakdown of the Rule

- **Metadata Section:** Includes a description, author, date, and hash value for reference.
    
- **String Indicators:** Detects key **anti-debugging, threading, and process manipulation techniques**.
    
- **Hex Patterns:** Identifies UPX-packed binaries.
    
- **Condition:** Ensures the file:
    
    - Has a valid PE header (`MZ` magic bytes at the start).
        
    - Is within a reasonable file size limit.
        
    - Contains either **six suspicious strings** or a **combination of four strings and two UPX patterns**.
        

## Submitting the Rule

Once the rule was created, we submitted it using:

```
socat -t60 - TCP:standard-pizzas.picoctf.net:57650 < ya.yar
```

### Result

✅ **Status: Passed**  
🎉 **Flag Received:** `picoCTF{yara_rul35_r0ckzzz_fd0e89c7}`

## Conclusion

This challenge demonstrated the importance of **behavior-based malware detection** using YARA rules. By identifying **common obfuscation techniques and suspicious API calls**, we successfully created a signature to detect future threats.

### Next Steps

- **Automate YARA scanning** on endpoints.
    
- **Expand detection capabilities** with sandbox analysis.
    
- **Integrate YARA with SIEM systems** for real-time monitoring.
    

This was a great exercise in **threat intelligence and malware analysis**!