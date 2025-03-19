
# Ph4nt0m 1ntrud3r - Challenge Writeup

## Challenge Description
![[Pasted image 20250315215812.png]]

**Points:** 50  
**Author:** Prince Niyonshuti N.

_A digital ghost has breached my defenses, and my sensitive data has been stolen! 😱💻 Your mission is to uncover how this phantom intruder infiltrated my system and retrieve the hidden flag._

To solve this challenge, we need to analyze the provided PCAP file and track down the attack method. The attacker has cleverly concealed their moves, so we must apply the right filters and use forensic techniques to uncover the flag.

---

## Step 1: Inspecting the PCAP File

The first step is to analyze the given network capture (PCAP) file. A useful approach is to extract readable strings from the file to find potential clues.

We run the `strings` command on the PCAP file:

```
strings network.pcap
```

The output contains several Base64-encoded strings, including:

```
ezF0X3c0cw==O
I+znCJg=O
/9QZRtc=O
uF+2UTs=O
pDW7rkI=O
8esVOK4=O
cGljb0NURg==O
KWEh2jQ=O
BGAVCe8=O
RA+7xFw=O
YmhfNHJfZA==O
CMEx344=O
PGb6oYA=O
uSy5rvo=O
bnRfdGg0dA==O
MTA2NTM4NA==O
xIJPbWg=O
XzM0c3lfdA==O
oDis5T8=O
v2XglLs=O
fQ==O
STneebY=
```

These strings appear to be encoded in Base64.

---

## Step 2: Decoding Base64 Strings

Since Base64 is a common encoding method used to obfuscate data, we decode each string using Python:

```
import base64

encoded_strings = [
    "ezF0X3c0cw==", "I+znCJg=", "/9QZRtc=", "uF+2UTs=", "pDW7rkI=",
    "8esVOK4=", "cGljb0NURg==", "KWEh2jQ=", "BGAVCe8=", "RA+7xFw=",
    "YmhfNHJfZA==", "CMEx344=", "PGb6oYA=", "uSy5rvo=", "bnRfdGg0dA==",
    "MTA2NTM4NA==", "xIJPbWg=", "XzM0c3lfdA==", "oDis5T8=", "v2XglLs=",
    "fQ==", "STneebY="
]

for encoded in encoded_strings:
    try:
        decoded = base64.b64decode(encoded).decode('utf-8')
        print(decoded)
    except Exception as e:
        print(f"Error decoding {encoded}: {e}")
```
![[Pasted image 20250315215433.png]]
The decoded strings include:

```
picoCTF{
1t_w4s
nt_th4t
_34sy_tbh_4r_d1065384}
```

---

## Step 3: Constructing the Flag

From the decoded fragments, we can reconstruct the flag in the standard `picoCTF{}` format.

After arranging the pieces logically, the final flag is:

```
picoCTF{1t_w4snt_th4t_34sy_tbh_4r_d1065384}
```

---

## Conclusion

To solve this challenge, we:

1. Extracted readable strings from the PCAP file using `strings`.
    
2. Identified and decoded Base64-encoded strings.
    
3. Reassembled the decoded fragments to form the complete flag.
    

This challenge demonstrated how attackers may hide sensitive data in network traffic and how forensic techniques can be used to recover and analyze it.

