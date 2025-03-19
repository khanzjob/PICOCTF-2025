
# Flag Hunters - Writeup

## Challenge Details

**Name:** Flag Hunters  
**Points:** 75  
**Author:** syreal

### Description

Lyrics jump from verses to the refrain, kind of like a subroutine call. There's a hidden refrain this program doesn't print by default.

To connect to the challenge, we use netcat:

```
$ nc verbal-sleep.picoctf.net 59014
```

---

## Solution

1. **Connecting to the Challenge Server:**  
    First, we connect to the given server using netcat:
    
    ```
    nc verbal-sleep.picoctf.net 59014
    ```
    
    This presents us with some ASCII art and a poem-like text. The challenge description hints at a hidden refrain.
    
2. **Analyzing the Output:**  
    The text contains multiple lines that resemble a poem about hacking:
    
    ```
    Command line wizards, we’re starting it right,
    Spawning shells in the terminal, hacking all night.
    Scripts and searches, grep through the void,
    Every keystroke, we're a cypher's envoy.
    Brute force the lock or craft that regex,
    Flag on the horizon, what challenge is next?
    
    We’re flag hunters in the ether, lighting up the grid,
    No puzzle too dark, no challenge too hid.
    With every exploit we trigger, every byte we decrypt,
    We’re chasing that victory, and we’ll never quit.
    ```
    
3. **Hidden Refrain Discovery:**  
    Observing the output, it is formatted like a poem with repeated sections, indicating some lines might be skipped.
    ![[Pasted image 20250314000104.png]]
4. **Injecting the Payload:**  
    The presence of programming-related keywords like "subroutine call" hints at using a command or input to reveal the hidden refrain.
    
    We enter the following payload in the netcat session:
    
    ```
    ;;RETURN 0
    ```
    
5. **Flag Extraction:**  
    Upon entering the payload, we receive the flag:
    
    ```
    picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}
    ```
    

---

### Flag

```
picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}
```

### Tools Used

- **Netcat (**`**nc**`**)**: To connect to the challenge server.
    
- **Basic Text Analysis**: Recognizing the pattern in the output.
    
- **Understanding Code Execution and Control Flow**: Recognizing the `RETURN` statement as a potential input to reveal the hidden content.
    

---

This challenge tested both basic command-line skills and the ability to analyze text output for hidden patterns. The solution required recognizing a programming reference in the challenge description and leveraging it to retrieve the flag.