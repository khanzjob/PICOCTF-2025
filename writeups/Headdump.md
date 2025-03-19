### **Steps to Extract the Flag from the Heap Dump**

1. **Download the Heap Dump**  
    Run the following command to download the heap snapshot file:

    `curl -o heapdump.heapsnapshot http://verbal-sleep.picoctf.net:52837/heapdump`
    
2. **Inspect the Heap Dump**  
    Heap dumps are usually in JSON format. You can analyze it using:
    
    `cat heapdump.heapsnapshot | less`
    
    Or pretty-print it:
    
    `jq . heapdump.heapsnapshot | less`
    
3. **Search for the Flag Pattern**  
    Since the flag format is usually `picoCTF{...}`, you can try:

    `strings heapdump.heapsnapshot | grep -i picoCTF`


![[Pasted image 20250308103315.png]]
