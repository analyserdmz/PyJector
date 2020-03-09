# PyJector
Python C-Style Shellcode Injector, armed with XOR, MD5-based, brute-force decryption of the Shellcode.

### Features of PyJector
- Encrypts a C-Style Shellcode (Payload) with a random XOR key.
- Stores the encrypted Shellcode without the actual decryption key.
- Brute-forces the encrypted Shellcode until the same MD5sum is found.
- Searches through processes to find one to inject the decrypted Shellcode to.
- Uses a process-exception list to avoid system crashes.

### How to execute the Script

#### First execute PyJector.py

`C:\tools\PyJector>python PyJector.py`

#### The final file is generated under fud.py
`C:\tools\PyJector>python fud.py`

`Key Found! Trying to find suitable process to inject. Please wait...`

`Success! PID: 14292 - ProcName: notepad++.exe`
