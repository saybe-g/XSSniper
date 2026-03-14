# XSSniper
Simple reflected XSS scanner for ethical testing and bug bounty hunting
------------------------------------------------------------------------------
# XSSniper

A simple and lightweight **reflected XSS scanner** (currently GET parameters only) designed for educational purposes and **legal security testing**.

**XSSNIPER** is a minimalistic Python script that quickly checks web applications for classic reflected XSS vulnerabilities by testing a list of popular payloads.

### Features
- Testing with ~200 effective XSS payloads (including modern vectors from 2024–2025)
- Load your own custom payloads from a `.txt` file
- Automatic URL-encoding of payloads
- Basic heuristic to detect unescaped reflection (no HTML entity encoding)
- Browser impersonation via realistic Chrome User-Agent
- 🌐 Better Error Handling
- Clean and colored terminal output
- 📋 Final Summary List
- Support for `FUZZ` keyword in URL to specify exact injection point
- ⏱️ Customizable Delay
- ⚡ Asynchronous Architecture
       Switched from synchronous requests to asynchronous httpx with asyncio.
       Allows concurrent requests, dramatically speeding up scans on targets with many payloads.
       Added --concurrency flag to control the number of parallel requests (default: 5).


### Reactions
→ ✅ [XSS!] -- # potential XSS found (payload reflected without obvious escaping) -- green

🛡️ (interesting) -- interesting code error -- magenta

→ ❌   --   # not found or not reflected -- red

→ ⏰ Timeout -- # timeout -- blue 

→ 🔌 Connection error - # connection error -- cyan 

→ ⚠️ Error -- # other request exceptions (truncated for readability) -- yellow
 
! Don't use this flag(--color) if you're outputting the contents to a file. The output may look bad.

### Installation

```
git clone https://github.com/saybe-g/XSSniper.git
cd xssniper
pip install -r requirements.txt
```

Usage
``` using FUZZ placeholder
python xssniper.py -u "https://example.com/search?q=FUZZ
```
Example
```
python xssniper.py -u "https://example.com/search?q=FUZZ -f 'payload.txt' --append --color
```
### IMPORTANT LEGAL NOTICE
XSSNIPER is intended strictly for ethical and legal use only:

Testing your own web applications
Participating in bug bounty programs with explicit written permission
Educational platforms, CTFs, and labs (DVWA, bWAPP, PortSwigger Web Security Academy, TryHackMe, Hack The Box, etc.)
Authorized penetration testing of systems where you have clear written permission

### The author assumes no responsibility whatsoever for any misuse of this tool.
Unauthorized scanning, exploitation of vulnerabilities, or causing damage to third-party systems is illegal in most countries and may result in criminal liability.

### License
MIT License — completely open source.
Feel free to fork, improve, and use it for learning — just please keep this ethical usage warning intact.
Happy (and legal) hunting!
