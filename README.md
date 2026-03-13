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
- Clean and colored terminal output
- Support for `FUZZ` keyword in URL to specify exact injection point

### Installation

```
git clone https://github.com/saybe-g/XSSniper.git
cd xssniper
pip install -r requirements.txt
chmod +x xssniper.py
```

Usage
``` Option 1 – using FUZZ placeholder (recommended)
python xssniper.py -u "https://example.com/search?q=FUZZ"
```
``` Option 2 – payload appended to the end of the URL
python xssniper.py -u "https://vuln.site/page?search="
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
