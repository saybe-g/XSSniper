# XSSniper
Professional XSS scanner for ethical testing and bug bounty hunting
------------------------------------------------------------------------------

-----------------The next major update will be in about a week.

### 🔥 Features
- Testing with ~300+ effective XSS payloads (including modern vectors from 2024–2025)
- Load your own custom payloads from a `.txt` file
- Automatic URL-encoding of payloads
- Browser impersonation via realistic Chrome User-Agent
- 🌐 Better Error Handling
- Clean and colored terminal output
- 📋 Final Summary List
- Support for `FUZZ` keyword in URL to specify exact injection point
- ⏱️ Customizable Delay
- ⚡ Asynchronous – concurrent requests (default 20, adjustable) make scanning several times faster.
- 🌐 POST & JSON – supports any HTTP method and data format.
- 📡 Blind XSS – built‑in server to receive callbacks, generates ready‑to‑use payloads.
- 🕷️ Crawler – automatically discovers links, forms, GET parameters; control depth and URL count.
- 🌐 Headless Verification – launches a real browser to confirm XSS (intercepts alerts, console errors, DOM changes).
- 🕵️ OSINT – during crawling, collects emails, phone numbers, comments, hidden fields, API endpoints, and potential keys.
- 🤖 Machine Learning – Random Forest model (12 features, trained on 200,000+ samples) boosts accuracy >95%.
- 🎯 Improved Heuristics – context analysis, escaping detection, WAF detection, confidence scoring.
- 🧩 Convenience Flags – --full (crawl+osint+color) and --full-an (ml‑model+headless).

### Reactions
→ ✅ [XSS!] -- # potential XSS found (payload reflected without obvious escaping) -- green

🛡️ (interesting) -- interesting code error -- magenta

→ ❌   --   # not found or not reflected -- red

→ ⏰ Timeout -- # timeout -- blue 

→ 🔌 Connection error - # connection error -- cyan 

→ ⚠️ Error -- # other request exceptions (truncated for readability) -- yellow
 

### Installation

```
git clone https://saybe-g/XSSniper.git
sudo apt update
sudo apt install python3-venv
cd XSSniper
python3 -m venv xssenv
source xssenv/bin/activate
pip install -r requirements.txt
playwright install chromium   
python3 xssniper.py --help
```
### Launch after installation:
```
cd XSSniper
source xssenv/bin/activate
python3 xssniper.py -h
```

### Usage
``` 
# Basic GET scan
python3 xssniper.py -u "http://testphp.vulnweb.com/search.php?test=FUZZ" --color
```

```
# POST form
python3 xssniper.py -u "http://site.com/login" --method POST --data "user=FUZZ&pass=123" --color
```

```
# JSON API
python3 xssniper.py -u "http://api.site.com/users" --method POST --data '{"name":"FUZZ"}' --json --color
```

```
# Full scan (crawl + OSINT + color)
python3 xssniper.py -u "http://site.com" --full
```

```
# Full analysis (ML + headless)
python3 xssniper.py -u "http://site.com/search?q=FUZZ" --full-an
```

```
# Everything combined
python3 xssniper.py -u "http://site.com" --full --full-an --concurrency 100 -d 0.3
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

## 🤝 Feedback
If you find a bug or have a feature request, please open an Issue or submit a Pull Request on GitHub.

##### XSSNIPER v0.4 is ready to hunt! 💥

