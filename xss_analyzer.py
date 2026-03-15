# xss_analyzer.py
import re
from bs4 import BeautifulSoup
import json
from typing import Dict, List, Tuple, Optional
import hashlib

class XSSContextAnalyzer:
    """
    Professional XSS context analyzer
    Determines exactly where the payload landed and how it was executed
    """
    
    # Patterns for different contexts
    CONTEXT_PATTERNS = {
        'html_tag': r'<[^>]*{payload}[^>]*>',
        'html_attribute': r'[a-zA-Z-]+=[\'"]?[^\'"]*{payload}[^\'"]*[\'"]?',
        'script_tag': r'<script[^>]*>[^<]*{payload}[^<]*</script>',
        'script_string': r'[\'"][^\'"]*{payload}[^\'"]*[\'"]',
        'css_style': r'style=[\'"][^\'"]*{payload}[^\'"]*[\'"]',
        'url_param': r'[?&][^=]+=[^&]*{payload}[^&]*',
        'json_value': r'"[^"]*"\s*:\s*"[^"]*{payload}[^"]*"',
    }
    
    # Successful execution indicators
    EXECUTION_INDICATORS = [
        'alert(',
        'prompt(',
        'confirm(',
        'document.cookie',
        'window.location',
        'eval(',
        'Function(',
        'setTimeout(',
        'setInterval(',
        'onerror=',
        'onload=',
        'onclick=',
        'javascript:',
    ]
    
    def __init__(self):
        self.results_cache = {}
        
    def analyze_response(self, payload: str, response_text: str, response_url: str) -> Dict:
        """Complete response analysis with context detection"""
        
        # Create cache key for performance
        cache_key = hashlib.md5(f"{payload}{response_url}".encode()).hexdigest()
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]
        
        result = {
            'payload': payload,
            'reflected': False,
            'context': None,
            'executed': False,
            'confidence': 0.0,
            'evidence': [],
            'waf_detected': False,
            'bypass_possible': False
        }
        
        # 1. Basic reflection check
        if payload in response_text:
            result['reflected'] = True
            result['evidence'].append("Payload found in response")
            
            # 2. Determine context
            context = self._determine_context(payload, response_text)
            result['context'] = context
            
            # 3. Check for escaping
            escaped = self._check_escaping(payload, response_text)
            if escaped:
                result['evidence'].append(f"Escaped: {escaped}")
                result['confidence'] -= 0.3
            
            # 4. Look for execution indicators
            execution_indicators = self._find_execution_indicators(response_text)
            if execution_indicators:
                result['executed'] = True
                result['confidence'] += 0.5
                result['evidence'].extend(execution_indicators)
            
            # 5. Check for WAF presence
            waf_signs = self._detect_waf(response_text, response_url)
            if waf_signs:
                result['waf_detected'] = True
                result['evidence'].append(f"WAF detected: {waf_signs}")
            
            # 6. Calculate confidence
            result['confidence'] = self._calculate_confidence(result)
            
            # 7. Check bypass possibility
            if not result['executed'] and result['waf_detected']:
                result['bypass_possible'] = self._check_bypass_possibility(payload, context)
        
        self.results_cache[cache_key] = result
        return result
    
    def _determine_context(self, payload: str, text: str) -> str:
        """Determines in which context the payload was reflected"""
        for context, pattern in self.CONTEXT_PATTERNS.items():
            if re.search(pattern.replace('{payload}', re.escape(payload)), text, re.IGNORECASE):
                return context
        return "unknown"
    
    def _check_escaping(self, payload: str, text: str) -> Optional[str]:
        """Checks if the payload is escaped"""
        escape_patterns = {
            'html_escape': payload.replace('<', '&lt;').replace('>', '&gt;'),
            'js_escape': payload.replace('"', '\\"').replace("'", "\\'"),
            'url_escape': re.sub(r'[^\w]', lambda m: f'%{ord(m.group(0)):02X}', payload)
        }
        
        for escape_type, escaped in escape_patterns.items():
            if escaped in text:
                return escape_type
        return None
    
    def _find_execution_indicators(self, text: str) -> List[str]:
        """Looks for JavaScript execution indicators"""
        found = []
        for indicator in self.EXECUTION_INDICATORS:
            if indicator in text.lower():
                found.append(indicator)
        return found
    
    def _detect_waf(self, text: str, url: str) -> Optional[str]:
        """Detects WAF presence by patterns"""
        waf_patterns = {
            'cloudflare': r'cloudflare|__cfduid',
            'akamai': r'akamai|ak_bmsc',
            'incapsula': r'incapsula|visid_incap',
            'sucuri': r'sucuri|cloudproxy',
            'aws_waf': r'awselb|awsalb',
        }
        
        combined_text = text + url
        for waf, pattern in waf_patterns.items():
            if re.search(pattern, combined_text, re.I):
                return waf
        return None
    
    def _calculate_confidence(self, result: Dict) -> float:
        """Confidence calculator for vulnerability"""
        confidence = 0.5  # Base
        
        if result['executed']:
            confidence += 0.3
        
        if result['context'] in ['script_tag', 'html_attribute']:
            confidence += 0.2
        elif result['context'] == 'unknown':
            confidence -= 0.2
        
        if len(result['evidence']) > 2:
            confidence += 0.1 * min(len(result['evidence']), 3)
        
        return min(max(confidence, 0.0), 1.0)
    
    def _check_bypass_possibility(self, payload: str, context: str) -> bool:
        """Checks WAF bypass possibility"""
        bypass_patterns = {
            'html_tag': ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>'],
            'script_string': ["';alert(1)//", '\\";alert(1)//'],
            'html_attribute': ['" onclick=alert(1)', "' onmouseover=alert(1)"],
        }
        
        if context in bypass_patterns:
            return any(bp in payload for bp in bypass_patterns[context])
        return False