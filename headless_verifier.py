# headless_verifier.py
import asyncio
from playwright.async_api import async_playwright
import time
import hashlib
from typing import Dict, List, Tuple

class HeadlessXSSVerifier:
    """
    XSS verification through real browser
    Uses Playwright to launch headless Chrome
    """
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.browser = None
        self.context = None
        
    async def initialize(self):
        """Browser initialization"""
        p = await async_playwright().start()
        self.browser = await p.chromium.launch(headless=self.headless)
        self.context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
    
    async def verify_xss(self, url: str, payload: str, timeout: int = 5000) -> Dict:
        """
        Checks if XSS executed in browser
        """
        page = await self.context.new_page()
        result = {
            'url': url,
            'payload': payload,
            'executed': False,
            'alert_detected': False,
            'console_errors': [],
            'dom_changes': [],
            'execution_time': 0
        }
        
        start_time = time.time()
        
        # Intercept alerts
        async def handle_dialog(dialog):
            result['executed'] = True
            result['alert_detected'] = True
            result['alert_message'] = dialog.message
            await dialog.dismiss()
        
        page.on('dialog', handle_dialog)
        
        # Intercept console.log and errors
        async def handle_console(msg):
            if 'xss' in msg.text.lower() or 'alert' in msg.text.lower():
                result['console_errors'].append(msg.text)
                result['executed'] = True
        
        page.on('console', handle_console)
        
        try:
            # Load page
            await page.goto(url, timeout=timeout, wait_until='networkidle')
            
            # Give time for scripts to execute
            await asyncio.sleep(1)
            
            # Check DOM for changes
            initial_dom = await page.content()
            await asyncio.sleep(0.5)
            final_dom = await page.content()
            
            if initial_dom != final_dom:
                result['dom_changes'].append("DOM changed after load")
                result['executed'] = True
            
        except Exception as e:
            result['console_errors'].append(str(e))
        finally:
            await page.close()
            
        result['execution_time'] = time.time() - start_time
        return result
    
    async def batch_verify(self, urls_with_payloads: List[Tuple[str, str]], max_concurrent: int = 3):
        """Batch verification with concurrency control"""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def verify_one(url, payload):
            async with semaphore:
                return await self.verify_xss(url, payload)
        
        tasks = [verify_one(url, payload) for url, payload in urls_with_payloads]
        results = await asyncio.gather(*tasks)
        return results
    
    async def close(self):
        if self.browser:
            await self.browser.close()