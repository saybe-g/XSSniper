# crawler.py
import httpx
import asyncio
from urllib.parse import urljoin, urlparse 
from bs4 import BeautifulSoup
from typing import Set, List, Dict, Any
import re 
import phonenumbers
from phonenumbers import PhoneNumberMatcher, PhoneNumberFormat


class Crawler: 
    """Professional asynchronous crawler for finding XSS targets"""

    def __init__(self, start_url: str, max_depth: int = 2, max_urls: int = 150, 
                 headers: Dict = None, timeout: int = 10, cookies: Dict = None, osint: bool = False):
        self.start_url = start_url
        self.base_domain = urlparse(start_url).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.headers = headers or {}
        self.timeout = timeout
        self.cookies = cookies or {}
        self.osint = osint 

        # data structures
        self.visited: Set[str] = set()
        self.targets: List[Dict] = []
        self.queue: asyncio.Queue = asyncio.Queue()

        # stats
        self.stats = {
            'pages_parsed': 0,
            'forms_found': 0,
            'get_params_found': 0,
            'errors': 0,
            'osint_finds': 0
        } 

        # OSINT data storage
        self.osint_data = {
            'emails': set(),
            'phones': set(),
            'comments': [],
            'hidden_fields': [],
            'meta_tags': {},
            'api_endpoints': set(),
            'potential_keys': []
        }

        self.email_regex = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        self.phone_regex = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}'
        self.api_key_regex = r'(?:api[_-]?key|token|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{16,})["\']'
        self.api_endpoint_regex = r'\/api\/|\/v\d+\/|\/graphql|\/rest\/'

    async def crawl(self) -> List[Dict]: 
        """Starts crawling and returns list of found targets"""
        print(f"[🌐] Starting intelligent crawl of {self.start_url}")
        print(f"[📊] Max depth: {self.max_depth}, Max URLs: {self.max_urls}")

        await self.queue.put((self.start_url, 0)) 

        async with httpx.AsyncClient(
            headers=self.headers,
            timeout=self.timeout,
            cookies=self.cookies,
            follow_redirects=True
        ) as client:
            workers = [self._worker(client) for _ in range(5)]
            await asyncio.gather(*workers)

        print(f"[✅] Crawling completed! Found {len(self.targets)} targets")
        print(f"    📄 Pages parsed: {self.stats['pages_parsed']}")
        print(f"    📝 Forms found: {self.stats['forms_found']}")
        print(f"    🔍 GET params found: {self.stats['get_params_found']}")
        if self.osint:
            print(f"\n[🕵️] OSINT Results:")
            print(f"    📧 Emails found: {len(self.osint_data['emails'])}")
            print(f"    📞 Phones found: {len(self.osint_data['phones'])}")
            print(f"    💬 Comments found: {len(self.osint_data['comments'])}")
            print(f"    🔑 Hidden fields: {len(self.osint_data['hidden_fields'])}")
            print(f"    🌐 API endpoints: {len(self.osint_data['api_endpoints'])}")
            print(f"    🔐 Potential keys: {len(self.osint_data['potential_keys'])}")
        return self.targets

    async def _worker(self, client: httpx.AsyncClient):
        """Worker for asynchronous URL processing from queue"""
        while True:
            try:
                url, depth = await asyncio.wait_for(self.queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                break  # No more URLs to process

            if url in self.visited or depth > self.max_depth or len(self.visited) >= self.max_urls:
                self.queue.task_done()
                continue
            self.visited.add(url)

            try:
                response = await client.get(url)
                self.stats['pages_parsed'] += 1
                content_type = response.headers.get('content-type', '')
                # 🔍 OSINT
                if self.osint:
                    self._extract_osint_from_text(response.text, url)
                if 'text/html' not in content_type:
                    self.queue.task_done()
                    continue

                soup = BeautifulSoup(response.text, 'lxml')
                await self._extract_links(soup, url, depth, client)
                self._extract_forms(soup, url)
                self._extract_get_params(url)
                if self.osint:
                    self._extract_html_osint(soup, url)
                if 'javascript' in content_type or url.endswith('.js'):
                    self._extract_osint_from_js(response.text, url)
            except Exception as e:
                self.stats['errors'] += 1
                print(f"[-] Error crawling {url}: {str(e)[:50]}")
            self.queue.task_done()

    async def _extract_links(self, soup: BeautifulSoup, base_url: str, depth: int, client: httpx.AsyncClient):
        """Extracts all links and adds them to queue"""
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()

            if not href or href.startswith('#'):
                continue

            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)

            if parsed.netloc != self.base_domain:
                continue

            if re.search(r'\.(jpg|jpeg|png|gif|css|js|ico|svg|woff|ttf|eot)$', parsed.path, re.I):
                continue

            if len(self.visited) < self.max_urls and full_url not in self.visited:
                await self.queue.put((full_url, depth + 1))

    def _extract_forms(self, soup: BeautifulSoup, page_url: str):
        """Professional form parsing with complete analysis"""
        forms = soup.find_all('form')

        for form in forms:
            self.stats['forms_found'] += 1

            action = form.get('action', '')
            if not action:
                action = page_url
            else:
                action = urljoin(page_url, action)

            method = form.get('method', 'get').lower()

            enctype = form.get('enctype', 'application/x-www-form-urlencoded')
            is_json = 'json' in enctype.lower()

            fields = {}
            field_types = {}

            for input_tag in form.find_all('input'):
                name = input_tag.get('name')
                if not name:
                    continue
                
                input_type = input_tag.get('type', 'text')
                value = input_tag.get('value', '')

                fields[name] = value
                field_types[name] = input_type

                # 🔍 OSINT: Save hidden fields
                if input_type == 'hidden' and self.osint:
                    self.osint_data['hidden_fields'].append({
                        'url': page_url,
                        'name': name,
                        'value': value
                    })
                    self.stats['osint_finds'] += 1
            
            for textarea in form.find_all('textarea'):
                name = textarea.get('name')
                if name:
                    fields[name] = textarea.get_text() or 'FUZZ'
                    field_types[name] = 'textarea'

            for select in form.find_all('select'):
                name = select.get('name')
                if name:
                    first_option = select.find('option')
                    value = first_option.get('value', '') if first_option else ''
                    fields[name] = value
                    field_types[name] = 'select'

            if fields:
                for field_name in fields.keys():
                    test_fields = fields.copy()
                    test_fields[field_name] = 'FUZZ'
                    target = {
                        'url': action,
                        'method': method.upper(),
                        'data': test_fields,
                        'json': is_json,
                        'enctype': enctype,
                        'context': {
                            'depth': self.max_depth,  # approximate
                            'source': 'form',
                            'field_types': field_types,
                            'tested_field': field_name,
                            'page_url': page_url
                        }
                    }
                    self.targets.append(target)

    def _extract_get_params(self, url: str):
        """Analyzes URL for GET parameters"""
        parsed = urlparse(url)
        if parsed.query:
            from urllib.parse import parse_qs, urlencode, parse_qsl
            
            params = parse_qs(parsed.query)
            for param_name in params.keys():
                query_parts = parse_qsl(parsed.query)

                new_query_parts = []
                for key, value in query_parts:
                    if key == param_name:
                        new_query_parts.append((key, 'FUZZ'))
                    else:
                        new_query_parts.append((key, value))

                new_query = urlencode(new_query_parts)
                new_url = parsed._replace(query=new_query).geturl()

                target = {
                    'url': new_url,
                    'method': 'GET',
                    'data': None,
                    'json': False,
                    'context': {
                        'depth': self.max_depth,
                        'source': 'url_param',
                        'param_name': param_name,
                        'original_url': url
                    }
                }
                self.targets.append(target)
                self.stats['get_params_found'] += 1


    def _extract_osint_from_text(self, text: str, source_url: str):
        """Extracts OSINT data from any text"""
    
        # 📧 Email search
        emails = re.findall(self.email_regex, text)
        for email in emails:
            if email not in self.osint_data['emails']:
                self.osint_data['emails'].add(email)
                self.stats['osint_finds'] += 1
                print(f"    📧 Found email: {email} at {source_url}")
    
        # 📞 PROFESSIONAL phone number search
        try:
            for match in PhoneNumberMatcher(text, None):  # None = auto region detection
                phone_number = phonenumbers.format_number(match.number, PhoneNumberFormat.E164)
                national = phonenumbers.format_number(match.number, PhoneNumberFormat.NATIONAL)
                international = phonenumbers.format_number(match.number, PhoneNumberFormat.INTERNATIONAL)
            
                if phone_number not in self.osint_data['phones']:
                    self.osint_data['phones'].add(phone_number)
                    self.stats['osint_finds'] += 1
                
                    # Additional phone number information
                    country = phonenumbers.region_code_for_number(match.number)
                    is_valid = phonenumbers.is_valid_number(match.number)
                    is_possible = phonenumbers.is_possible_number(match.number)
                
                    print(f"    📞 Found phone: {international}")
                    print(f"        ├─ E164: {phone_number}")
                    print(f"        ├─ National: {national}")
                    print(f"        ├─ Country: {country or 'Unknown'}")
                    print(f"        ├─ Valid: {'✅' if is_valid else '❌'}")
                    print(f"        └─ Possible: {'✅' if is_possible else '❌'}")
        except Exception as e:
            # Rare case when library might fail
            pass
    
        # 🔐 Potential API key search
        keys = re.findall(self.api_key_regex, text, re.IGNORECASE)
        for key in keys:
            self.osint_data['potential_keys'].append({
                'key': key,
                'source': source_url
            })
            self.stats['osint_finds'] += 1
            print(f"    🔐 Found potential key: {key[:20]}... at {source_url}")

    def _extract_html_osint(self, soup: BeautifulSoup, page_url: str):
        """Extracts OSINT data from HTML structure"""
    
        # 💬 Comment search
        comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
        for comment in comments:
            comment_text = str(comment).strip()
            if comment_text and len(comment_text) > 10:  # Ignore empty ones
                self.osint_data['comments'].append({
                    'text': comment_text,
                    'url': page_url
                })
                self.stats['osint_finds'] += 1
                print(f"    💬 Found comment: {comment_text[:50]}... at {page_url}")
    
        # 📝 Meta tags
        meta_tags = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property')
            content = meta.get('content')
            if name and content:
                meta_tags[name] = content
                if name in ['author', 'description', 'keywords']:
                    self.stats['osint_finds'] += 1
                    print(f"    📝 Meta {name}: {content[:50]} at {page_url}")
    
        if meta_tags:
            self.osint_data['meta_tags'][page_url] = meta_tags
    
        # 🌐 API endpoint search in links and scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            if re.search(self.api_endpoint_regex, src, re.I):
                full_url = urljoin(page_url, src)
                self.osint_data['api_endpoints'].add(full_url)
                self.stats['osint_finds'] += 1
                print(f"    🌐 Found API endpoint: {full_url}")
    
        for link in soup.find_all('link', href=True):
            href = link['href']
            if re.search(self.api_endpoint_regex, href, re.I):
                full_url = urljoin(page_url, href)
                self.osint_data['api_endpoints'].add(full_url)
                self.stats['osint_finds'] += 1
                print(f"    🌐 Found API endpoint: {full_url}")

    def _extract_osint_from_js(self, js_content: str, js_url: str):
        """Extracts OSINT data from JavaScript files"""
    
        # JS files can also contain emails and keys
        self._extract_osint_from_text(js_content, js_url)
    
        # Search for API endpoints in strings
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
            r'["\'](/graphql)[^"\']*["\']',
            r'["\'](/rest/[^"\']+)["\']'
        ]
    
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                full_url = urljoin(js_url, match)
                self.osint_data['api_endpoints'].add(full_url)
                self.stats['osint_finds'] += 1
                print(f"    🌐 Found API endpoint in JS: {full_url}")