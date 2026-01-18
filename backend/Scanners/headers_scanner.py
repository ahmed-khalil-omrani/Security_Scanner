from .base_scanner import BaseScanner
from typing import Dict , List

class SecurityHeadersScanner(BaseScanner):
    REQUIRED_HEADERS = {
        'X-Frame-Options': 'Prevents clickjacking attacks by controlling iframe embedding',
        'X-Content-Type-Options': 'Prevents MIME-sniffing attacks',
        'Strict-Transport-Security': 'Enforces HTTPS connections (HSTS)',
        'Content-Security-Policy': 'Prevents XSS and injection attacks',
        'X-XSS-Protection': 'Enables browser XSS protection',
        'Referrer-Policy': 'Controls referrer information sent with requests',
        'Permissions-Policy': 'Controls browser features and APIs'
    }
    def scan(self)->List[Dict]:
        print("\n[*] Starting Security Headers Scan...")
        results = []
        try :
            response=self.session.get(self.target_url,timeout=10,verify=False)
            headers=response.headers
            for header,description in self.REQUIRED_HEADERS.items():
                if header not in headers:
                    results.append({
                                    'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'url': self.target_url,
                        'description': f'Missing security header: {header}',
                        'payload': None,
                        'evidence': description,
                        'recommendation': f'Add {header} header to all responses. Example: {header}: SAMEORIGIN (for X-Frame-Options)'
                    })
                    disclosure_headers=['Server', 'X-Powered-By', 'X-AspNet-Version']
                    for header in disclosure_headers:
                        if header in headers:
                             results.append({
                                'type': 'Information Disclosure',
                                'severity': 'LOW',
                                'url': self.target_url,
                                'description': f'{header} header reveals server information',
                                'payload': None,
                                'evidence': f'{header}: {headers[header]}',
                                'recommendation': f'Remove or obfuscate {header} header to avoid information disclosure.'
                            })
        except Exception as e:
            print(f'[!] Headers scan error: {e}')
        print(f"[+] Security Headers scan complete. Found {len(results)} issues.")
        return results