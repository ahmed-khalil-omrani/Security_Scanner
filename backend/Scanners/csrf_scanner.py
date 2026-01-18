from .base_scanner import BaseScanner
from typing import List, Dict

class CSRFScanner(BaseScanner):
    
    def scan(self) -> List[Dict]:
        print("\n[*] Starting CSRF Scan...")
        results = []
        
        for form in self.forms:
            if form['method'] == 'post':
                has_csrf_token = False
                
                for input_field in form['inputs']:
                    token_names = ['csrf', 'token', '_token', 'xsrf', 'authenticity_token']
                    if any(name in input_field['name'].lower() for name in token_names):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    results.append({
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'MEDIUM',
                        'url': form['action'],
                        'description': 'Form lacks CSRF protection token',
                        'payload': None,
                        'evidence': 'No CSRF token found in POST form',
                        'recommendation': 'Implement CSRF tokens for all state-changing operations. Use SameSite cookie attribute.'
                    })
        
        print(f"[+] CSRF scan complete. Found {len(results)} issues.")
        return results