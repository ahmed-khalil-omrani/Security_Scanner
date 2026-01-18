from .base_scanner import BaseScanner
import ssl
import socket
from datetime import datetime
from urllib.parse import parse_qs,urlparse
from typing import List , Dict

class SSLScanner(BaseScanner):

    def scan(self)->List[Dict]:

        print("\n[*] Starting SSL/TLS Scan...")
        results=[]
        parsed=urlparse(self.target_url)


        if parsed.scheme!='https':
            if parsed.scheme != 'https':
                results.append({
                'type': 'Insecure Transport',
                'severity': 'HIGH',
                'url': self.target_url,
                'description': 'Website not using HTTPS',
                'payload': None,
                'evidence': 'HTTP protocol detected instead of HTTPS',
                'recommendation': 'Implement HTTPS with a valid SSL/TLS certificate. Redirect all HTTP traffic to HTTPS.'
                 })
                return results
            hostname=parsed.netloc.split(':')[0]


        try:
            context=ssl.create_default_context()
            with socket.create_connection((hostname,443),timeout=10)as sock:
                with context.wrap_socket(sock,server_hostname=hostname)as ssocket:
                    cert=ssocket.getpeercert()

                    expire_date=datetime.striptime(
                         cert['notAfter'], 
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    days_util_expiry=(expire_date-datetime.now()).days
                    if days_util_expiry <30:
                        severity='HIGH' if days_util_expiry <7 else'MEDIUM'
                        results.append({
                            'type': 'SSL Certificate Expiring Soon',
                            'severity': severity,
                            'url': self.target_url,
                            'description': f'SSL certificate expires in {days_util_expiry} days',
                            'payload': None,
                            'evidence': f'Certificate expires: {expire_date}',
                            'recommendation': 'Renew SSL certificate before expiration. Consider using automated certificate renewal.'
                        })
                    tls_version=ssocket.version()
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                         results.append({
                            'type': 'Outdated TLS Version',
                            'severity': 'HIGH',
                            'url': self.target_url,
                            'description': f'Using outdated TLS version: {tls_version}',
                            'payload': None,
                            'evidence': f'TLS version: {tls_version}',
                            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3. Disable older versions (TLS 1.0, TLS 1.1).'
                        })
        except ssl.SSLError as e:
               results.append({
                'type': 'SSL/TLS Configuration Error',
                'severity': 'HIGH',
                'url': self.target_url,
                'description': 'SSL/TLS configuration issue detected',
                'payload': None,
                'evidence': str(e),
                'recommendation': 'Fix SSL/TLS configuration. Ensure valid certificate chain. Check cipher suite compatibility.'
            })
        except Exception as e:
              print(f"[!] SSL scan error: {e}")
        print(f"[+] SSL/TLS scan complete. Found {len(results)} issues.")
        return results
                