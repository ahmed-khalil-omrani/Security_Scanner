import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin,urlparse, parse_qs
from typing import List,Dict ,Set


class BaseScanner:
    def __init__(self ,target_url:str,max_pages:int=50):
        self.target_url=target_url
        self.max_pages=max_pages
        self.vulnerabilities: List[Dict]=[]

        self.session=requests.Session()
        self.session.headers.update({
            "User-agent":'Mozilla/5.0 (Security Scanner)'
        })
        self.visited_urls:Set[str]=set()
        self.forms:List[Dict]=[]
        self.cookies=[]



    def crawl(self):
        to_visit = [self.target_url]
        
        while to_visit and len(self.visited_urls) < self.max_pages:
            url = to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
                
            try:
                print(f"Crawling: {url}")
                response = self.session.get(url, timeout=10, verify=False)
                self.visited_urls.add(url)
                
                if response.cookies:
                    self.cookies.extend(response.cookies)
                
              
                soup = BeautifulSoup(response.content, 'html.parser')
                
                
                for form in soup.find_all('form'):
                    form_details = self._get_form_details(form, url)
                    if form_details not in self.forms:
                        self.forms.append(form_details)
                
               
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    parsed = urlparse(next_url)
                    
                   
                    if parsed.netloc == urlparse(self.target_url).netloc:
                        if next_url not in self.visited_urls:
                            to_visit.append(next_url)
                            
            except Exception as e:
                print(f"Error crawling {url}: {e}")
                
        return list(self.visited_urls), self.forms

    
    def _get_form_details(self,form,page_url:str)->Dict:
        details={
            'action':urljoin(page_url,form.get('action','')),
            'method':form.get('method','get').lower(),
            'inputs':[]
        }
        for input_tag in form.find_all(['input','textarea','select']):  
            input_type=input_tag.get('type','text')
            input_name=input_tag.get('name')
            input_value=input_tag.get('value','')
            if input_name:
                details['inputs'].append({
                    'type':input_type,
                    'name':input_name,
                    'value':input_value
                })
        return details