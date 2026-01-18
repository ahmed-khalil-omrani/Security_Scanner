from fastapi import FastAPI,HTTPException,BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List , Dict , Optional
from datetime import datetime
import hashlib
import asyncio

from Scanners.sql_injaction import SQLInjection
from Scanners.xss_scanner import XSSScanner
from Scanners.ssl_scanner import SSLScanner
from Scanners.headers_scanner import SecurityHeadersScanner
from Scanners.csrf_scanner import CSRFScanner

app=FastAPI(
    title="OWASP Security Scanner",
    description="Advanced web application security scanner",
    version="2.0.0"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_results={}

class ScanRequest(BaseModel):
    url:HttpUrl
    max_pages: int=50
    scan_types:List[str]=[
        "sql_injection",
        "xss",
        "csrf",
        "ssl",
        "headers"
    ]

    class Config:
        schema_extra={
            "example":{
                "url": "http://testphp.vulnweb.com",
                "max_page":30,
                "scan_types":["sql_injection", "xss", "csrf", "ssl", "headers"]
            }
        }
class OWASPScanner:


    def __init__(self,target_url:str,max_pages:int,scan_types:List[str]):
        self.target_url=target_url
        self.max_pages=max_pages
        self.scan_types=scan_types
        self.vulnerabilities = []

    async def run_scan(self)->Dict: 
        scan_id=hashlib.md5(
            f"{self.target_url}{datetime.now()}".encode()
        ).hexdigest()


        print(f"\n{'='*60}")
        print(f"Starting scan: {scan_id}")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}")

        scan_info={
            'scan_id':scan_id,
            'target':self.target_url,
            'start_time':datetime.now().isoformat(),
            'status':'running',
            'urls_found':0,
            'forms_found':0,
            'vulnerabilities':[]
                            }
        try:
            print("\n[*] Phase 1: Website Crawling")
            from Scanners.base_scanner import BaseScanner
            base_scanner=BaseScanner(self.target_url,self.max_pages)
            urls,forms=base_scanner.crawl()
            scan_info["urls_found"]=len(urls)
            scan_info['forms_found']=len(forms)


            print(f"[+] Crawling complete: {len(urls)} URLs, {len(forms)} forms")
            
            print("\n[*] Phase 2: Vulnerability Scanning")
            scanners = []
 
            if'sql_injection' in self.scan_types:
                sql_scanner=SQLInjection(self.target_url,self.max_pages)
                sql_scanner.visited_urls=urls
                sql_scanner.forms=forms
                scanners.append(("SQL Injection",sql_scanner.scan))
            if 'xss' in self.scan_types:
                xss_scanner=XSSScanner(self.target_url,self.max_pages)
                xss_scanner.visited_urls=urls
                xss_scanner.forms=forms
                scanners.append(('XSS',xss_scanner.scan))

            if 'csrf'in self.scan_types:
                csrf_scanner=CSRFScanner(self.target_url,self.max_pages)
                csrf_scanner.visited_urls=urls
                csrf_scanner.forms=forms
                scanners.append(("CSRF",csrf_scanner.scan))
            if "ssl"in self.scan_types:
                ssl_scanner=SSLScanner(self.target_url,self.max_pages)
                scanners.append(("SSL/TLS",ssl_scanner.scan))
            if 'headers' in self.scan_types:
                headers_scanner = SecurityHeadersScanner(self.target_url, self.max_pages)
                scanners.append(('Security Headers', headers_scanner.scan))
            for scanner_name,scanner_func in scanners:
                try:
                    results=scanner_func()
                    self.vulnerabilities.extend(results)
                except Exception as e:
                    print(f"[!] Error in {scanner_name} scanner: {e}")


            print("\n[*] Phase 3: Generating Report")
            scan_info['vulnerabilities']=self.vulnerabilities
            scan_info['end_time']=datetime.now().isoformat()
            scan_info['status']='completed'
            scan_info['total_vulnerabilities']=len(self.vulnerabilities)

            scan_info['critical']=len([v for v in self.vulnerabilities if v["severity"]=='CRITICAL'])
            scan_info['high']=len([v for v in self.vulnerabilities if v["severity"]=='HIGH'])
            scan_info['medium']=len([v for v in self.vulnerabilities if v["severity"]=='MEDIUM'])
            scan_info['low']=len([v for v in self.vulnerabilities if v["severity"]=='LOW'])

            scan_results[scan_id]=scan_info


            print(f"\n{'='*60}")
            print(f"Scan complete: {scan_id}")
            print(f"Total vulnerabilities: {len(self.vulnerabilities)}")
            print(f"  CRITICAL: {scan_info['critical']}")
            print(f"  HIGH: {scan_info['high']}")
            print(f"  MEDIUM: {scan_info['medium']}")
            print(f"  LOW: {scan_info['low']}")
            print(f"{'='*60}\n")
            
            return scan_info
        

        except Exception as e:
            print(f"[!] Fatal error during scan: {e}")
            scan_info['status'] = 'failed'
            scan_info['error'] = str(e)
            scan_info['end_time'] = datetime.now().isoformat()
            scan_results[scan_id] = scan_info
            return scan_info

@app.get("/")
async def root():
        return {
        "message": "OWASP Security Scanner API",
        "version": "2.0.0",
        "endpoints": {
            "POST /api/scan": "Start a new security scan",
            "GET /api/scan/{scan_id}": "Get scan results",
            "GET /api/scans": "List all scans",
            "DELETE /api/scan/{scan_id}": "Delete scan results",
            "GET /health": "Health check",
            "GET /docs": "API documentation"
        },
       
    }
               


@app.post("/api/scan")
async def start_scan(request:ScanRequest):
    try:
        scanner=OWASPScanner(
            str(request.url),
            request.max_pages,
            request.scan_types
        )
        result=await scanner.run_scan()

        return {
            "status": "success",
            "scan_id": result['scan_id'],
            "message": "Scan completed successfully",
            "result": result
        }
    except Exception as e:
        return HTTPException(
            status_code=500, 
            detail=f"Scan failed: {str(e)}"
        )
@app.get("api/scan/{scan_id}")
async def get_scan_result(scan_id:str):


    if scan_id  not in scan_results:
        raise HTTPException(
            status_code=404, 
            detail="Scan not found"
        )
    return scan_results[scan_id]


@app.get("/api/sacans")
async def list_scans():
    return{

        "total":len(scan_results),
        "scans":[
            {
                  "scan_id": scan_id,
                "target": scan_info['target'],
                "status": scan_info['status'],
                "start_time": scan_info.get('start_time'),
                "total_vulnerabilities": scan_info.get('total_vulnerabilities', 0),
                "critical": scan_info.get('critical', 0),
                "high": scan_info.get('high', 0),
                "medium": scan_info.get('medium', 0),
                "low": scan_info.get('low', 0)
            }
            for scan_id,scan_info in scan_results.items()
        ]
    }

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id:str):
    if scan_id not in scan_results:
        raise HTTPException(
            status_code=404, 
            detail="Scan not found"
        )
    
    del scan_results[scan_id]
    return {
        "status": "success", 
        "message": f"Scan {scan_id} deleted successfully"
    }

@app.get("/health")
async def health_check():
        return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "total_scans": len(scan_results)
    }

if __name__=="__main__":
    import uvicorn 
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║              OWASP Security Scanner                      ║
    ║               Created By The Fool                        ║
    ║                                                          ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")