"""
OSINT Intelligence Module - Dynamic Vulnerability Research
Uses DuckDuckGo to search for CVEs, exploits, and attack techniques.
"""

import re
import requests
from typing import Optional
from urllib.parse import quote_plus


class OSINTResearcher:
    """
    Performs OSINT research using DuckDuckGo to find vulnerabilities and exploits.
    """
    
    DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"
    
    # Patterns to extract relevant information from search results
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    EXPLOIT_DB_PATTERN = re.compile(r'exploit-db\.com/exploits/(\d+)', re.IGNORECASE)
    MSF_MODULE_PATTERN = re.compile(r'(exploit|auxiliary|post)/[\w/]+', re.IGNORECASE)
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
    
    def search(self, query: str, max_results: int = 5) -> list[dict]:
        """
        Search DuckDuckGo and return parsed results.
        
        Args:
            query: Search query
            max_results: Maximum number of results to return
            
        Returns:
            List of dicts with 'title', 'url', 'snippet'
        """
        try:
            response = self.session.post(
                self.DUCKDUCKGO_URL,
                data={'q': query, 'b': ''},
                timeout=self.timeout
            )
            response.raise_for_status()
            
            results = []
            html = response.text
            
            # Parse results using regex (avoiding heavy dependencies)
            # DuckDuckGo HTML results have a specific structure
            result_blocks = re.findall(
                r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]*)</a>.*?'
                r'<a[^>]*class="result__snippet"[^>]*>([^<]*)</a>',
                html, re.DOTALL
            )
            
            for url, title, snippet in result_blocks[:max_results]:
                # Clean up the extracted text
                title = re.sub(r'<[^>]+>', '', title).strip()
                snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                
                results.append({
                    'title': title,
                    'url': url,
                    'snippet': snippet
                })
            
            # Fallback: try alternative parsing if no results
            if not results:
                results = self._parse_alternative(html, max_results)
            
            return results
            
        except Exception as e:
            return [{'error': str(e)}]
    
    def _parse_alternative(self, html: str, max_results: int) -> list[dict]:
        """Alternative parsing method for DuckDuckGo results."""
        results = []
        
        # Try to find result links
        links = re.findall(r'<a[^>]*href="(https?://[^"]+)"[^>]*>([^<]+)</a>', html)
        
        for url, title in links[:max_results * 2]:
            # Filter out navigation/internal links
            if any(skip in url.lower() for skip in ['duckduckgo.com', 'javascript:', '#']):
                continue
            
            title = re.sub(r'<[^>]+>', '', title).strip()
            if title and len(title) > 10:
                results.append({
                    'title': title,
                    'url': url,
                    'snippet': ''
                })
                
            if len(results) >= max_results:
                break
        
        return results
    
    def search_vulnerabilities(self, service: str, version: str = None) -> dict:
        """
        Search for vulnerabilities related to a service/version.
        
        Args:
            service: Service name (e.g., 'vsftpd', 'apache', 'openssh')
            version: Optional version string
            
        Returns:
            Dict with 'cves', 'exploits', 'msf_modules', 'summary'
        """
        # Build search query
        if version:
            query = f"{service} {version} exploit vulnerability CVE"
        else:
            query = f"{service} exploit vulnerability CVE"
        
        results = self.search(query, max_results=10)
        
        # Extract relevant information
        cves = set()
        exploits = set()
        msf_modules = set()
        snippets = []
        
        for result in results:
            if 'error' in result:
                continue
                
            text = f"{result.get('title', '')} {result.get('snippet', '')} {result.get('url', '')}"
            
            # Extract CVEs
            found_cves = self.CVE_PATTERN.findall(text)
            cves.update(found_cves)
            
            # Extract Exploit-DB IDs
            found_exploits = self.EXPLOIT_DB_PATTERN.findall(text)
            exploits.update(f"EDB-{eid}" for eid in found_exploits)
            
            # Extract Metasploit modules
            found_msf = self.MSF_MODULE_PATTERN.findall(text)
            msf_modules.update(found_msf)
            
            # Collect snippets for summary
            if result.get('snippet'):
                snippets.append(result['snippet'][:200])
        
        # Generate summary
        summary = self._generate_summary(service, version, cves, exploits, msf_modules, snippets)
        
        return {
            'service': service,
            'version': version,
            'cves': list(cves)[:10],
            'exploits': list(exploits)[:5],
            'msf_modules': list(msf_modules)[:5],
            'summary': summary,
            'raw_results': results[:5]
        }
    
    def _generate_summary(self, service: str, version: str, cves: set, 
                         exploits: set, msf_modules: set, snippets: list) -> str:
        """Generate a tactical summary from research results."""
        parts = []
        
        if cves:
            parts.append(f"CVEs encontrados: {', '.join(list(cves)[:5])}")
        
        if exploits:
            parts.append(f"Exploits públicos: {', '.join(list(exploits)[:3])}")
        
        if msf_modules:
            parts.append(f"Módulos Metasploit: {', '.join(list(msf_modules)[:3])}")
        
        if not parts:
            parts.append(f"Nenhuma vulnerabilidade conhecida encontrada para {service}")
            if version:
                parts.append(f"Versão: {version}")
        
        return "; ".join(parts)
    
    def search_exploit_technique(self, technique: str) -> dict:
        """
        Search for specific attack techniques or methods.
        
        Args:
            technique: Attack technique (e.g., 'ssh brute force', 'sql injection')
            
        Returns:
            Dict with search results and recommendations
        """
        query = f"{technique} tutorial howto pentest"
        results = self.search(query, max_results=5)
        
        return {
            'technique': technique,
            'results': results,
            'tools_mentioned': self._extract_tools(results)
        }
    
    def _extract_tools(self, results: list) -> list[str]:
        """Extract tool names mentioned in search results."""
        common_tools = [
            'nmap', 'hydra', 'metasploit', 'msfconsole', 'sqlmap', 'nikto',
            'gobuster', 'dirb', 'burp', 'wireshark', 'john', 'hashcat',
            'enum4linux', 'smbclient', 'crackmapexec', 'responder',
            'impacket', 'bloodhound', 'mimikatz', 'netcat', 'nc'
        ]
        
        found_tools = set()
        for result in results:
            if 'error' in result:
                continue
            text = f"{result.get('title', '')} {result.get('snippet', '')}".lower()
            for tool in common_tools:
                if tool in text:
                    found_tools.add(tool)
        
        return list(found_tools)


def research_service(service: str, version: str = None) -> dict:
    """
    Convenience function to research a service.
    
    Args:
        service: Service name
        version: Optional version
        
    Returns:
        Research results dict
    """
    researcher = OSINTResearcher()
    return researcher.search_vulnerabilities(service, version)


def research_technique(technique: str) -> dict:
    """
    Convenience function to research an attack technique.
    
    Args:
        technique: Attack technique description
        
    Returns:
        Research results dict
    """
    researcher = OSINTResearcher()
    return researcher.search_exploit_technique(technique)


# Test
if __name__ == "__main__":
    print("=== OSINT Intelligence Module Test ===\n")
    
    researcher = OSINTResearcher()
    
    # Test vulnerability search
    print("[TEST 1] Searching for vsftpd 2.3.4 vulnerabilities...")
    results = researcher.search_vulnerabilities("vsftpd", "2.3.4")
    print(f"  CVEs: {results['cves']}")
    print(f"  Exploits: {results['exploits']}")
    print(f"  MSF Modules: {results['msf_modules']}")
    print(f"  Summary: {results['summary']}")
    print()
    
    # Test technique search
    print("[TEST 2] Searching for SSH brute force techniques...")
    results = researcher.search_exploit_technique("ssh brute force linux")
    print(f"  Tools mentioned: {results['tools_mentioned']}")
    print(f"  Results: {len(results['results'])} found")
