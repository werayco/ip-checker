import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
from urllib3.poolmanager import PoolManager

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        context = ssl.create_default_context()
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, ssl_context=context)

def check_ip_abuse(ip_address, max_age_days=90, api_key="1930805c6a0c63be9186338b5a31f88d8d437803be0776c5949d07ef9117b1db3e5c45cd6bd580ab"):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days
    }

    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = TLSAdapter(max_retries=retries)
    session.mount("https://", adapter)

    response = session.get(url, headers=headers, params=params, timeout=10)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Error {response.status_code}: {response.text}")

def check_suspicious_indicators(isp, domain):
    suspicious_isps = [
        "bulletproof", "offshore", "vpn", "proxy", "tor", 
        "anonymous", "hosting", "cloud", "server"
    ]
    
    suspicious_domains = [
        ".ru", ".su", ".cn", ".br", ".ua", ".pl", 
        "vpn", "proxy", "tor", "anonymous"
    ]
    
    isp_lower = isp.lower() if isp else ""
    domain_lower = domain.lower() if domain else ""
    
    for keyword in suspicious_isps:
        if keyword in isp_lower:
            return True
    
    for keyword in suspicious_domains:
        if keyword in domain_lower:
            return True
    
    return False

def evaluate_ip(ip_data):
    data = ip_data.get("data", {})
    abuse_score = data.get("abuseConfidenceScore", 0)
    total_reports = data.get("totalReports", 0)
    country = data.get("countryCode", "")
    isp = data.get("isp", "")
    domain = data.get("domain", "")
    is_public = data.get("isPublic", False)
    is_whitelisted = data.get("isWhitelisted", False)
    last_reported = data.get("lastReportedAt", "")
    
    if is_whitelisted:
        return "Safe"
    
    if abuse_score >= 75:
        return "Block"
    
    if abuse_score >= 50 and total_reports > 10:
        return "Block"
    
    if total_reports > 20 and abuse_score >= 25:
        return "Caution"
    
    if is_public and total_reports > 5 and abuse_score > 0:
        return "Caution"
    
    suspicious_indicators = check_suspicious_indicators(isp, domain)
    if suspicious_indicators and abuse_score > 10:
        return "Caution"
    
    high_risk_countries = ["RU", "CN", "UA", "BR", "IN", "VN", "ID", "TR"]
    if country in high_risk_countries and abuse_score > 20:
        return "Caution"
    
    return "Safe"
