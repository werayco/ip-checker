import requests
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class ThreatFeed:
    name: str
    first_seen: str
    last_seen: str


@dataclass
class SSHData:
    attempts: int
    usernames: int
    passwords: int
    start: str
    end: str


@dataclass
class WebLogData:
    count: int
    avg_authors: int
    avg_urls: int
    avg_user_agents: int
    first_seen: str
    last_seen: str


@dataclass
class IPThreatInfo:
    ip: str
    count: Optional[int]
    attacks: Optional[int]
    max_date: str
    min_date: str
    updated: str
    comment: str
    max_risk: Optional[int]
    as_abuse_contact: str
    asn: str
    as_name: str
    as_country: str
    as_size: int
    network: str
    threat_feeds: List[ThreatFeed]
    ssh_data: Optional[SSHData]
    weblog_data: Optional[WebLogData]


class SANSISCClient:
    BASE_URL = "http://isc.sans.edu/api"
    
    def __init__(self, user_agent: str = "SANSISCClient/1.0"):
        self.headers = {"User-Agent": user_agent}
    
    def check_ip(self, ip: str) -> IPThreatInfo:
        url = f"{self.BASE_URL}/ip/{ip}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return self._parse_ip_response(response.text)
    
    def get_top_ips(self, limit: int = 10, date: str = None) -> List[Dict]:
        url = f"{self.BASE_URL}/topips/records/{limit}"
        if date:
            url += f"/{date}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return self._parse_top_ips_response(response.text)
    
    def get_sources_by_attacks(self, limit: int = 100, date: str = None) -> List[Dict]:
        url = f"{self.BASE_URL}/sources/attacks/{limit}"
        if date:
            url += f"/{date}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return self._parse_sources_response(response.text)
    
    @staticmethod
    def _safe_int(value: str) -> Optional[int]:
        try:
            return int(value) if value.strip() else None
        except (ValueError, AttributeError):
            return None
    
    @staticmethod
    def _safe_text(element) -> str:
        return element.text if element is not None and element.text else ""
    
    @staticmethod
    def _parse_ip_response(xml_content: str) -> IPThreatInfo:
        root = ET.fromstring(xml_content)
        
        threat_feeds = []
        threatfeeds_elem = root.find("threatfeeds")
        if threatfeeds_elem is not None:
            for feed in threatfeeds_elem:
                threat_feeds.append(ThreatFeed(
                    name=feed.tag,
                    first_seen=SANSISCClient._safe_text(feed.find("firstseen")),
                    last_seen=SANSISCClient._safe_text(feed.find("lastseen"))
                ))
        
        ssh_data = None
        ssh_elem = root.find("ssh")
        if ssh_elem is not None:
            ssh_data = SSHData(
                attempts=SANSISCClient._safe_int(SANSISCClient._safe_text(ssh_elem.find("attempts"))) or 0,
                usernames=SANSISCClient._safe_int(SANSISCClient._safe_text(ssh_elem.find("usernames"))) or 0,
                passwords=SANSISCClient._safe_int(SANSISCClient._safe_text(ssh_elem.find("passwords"))) or 0,
                start=SANSISCClient._safe_text(ssh_elem.find("start")),
                end=SANSISCClient._safe_text(ssh_elem.find("end"))
            )
        
        weblog_data = None
        weblog_elem = root.find("weblogs")
        if weblog_elem is not None:
            weblog_data = WebLogData(
                count=SANSISCClient._safe_int(SANSISCClient._safe_text(weblog_elem.find("count"))) or 0,
                avg_authors=SANSISCClient._safe_int(SANSISCClient._safe_text(weblog_elem.find("avgauthors"))) or 0,
                avg_urls=SANSISCClient._safe_int(SANSISCClient._safe_text(weblog_elem.find("avgurls"))) or 0,
                avg_user_agents=SANSISCClient._safe_int(SANSISCClient._safe_text(weblog_elem.find("avguser_agents"))) or 0,
                first_seen=SANSISCClient._safe_text(weblog_elem.find("firstseen")),
                last_seen=SANSISCClient._safe_text(weblog_elem.find("lastseen"))
            )
        
        return IPThreatInfo(
            ip=SANSISCClient._safe_text(root.find("number")),
            count=SANSISCClient._safe_int(SANSISCClient._safe_text(root.find("count"))),
            attacks=SANSISCClient._safe_int(SANSISCClient._safe_text(root.find("attacks"))),
            max_date=SANSISCClient._safe_text(root.find("maxdate")),
            min_date=SANSISCClient._safe_text(root.find("mindate")),
            updated=SANSISCClient._safe_text(root.find("updated")),
            comment=SANSISCClient._safe_text(root.find("comment")),
            max_risk=SANSISCClient._safe_int(SANSISCClient._safe_text(root.find("maxrisk"))),
            as_abuse_contact=SANSISCClient._safe_text(root.find("asabusecontact")),
            asn=SANSISCClient._safe_text(root.find("as")),
            as_name=SANSISCClient._safe_text(root.find("asname")),
            as_country=SANSISCClient._safe_text(root.find("ascountry")),
            as_size=SANSISCClient._safe_int(SANSISCClient._safe_text(root.find("assize"))) or 0,
            network=SANSISCClient._safe_text(root.find("network")),
            threat_feeds=threat_feeds,
            ssh_data=ssh_data,
            weblog_data=weblog_data
        )
    
    @staticmethod
    def _parse_top_ips_response(xml_content: str) -> List[Dict]:
        root = ET.fromstring(xml_content)
        results = []
        
        for ip_elem in root.findall("ipaddress"):
            results.append({
                "rank": SANSISCClient._safe_int(SANSISCClient._safe_text(ip_elem.find("rank"))),
                "source": SANSISCClient._safe_text(ip_elem.find("source")),
                "reports": SANSISCClient._safe_int(SANSISCClient._safe_text(ip_elem.find("reports"))),
                "targets": SANSISCClient._safe_int(SANSISCClient._safe_text(ip_elem.find("targets")))
            })
        
        return results
    
    @staticmethod
    def _parse_sources_response(xml_content: str) -> List[Dict]:
        root = ET.fromstring(xml_content)
        results = []
        
        for data_elem in root.findall("data"):
            results.append({
                "ip": SANSISCClient._safe_text(data_elem.find("ip")),
                "attacks": SANSISCClient._safe_int(SANSISCClient._safe_text(data_elem.find("attacks"))),
                "count": SANSISCClient._safe_int(SANSISCClient._safe_text(data_elem.find("count"))),
                "first_seen": SANSISCClient._safe_text(data_elem.find("firstseen")),
                "last_seen": SANSISCClient._safe_text(data_elem.find("lastseen"))
            })
        
        return results


class ThreatAnalyzer:
    
    @staticmethod
    def is_tor_exit_node(ip_info: IPThreatInfo) -> bool:
        return any(feed.name in ["torexit", "alltor"] for feed in ip_info.threat_feeds)
    
    @staticmethod
    def get_threat_score(ip_info: IPThreatInfo) -> int:
        score = 0
        score += len(ip_info.threat_feeds) * 10
        
        if ip_info.ssh_data:
            score += min(ip_info.ssh_data.attempts, 100)
        
        if ThreatAnalyzer.is_tor_exit_node(ip_info):
            score += 50
        
        return score
    
    @staticmethod
    def categorize_threat_level(score: int) -> str:
        if score >= 100:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "CLEAN"


# if __name__ == "__main__":
#     client = SANSISCClient("ThreatChecker/1.0 (security@company.com)")
    
#     ip_to_check = "209.85.220.41"
#     ip_info = client.check_ip(ip_to_check)
    
#     analyzer = ThreatAnalyzer()
#     threat_score = analyzer.get_threat_score(ip_info)
#     threat_level = analyzer.categorize_threat_level(threat_score)
    
#     result = {
#         "ip": ip_info.ip,
#         "threat_level": threat_level,
#         "threat_score": threat_score,
#         "is_tor": analyzer.is_tor_exit_node(ip_info),
#         "threat_feeds_count": len(ip_info.threat_feeds),
#         "asn": ip_info.asn,
#         "country": ip_info.as_country,
#         "network": ip_info.network
#     }
#     print(result)