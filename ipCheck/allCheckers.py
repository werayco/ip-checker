## allCheckers.py
import socket
import concurrent.futures
from typing import List, Dict, Tuple
import ipaddress
import time

class BlacklistChecker:
    tier1_blacklists = {
        'Spamhaus Zen': 'zen.spamhaus.org',
        'SpamCop': 'bl.spamcop.net', 
        'Composite Blocking List': 'cbl.abuseat.org',
        'Barracuda': 'b.barracudacentral.org',
        'Passive Spam Block List': 'psbl.surriel.com'
    }
    
    tier2_blacklists = {
        'Spamhaus SBL': 'sbl.spamhaus.org',
        'Spamhaus XBL': 'xbl.spamhaus.org',
        'Spamhaus PBL': 'pbl.spamhaus.org',
        'SURBL Multi': 'multi.surbl.org',
        'URIBL Black': 'black.uribl.com',
        'Drone BL': 'drone.abuse.ch'
    }
    
    all_blacklists = {**tier1_blacklists, **tier2_blacklists}
    
    @staticmethod
    def reverse_ip(ip: str) -> str:
        return '.'.join(reversed(ip.split('.')))
    
    @staticmethod
    def check_single_blacklist(ip: str, blacklist_name: str, blacklist_host: str, timeout: int = 2) -> Tuple[str, bool, str]:
        try:
            ipaddress.ip_address(ip)
            reversed_ip = BlacklistChecker.reverse_ip(ip)
            query_host = f"{reversed_ip}.{blacklist_host}"
            
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            
            try:
                result = socket.gethostbyname(query_host)
                return blacklist_name, True, f"Listed ({result})"
            finally:
                socket.setdefaulttimeout(original_timeout)
                
        except socket.gaierror as e:
            if any(msg in str(e).lower() for msg in ["name or service not known", "no such host", "nxdomain"]):
                return blacklist_name, False, "Clean"
            else:
                return blacklist_name, False, f"DNS Error"
        except socket.timeout:
            return blacklist_name, False, "Timeout"
        except Exception as e:
            return blacklist_name, False, f"Error: {type(e).__name__}"
    
    @staticmethod
    def quick_check(ip: str) -> Dict[str, Dict[str, any]]:
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_blacklist = {
                executor.submit(BlacklistChecker.check_single_blacklist, ip, name, host, 3): name 
                for name, host in BlacklistChecker.tier1_blacklists.items()
            }
            
            for future in concurrent.futures.as_completed(future_to_blacklist, timeout=8):
                blacklist_name = future_to_blacklist[future]
                
                try:
                    name, is_listed, status = future.result()
                    results[name] = {'listed': is_listed, 'status': status}
                except Exception as e:
                    results[blacklist_name] = {'listed': False, 'status': f'Error: {e}'}
        
        return results
    
    @staticmethod
    def comprehensive_check(ip: str) -> Dict[str, Dict[str, any]]:
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            future_to_blacklist = {
                executor.submit(BlacklistChecker.check_single_blacklist, ip, name, host, 4): name 
                for name, host in BlacklistChecker.all_blacklists.items()
            }
            
            try:
                for future in concurrent.futures.as_completed(future_to_blacklist, timeout=15):
                    blacklist_name = future_to_blacklist[future]
                    
                    try:
                        name, is_listed, status = future.result()
                        results[name] = {'listed': is_listed, 'status': status}
                    except Exception as e:
                        results[blacklist_name] = {'listed': False, 'status': f'Error: {e}'}
                        
            except concurrent.futures.TimeoutError:
                for future, blacklist_name in future_to_blacklist.items():
                    if blacklist_name not in results:
                        future.cancel()
                        results[blacklist_name] = {'listed': False, 'status': 'Timeout'}
        
        return results
    
    @staticmethod
    def get_summary(ip: str, results: Dict[str, Dict[str, any]]) -> Dict[str, any]:
        listed_results = {name: result for name, result in results.items() if result['listed']}
        clean_results = {name: result for name, result in results.items() if not result['listed']}
        
        threat_level = BlacklistChecker.assess_threat_level(listed_results)
        
        return {
            'ip': ip,
            'blacklisted_count': len(listed_results),
            'total_checked': len(results),
            'blacklisted_on': listed_results,
            'clean_on': clean_results,
            'threat_level': threat_level,
            'is_blacklisted': len(listed_results) > 0
        }
    
    @staticmethod
    def assess_threat_level(listed_results: Dict) -> str:
        if not listed_results:
            return "LOW"
        
        high_priority = ['Spamhaus Zen', 'Spamhaus SBL', 'SpamCop', 'Barracuda']
        high_priority_hits = [name for name in listed_results.keys() if name in high_priority]
        
        if len(high_priority_hits) >= 2:
            return "HIGH"
        elif len(high_priority_hits) >= 1:
            return "MEDIUM"
        else:
            return "LOW-MEDIUM"
    
    @staticmethod
    def is_blacklisted(ip: str) -> bool:
        results = BlacklistChecker.quick_check(ip)
        return any(result['listed'] for result in results.values())
    
    @staticmethod
    def check_multiple_ips(ip_list: List[str]) -> Dict[str, Dict[str, any]]:
        all_results = {}
        for ip in ip_list:
            results = BlacklistChecker.quick_check(ip)
            all_results[ip] = BlacklistChecker.get_summary(ip, results)
        return all_results
    
    @staticmethod
    def get_blacklisted_ips(ip_list: List[str]) -> List[str]:
        blacklisted_ips = []
        for ip in ip_list:
            if BlacklistChecker.is_blacklisted(ip):
                blacklisted_ips.append(ip)
        return blacklisted_ips
    
