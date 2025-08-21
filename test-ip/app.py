from ipCheck import abuseIP, allCheckers, sansIP
ipAdd = str(input("kindly input your ip: " )).strip()
print("------Using SansIP------------")
client = sansIP.SANSISCClient("ThreatChecker/1.0 (security@company.com)") 
ip_to_check =ipAdd
ip_info = client.check_ip(ip_to_check)
    
analyzer = sansIP.ThreatAnalyzer()
threat_score = analyzer.get_threat_score(ip_info)
threat_level = analyzer.categorize_threat_level(threat_score)

result = {
        "ip": ip_info.ip,
        "threat_level": threat_level,
        "threat_score": threat_score,

    }
print(result)


print("------USing AbuseIpdb--------")
ip_data = abuseIP.check_ip_abuse(ipAdd)
result = abuseIP.evaluate_ip(ip_data)
print(f"IP Evaluation Result: {result}")
print(f"Full Data: {ip_data}")


print("-----Using AllCheckers----")
resultAll = allCheckers.BlacklistChecker.is_blacklisted(ipAdd)
print(resultAll)


