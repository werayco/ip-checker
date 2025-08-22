## run.py
import streamlit as st
import requests
from ipCheck import abuseIP, allCheckers, sansIP

st.title("IP Threat and Blacklist Checker")

ipAdd = st.text_input("Kindly input your IP:").strip()

if ipAdd:
    st.subheader("Using SansIP")
    try:
        client = sansIP.SANSISCClient("ThreatChecker/1.0 (security@company.com)")
        ip_info = client.check_ip(ipAdd)
        analyzer = sansIP.ThreatAnalyzer()
        threat_score = analyzer.get_threat_score(ip_info)
        threat_level = analyzer.categorize_threat_level(threat_score)
        sansip_result = {
            "ip": ip_info.ip,
            "threat_level": threat_level,
            "threat_score": threat_score,
        }
        st.json(sansip_result)
    except requests.exceptions.HTTPError as e:
        st.error(f"SANS ISC API unavailable: {e}")
    except Exception as e:
        st.error(f"Error checking IP with SansIP: {e}")

    st.subheader("Using AbuseIPDB")
    try:
        ip_data = abuseIP.check_ip_abuse(ipAdd)
        abuse_result = abuseIP.evaluate_ip(ip_data)
        st.write("IP Evaluation Result:", abuse_result)
        st.json(ip_data)
    except requests.exceptions.HTTPError as e:
        st.error(f"AbuseIPDB API unavailable: {e}")
    except Exception as e:
        st.error(f"Error checking IP with AbuseIPDB: {e}")

    st.subheader("Using AllCheckers")
    try:
        results = allCheckers.BlacklistChecker.quick_check(ipAdd)  # run tier1 blacklists
        summary = allCheckers.BlacklistChecker.get_summary(ipAdd, results)  # get full summary
        
        st.write("Blacklist Summary:")
        st.json(summary)   # pretty print JSON-style
    except Exception as e:
        st.error(f"Error checking IP with AllCheckers: {e}")
