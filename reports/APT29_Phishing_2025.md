# APT29 Phishing Campaign (July 2025)  
**Target**: Finance sector in Europe.  

## 🔎 IOCs  
| Type       | Value                  | Description          |  
|------------|------------------------|----------------------|  
| Domain     | secure-invoice[.]com   | C2 server           |  
| IP         | 45.134.26.209         | Phishing host       |  
| SHA256     | 1a2b3c...             | Malicious PDF lure   |  

## ⚙️ TTPs (MITRE ATT&CK)  
- **T1566.001**: Spearphishing attachment.  
- **T1059.005**: PowerShell payload.  

## 🛡️ Mitigation  
- Block IOCs at firewall/EDR.  
- Train staff to spot PDF phishing.  
