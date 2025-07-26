import re

def extract_iocs(text):
    """Extract IPs, domains, and hashes from text."""
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', text)
    domains = re.findall(r'(?:[a-z0-9]+(?:-[a-z0-9]+)*\.)+[a-z]{2,}', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    return {"IPs": ips, "Domains": domains, "Hashes": hashes}

# Example usage:
print(extract_iocs("C2: secure-invoice[.]com, IP: 45.134.26.209"))
