from datetime import datetime

def _base_record(indicator, itype, source):
    return {
        "indicator": indicator,
        "type": itype,
        "source": source,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def _normalize_ips(ips, source):
    records = []
    for ip in ips:
        records.append(_base_record(ip, "IP", source))
    return records

def _normalize_domains(domains, source):
    records = []
    for domain in domains:
        records.append(_base_record(domain, "DOMAIN", source))
    return records

def _normalize_urls(urls, source):
    records = []
    for url in urls:
        records.append(_base_record(url, "URL", source))
    return records

def _normalize_hashes(hashes, source):
    records = []
    for h in hashes:
        records.append(_base_record(h, "HASH", source))
    return records

def _normalize_emails(emails, source):
    records = []
    for email in emails:
        records.append(_base_record(email, "EMAIL", source))
    return records

def normalize_indicators(ips, domains, urls, hashes, emails, source):
    normalized = []
    normalized.extend(_normalize_ips(ips, source))
    normalized.extend(_normalize_domains(domains, source))
    normalized.extend(_normalize_urls(urls, source))
    normalized.extend(_normalize_hashes(hashes, source))
    normalized.extend(_normalize_emails(emails, source))
    return normalized
