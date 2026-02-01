import re
import ipaddress
from urllib.parse import urlparse

def _read_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.readlines()

def _extract_ips(lines):
    results = set()
    pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    for line in lines:
        matches = pattern.findall(line)
        for ip in matches:
            try:
                ipaddress.ip_address(ip)
                results.add(ip)
            except Exception:
                pass
    return results

def _extract_domains(lines):
    results = set()
    pattern = re.compile(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b")
    for line in lines:
        matches = pattern.findall(line)
        for domain in matches:
            if not domain.startswith("http"):
                results.add(domain.lower())
    return results

def _extract_urls(lines):
    results = set()
    pattern = re.compile(r"https?://[^\s]+")
    for line in lines:
        matches = pattern.findall(line)
        for url in matches:
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                results.add(url)
    return results

def _extract_hashes(lines):
    results = set()
    for line in lines:
        value = line.strip()
        if re.fullmatch(r"[a-fA-F0-9]{32}", value):
            results.add(value)
        elif re.fullmatch(r"[a-fA-F0-9]{40}", value):
            results.add(value)
        elif re.fullmatch(r"[a-fA-F0-9]{64}", value):
            results.add(value)
    return results

def _extract_emails(lines):
    results = set()
    pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    for line in lines:
        matches = pattern.findall(line)
        for email in matches:
            results.add(email.lower())
    return results

def parse_feed(path):
    lines = _read_file(path)
    ips = _extract_ips(lines)
    domains = _extract_domains(lines)
    urls = _extract_urls(lines)
    hashes = _extract_hashes(lines)
    emails = _extract_emails(lines)
    return list(ips), list(domains), list(urls), list(hashes), list(emails)
