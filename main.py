from parser import parse_feed
from normalizer import normalize_indicators
from correlator import correlate_indicators
from exporter import export_blocklists
from report import generate_final_report

def main():
    feeds = {
        "feed1": "../feeds/feed1.txt",
        "feed2": "../feeds/feed2.txt"
    }

    all_normalized = []

    for source, path in feeds.items():
        ips, domains, urls, hashes, emails = parse_feed(path)
        normalized = normalize_indicators(
            ips,
            domains,
            urls,
            hashes,
            emails,
            source
        )
        all_normalized.extend(normalized)

    correlated = correlate_indicators(all_normalized)

    stats = {
        "total_indicators": len(correlated),
        "critical": len([i for i in correlated if i["severity"] == "CRITICAL"]),
        "high": len([i for i in correlated if i["severity"] == "HIGH"]),
        "medium": len([i for i in correlated if i["severity"] == "MEDIUM"]),
        "low": len([i for i in correlated if i["severity"] == "LOW"]),
        "ip_count": len([i for i in correlated if i["type"] == "IP"]),
        "domain_count": len([i for i in correlated if i["type"] == "DOMAIN"]),
        "url_count": len([i for i in correlated if i["type"] == "URL"]),
        "hash_count": len([i for i in correlated if i["type"] == "HASH"]),
        "email_count": len([i for i in correlated if i["type"] == "EMAIL"])
    }

    export_blocklists(correlated)
    generate_final_report(correlated, list(feeds.keys()), stats)

if __name__ == "__main__":
    main()
