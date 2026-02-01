from datetime import datetime
import os

def _write_header(f):
    f.write("THREAT INTELLIGENCE AGGREGATION REPORT\n")
    f.write("=" * 60 + "\n")
    f.write("Generated (UTC): " + datetime.utcnow().isoformat() + "Z\n\n")

def _write_feed_section(f, feeds):
    f.write("FEEDS PROCESSED\n")
    f.write("-" * 60 + "\n")
    for feed in feeds:
        f.write("• " + feed + "\n")
    f.write("\n")

def _write_summary_section(f, stats):
    f.write("SUMMARY OVERVIEW\n")
    f.write("-" * 60 + "\n")
    f.write("Total Indicators: " + str(stats.get("total_indicators", 0)) + "\n")
    f.write("Critical Severity: " + str(stats.get("critical", 0)) + "\n")
    f.write("High Severity: " + str(stats.get("high", 0)) + "\n")
    f.write("Medium Severity: " + str(stats.get("medium", 0)) + "\n")
    f.write("Low Severity: " + str(stats.get("low", 0)) + "\n\n")

def _write_type_breakdown(f, stats):
    f.write("INDICATOR TYPE DISTRIBUTION\n")
    f.write("-" * 60 + "\n")
    f.write("IP Indicators: " + str(stats.get("ip_count", 0)) + "\n")
    f.write("Domain Indicators: " + str(stats.get("domain_count", 0)) + "\n")
    f.write("URL Indicators: " + str(stats.get("url_count", 0)) + "\n")
    f.write("Hash Indicators: " + str(stats.get("hash_count", 0)) + "\n")
    f.write("Email Indicators: " + str(stats.get("email_count", 0)) + "\n\n")

def _write_high_severity(f, data):
    f.write("HIGH & CRITICAL SEVERITY INDICATORS\n")
    f.write("-" * 60 + "\n")
    for item in data:
        if item["severity"] in ("HIGH", "CRITICAL"):
            f.write(
                item["indicator"] + " | " +
                item["type"] + " | " +
                item["severity"] + " | " +
                "Confidence: " + str(item["confidence"]) + " | " +
                "Sources: " + ", ".join(item["sources"]) + "\n"
            )
    f.write("\n")

def _write_full_listing(f, data):
    f.write("FULL CORRELATED INDICATOR LISTING\n")
    f.write("-" * 60 + "\n")
    index = 1
    for item in data:
        f.write("Record #" + str(index) + "\n")
        f.write("Indicator     : " + item["indicator"] + "\n")
        f.write("Type          : " + item["type"] + "\n")
        f.write("Severity      : " + item["severity"] + "\n")
        f.write("Confidence    : " + str(item["confidence"]) + "\n")
        f.write("Occurrences   : " + str(item["occurrences"]) + "\n")
        f.write("Sources       : " + ", ".join(item["sources"]) + "\n")
        f.write("-" * 40 + "\n")
        index += 1
    f.write("\n")

def _write_footer(f):
    f.write("END OF REPORT\n")
    f.write("=" * 60 + "\n")

def generate_final_report(data, feeds, stats):
    output_path = "../output/final_report.txt"
    os.makedirs("../output", exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        _write_header(f)
        _write_feed_section(f, feeds)
        _write_summary_section(f, stats)
        _write_type_breakdown(f, stats)
        _write_high_severity(f, data)
        _write_full_listing(f, data)
        _write_footer(f)
