import os
import json
import csv
from datetime import datetime

def _ensure_output_structure(base_path):
    directories = [
        base_path,
        os.path.join(base_path, "blocklists"),
        os.path.join(base_path, "archives"),
        os.path.join(base_path, "metadata")
    ]
    for d in directories:
        if not os.path.exists(d):
            os.makedirs(d, exist_ok=True)

def _open_files(base_path):
    files = {}
    files["ip"] = open(os.path.join(base_path, "blocklists", "ip_blocklist.txt"), "w", encoding="utf-8")
    files["domain"] = open(os.path.join(base_path, "blocklists", "domain_blocklist.txt"), "w", encoding="utf-8")
    files["url"] = open(os.path.join(base_path, "blocklists", "url_blocklist.txt"), "w", encoding="utf-8")
    files["hash"] = open(os.path.join(base_path, "blocklists", "hash_blocklist.txt"), "w", encoding="utf-8")
    files["email"] = open(os.path.join(base_path, "blocklists", "email_blocklist.txt"), "w", encoding="utf-8")
    return files

def _close_files(files):
    for f in files.values():
        try:
            f.flush()
            f.close()
        except Exception:
            pass

def _write_text_blocklists(files, item):
    t = item["type"]
    if t == "IP":
        files["ip"].write(item["indicator"] + "\n")
    elif t == "DOMAIN":
        files["domain"].write(item["indicator"] + "\n")
    elif t == "URL":
        files["url"].write(item["indicator"] + "\n")
    elif t == "HASH":
        files["hash"].write(item["indicator"] + "\n")
    elif t == "EMAIL":
        files["email"].write(item["indicator"] + "\n")

def _export_json(data, base_path):
    structured = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "total_records": len(data),
        "records": data
    }
    json_path = os.path.join(base_path, "archives", "ioc_full_export.json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(structured, jf, indent=2)

def _export_csv(data, base_path):
    csv_path = os.path.join(base_path, "archives", "ioc_full_export.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow([
            "indicator",
            "type",
            "severity",
            "confidence",
            "sources",
            "occurrences"
        ])
        for item in data:
            writer.writerow([
                item["indicator"],
                item["type"],
                item["severity"],
                item.get("confidence", "N/A"),
                ",".join(item.get("sources", [])),
                item.get("count", item.get("occurrences", 1))
            ])

def _export_metadata(data, base_path):
    meta = {
        "counts": {},
        "severity_distribution": {},
        "type_distribution": {}
    }

    for item in data:
        meta["counts"]["total"] = meta["counts"].get("total", 0) + 1

        sev = item.get("severity", "UNKNOWN")
        meta["severity_distribution"][sev] = meta["severity_distribution"].get(sev, 0) + 1

        t = item.get("type", "UNKNOWN")
        meta["type_distribution"][t] = meta["type_distribution"].get(t, 0) + 1

    meta_path = os.path.join(base_path, "metadata", "export_metadata.json")
    with open(meta_path, "w", encoding="utf-8") as mf:
        json.dump(meta, mf, indent=2)

def export_blocklists(data):
    base_path = "../output"
    _ensure_output_structure(base_path)
    files = _open_files(base_path)

    try:
        for item in data:
            _write_text_blocklists(files, item)
    finally:
        _close_files(files)

    _export_json(data, base_path)
    _export_csv(data, base_path)
    _export_metadata(data, base_path)
