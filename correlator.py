def _severity_from_count(count):
    if count >= 5:
        return "CRITICAL"
    if count >= 3:
        return "HIGH"
    if count == 2:
        return "MEDIUM"
    return "LOW"

def _confidence_from_sources(sources):
    if len(sources) >= 5:
        return 0.95
    if len(sources) >= 3:
        return 0.85
    if len(sources) == 2:
        return 0.70
    return 0.50

def correlate_indicators(data):
    bucket = {}

    for item in data:
        key = (item["indicator"], item["type"])
        if key not in bucket:
            bucket[key] = {
                "indicator": item["indicator"],
                "type": item["type"],
                "sources": set(),
                "occurrences": 0
            }
        bucket[key]["sources"].add(item["source"])
        bucket[key]["occurrences"] += 1

    correlated = []

    for record in bucket.values():
        severity = _severity_from_count(record["occurrences"])
        confidence = _confidence_from_sources(record["sources"])
        correlated.append({
            "indicator": record["indicator"],
            "type": record["type"],
            "sources": sorted(list(record["sources"])),
            "occurrences": record["occurrences"],
            "severity": severity,
            "confidence": confidence
        })

    correlated.sort(key=lambda x: (x["severity"], x["occurrences"]), reverse=True)
    return correlated
