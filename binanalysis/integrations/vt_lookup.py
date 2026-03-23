"""VirusTotal hash reputation lookup."""

import os

import requests

from binanalysis.output import heading, info, detail, warn, danger


VT_API_URL = "https://www.virustotal.com/api/v3/files"


def lookup_hash(sha256: str) -> dict:
    """Query VirusTotal for a file hash and return detection summary."""
    heading("VIRUSTOTAL REPUTATION")

    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        info("VT_API_KEY not set — skipping VirusTotal lookup")
        return {}

    try:
        resp = requests.get(
            f"{VT_API_URL}/{sha256}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
    except requests.RequestException as e:
        warn(f"VirusTotal request failed: {e}")
        return {}

    if resp.status_code == 404:
        info("Hash not found on VirusTotal (unknown sample)")
        return {"found": False}

    if resp.status_code == 429:
        warn("VirusTotal rate limit exceeded — try again later")
        return {}

    if resp.status_code != 200:
        warn(f"VirusTotal returned HTTP {resp.status_code}")
        return {}

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {})

    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + undetected + stats.get("harmless", 0) + stats.get("suspicious", 0)

    result = {
        "found": True,
        "malicious": malicious,
        "undetected": undetected,
        "total_engines": total,
        "detection_ratio": f"{malicious}/{total}",
    }

    # Known family names
    popular = attrs.get("popular_threat_classification", {})
    if popular:
        label = popular.get("suggested_threat_label", "")
        if label:
            result["threat_label"] = label

    # File names seen
    names = attrs.get("names", [])
    if names:
        result["known_names"] = names[:5]

    # Signature info from VT
    sig_info = attrs.get("signature_info", {})
    if sig_info:
        result["vt_signer"] = sig_info.get("subject", "")

    # Tags
    tags = attrs.get("tags", [])
    if tags:
        result["tags"] = tags

    # Display
    if malicious == 0:
        info(f"Detection: {malicious}/{total} — CLEAN on VirusTotal")
    elif malicious <= 3:
        warn(f"Detection: {malicious}/{total} — low detection (possible FP)")
    else:
        danger(f"Detection: {malicious}/{total} — DETECTED as malicious")

    detail("Detection Ratio", result["detection_ratio"])
    if result.get("threat_label"):
        detail("Threat Label", result["threat_label"])
    if result.get("known_names"):
        detail("Known Names", ", ".join(result["known_names"]))
    if result.get("vt_signer"):
        detail("VT Signer", result["vt_signer"])
    if result.get("tags"):
        detail("Tags", ", ".join(result["tags"]))

    return result
