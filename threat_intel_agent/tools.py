"""
STEP 2 — Tools for the Threat-Intel agent (LangChain).

A "tool" is just a normal Python function that the LLM is allowed to call.
The @tool decorator (from LangChain) reads:
  * the function NAME            -> the tool's name the LLM sees
  * the DOCSTRING                -> the description the LLM uses to decide WHEN to call it
  * the TYPE HINTS (ip: str ...) -> the JSON schema of the arguments
So write docstrings carefully: they are instructions to the model.

The data below is MOCK data so the project works offline and for free.
Later you can swap the body of each function for a real API call
(AbuseIPDB, VirusTotal, NVD, etc.) without changing anything else.
"""

from langchain_core.tools import tool

# ---------------- mock "threat intelligence database" ----------------
_IP_DB = {
    "185.220.101.1": {"verdict": "malicious", "score": 95, "tags": ["tor-exit-node", "brute-force"], "country": "DE"},
    "45.95.147.236": {"verdict": "malicious", "score": 88, "tags": ["c2-server", "mirai"], "country": "NL"},
    "8.8.8.8": {"verdict": "benign", "score": 0, "tags": ["google-dns"], "country": "US"},
}

_CVE_DB = {
    "CVE-2021-44228": {"name": "Log4Shell", "cvss": 10.0, "summary": "RCE in Apache Log4j 2 via JNDI lookups.", "exploited_in_wild": True},
    "CVE-2023-4966": {"name": "Citrix Bleed", "cvss": 9.4, "summary": "Session token leak in NetScaler ADC/Gateway.", "exploited_in_wild": True},
    "CVE-2024-3400": {"name": "PAN-OS GlobalProtect", "cvss": 10.0, "summary": "Command injection in PAN-OS GlobalProtect.", "exploited_in_wild": True},
}

_HASH_DB = {
    "44d88612fea8a8f36de82e1278abb02f": {"verdict": "malicious", "family": "EICAR test file", "detections": "60/70"},
}


@tool
def check_ip_reputation(ip: str) -> dict:
    """Look up the reputation of an IPv4 address. Returns verdict, risk score (0-100), tags and country."""
    return _IP_DB.get(ip.strip(), {"verdict": "unknown", "score": None, "tags": [], "note": "No intel found for this IP."})


@tool
def lookup_cve(cve_id: str) -> dict:
    """Get details for a CVE identifier such as CVE-2021-44228: name, CVSS score, summary and whether it is exploited in the wild."""
    return _CVE_DB.get(cve_id.strip().upper(), {"note": f"{cve_id} not in local database."})


@tool
def check_file_hash(file_hash: str) -> dict:
    """Check an MD5/SHA1/SHA256 file hash against malware intelligence. Returns verdict, malware family and AV detections."""
    return _HASH_DB.get(file_hash.strip().lower(), {"verdict": "unknown", "note": "Hash not seen before."})


# The list the graph will use
ALL_TOOLS = [check_ip_reputation, lookup_cve, check_file_hash]
