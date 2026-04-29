"""
OPNSense Configuration Analyzer - Backend API
All processing happens in-memory. Files are never written to disk.
Sensitive data is scrubbed before any analysis results are returned.
"""

import xml.etree.ElementTree as ET
import hashlib
import re
import json
import ipaddress
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="OPNSense Analyzer", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ─── SECURITY: Sanitize sensitive values before returning ───────────────────

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "key", "token", "hash",
    "psk", "cert", "ca", "crl", "prv", "pub", "pin",
    "username", "user", "apikey", "api_key", "passphrase",
    "ldap_bindpw", "radius_secret", "vpn_password"
}

def scrub(value: str, key: str = "") -> str:
    """Replace sensitive values with a placeholder."""
    k = key.lower()
    if any(s in k for s in SENSITIVE_KEYS):
        return "***REDACTED***"
    return value

def scrub_dict(d: dict) -> dict:
    """Recursively scrub sensitive keys from a dict."""
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out[k] = scrub_dict(v)
        elif isinstance(v, list):
            out[k] = [scrub_dict(i) if isinstance(i, dict) else i for i in v]
        elif isinstance(v, str):
            out[k] = scrub(v, k)
        else:
            out[k] = v
    return out

def safe_ip(ip: str) -> str:
    """Validate IP or return placeholder."""
    try:
        ipaddress.ip_network(ip, strict=False)
        return ip
    except Exception:
        return ip  # Return as-is if it's an alias or hostname

# ─── XML PARSING ────────────────────────────────────────────────────────────

def parse_opnsense_xml(content: bytes) -> dict:
    """Parse OPNSense XML backup into structured dict."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML: {e}")

    data = {}

    # --- System Info (scrubbed) ---
    system = root.find("system")
    if system is not None:
        data["system"] = {
            "hostname": system.findtext("hostname", "unknown"),
            "domain": system.findtext("domain", "unknown"),
            "timezone": system.findtext("timezone", "unknown"),
            "version": system.findtext("version", "unknown"),
            "language": system.findtext("language", "en_US"),
        }

    # --- Interfaces ---
    interfaces_node = root.find("interfaces")
    interfaces = {}
    if interfaces_node is not None:
        for iface in interfaces_node:
            iface_data = {tag.tag: tag.text or "" for tag in iface}
            # Scrub any sensitive fields
            iface_data = scrub_dict(iface_data)
            interfaces[iface.tag] = iface_data
    data["interfaces"] = interfaces

    # --- Firewall Rules ---
    filter_node = root.find("filter")
    rules = []
    if filter_node is not None:
        for rule in filter_node.findall("rule"):
            r = {tag.tag: (tag.text or "").strip() for tag in rule}
            # Parse nested source/destination
            src = rule.find("source")
            dst = rule.find("destination")
            r["source"] = {}
            r["destination"] = {}
            if src is not None:
                r["source"] = {t.tag: (t.text or "").strip() for t in src}
            if dst is not None:
                r["destination"] = {t.tag: (t.text or "").strip() for t in dst}
            rules.append(r)
    data["rules"] = rules

    # --- NAT Rules ---
    nat_node = root.find("nat")
    nat_rules = []
    if nat_node is not None:
        for rule in nat_node.findall("rule"):
            r = {tag.tag: (tag.text or "").strip() for tag in rule}
            src = rule.find("source")
            dst = rule.find("destination")
            r["source"] = {}
            r["destination"] = {}
            if src is not None:
                r["source"] = {t.tag: (t.text or "").strip() for t in src}
            if dst is not None:
                r["destination"] = {t.tag: (t.text or "").strip() for t in dst}
            nat_rules.append(r)
    data["nat"] = nat_rules

    # --- Aliases ---
    aliases_node = root.find("aliases")
    aliases = []
    if aliases_node is not None:
        for alias in aliases_node.findall("alias"):
            a = {tag.tag: (tag.text or "").strip() for tag in alias}
            aliases.append(a)
    data["aliases"] = aliases

    # --- VPN (OpenVPN / IPsec) ---
    vpn = {}
    openvpn = root.find("openvpn")
    if openvpn is not None:
        servers = []
        for srv in openvpn.findall("openvpn-server"):
            s = scrub_dict({tag.tag: (tag.text or "").strip() for tag in srv})
            servers.append(s)
        clients = []
        for cli in openvpn.findall("openvpn-client"):
            c = scrub_dict({tag.tag: (tag.text or "").strip() for tag in cli})
            clients.append(c)
        vpn["openvpn"] = {"servers": servers, "clients": clients}

    ipsec = root.find("ipsec")
    if ipsec is not None:
        phases = []
        for p in ipsec.findall("phase1"):
            ph = scrub_dict({tag.tag: (tag.text or "").strip() for tag in p})
            phases.append(ph)
        vpn["ipsec"] = {"phase1": phases}
    data["vpn"] = vpn

    # --- DHCP ---
    dhcp = {}
    for node in root:
        if node.tag.startswith("dhcpd"):
            iface_name = node.tag.replace("dhcpd", "") or "lan"
            d = {tag.tag: (tag.text or "").strip() for tag in node}
            dhcp[iface_name] = d
    data["dhcp"] = dhcp

    # --- DNS / Unbound ---
    unbound = root.find("unbound")
    if unbound is not None:
        data["dns"] = {tag.tag: (tag.text or "").strip() for tag in unbound}
    else:
        data["dns"] = {}

    # --- Syslog ---
    syslog = root.find("syslog")
    if syslog is not None:
        data["syslog"] = {tag.tag: (tag.text or "").strip() for tag in syslog}
    else:
        data["syslog"] = {}

    # --- Users (only count, never dump credentials) ---
    system_node = root.find("system")
    user_count = 0
    admin_users = []
    if system_node is not None:
        for user in system_node.findall("user"):
            user_count += 1
            priv = [p.text for p in user.findall("priv") if p.text]
            uname = user.findtext("name", "")
            if "page-all" in priv or "admin" in priv:
                admin_users.append(uname)
    data["user_summary"] = {
        "total_users": user_count,
        "admin_users": admin_users,
        "admin_count": len(admin_users)
    }

    return data

# ─── ANALYSIS ENGINE ────────────────────────────────────────────────────────

SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def analyze(data: dict) -> dict:
    findings = []
    score = 100

    rules = data.get("rules", [])
    interfaces = data.get("interfaces", {})
    vpn = data.get("vpn", {})
    dns = data.get("dns", {})
    syslog = data.get("syslog", {})
    user_summary = data.get("user_summary", {})
    nat = data.get("nat", [])

    def add(severity, category, title, detail, recommendation, rule_ref=None):
        nonlocal score
        score -= SEVERITY[severity]
        findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "recommendation": recommendation,
            "rule_ref": rule_ref,
        })

    # ── Rule Analysis ──────────────────────────────────────────────────────

    has_default_deny = False
    any_any_rules = []
    disabled_rules = []
    no_log_rules = []
    allow_all_outbound = []
    icmp_any = []
    wan_allow_rules = []
    no_description_rules = []
    bogon_not_blocked = True
    antispoof_missing = []

    for i, rule in enumerate(rules):
        action = rule.get("type", rule.get("action", "")).lower()
        iface = rule.get("interface", "")
        disabled = rule.get("disabled", "")
        log = rule.get("log", "")
        descr = rule.get("descr", "").strip()
        proto = rule.get("protocol", "any").lower()

        src = rule.get("source", {})
        dst = rule.get("destination", {})
        src_any = "any" in src or src.get("any") is not None or src.get("network") == "any"
        dst_any = "any" in dst or dst.get("any") is not None or dst.get("network") == "any"

        if disabled in ("1", "true"):
            disabled_rules.append(i)

        if not descr:
            no_description_rules.append(i)

        if action == "block" and src_any and dst_any:
            has_default_deny = True

        if action == "pass" and src_any and dst_any:
            any_any_rules.append(i)

        if action == "pass" and not log and not disabled:
            no_log_rules.append(i)

        if action == "pass" and "wan" in iface.lower() and src_any:
            wan_allow_rules.append(i)

        if proto == "icmp" and src_any:
            icmp_any.append(i)

        if action == "pass" and dst_any and "lan" not in iface.lower():
            allow_all_outbound.append(i)

    # Check bogon blocking on WAN
    for iface_name, iface in interfaces.items():
        if "wan" in iface_name.lower():
            if iface.get("blockbogons", "0") != "1":
                bogon_not_blocked = True
                add("high", "Interfaces", "Bogon Networks Not Blocked on WAN",
                    f"Interface '{iface_name}' does not have bogon network blocking enabled.",
                    "Enable 'Block bogon networks' on all WAN interfaces to prevent spoofed traffic.")
            else:
                bogon_not_blocked = False
            if iface.get("spoofcheck", iface.get("ipspoof", "0")) not in ("1", "enabled"):
                antispoof_missing.append(iface_name)

    if not has_default_deny:
        add("high", "Firewall Rules", "No Default Deny Rule Found",
            "A default deny-all rule at the bottom of your ruleset was not detected.",
            "Add a block rule with source=any, destination=any at the lowest priority to ensure implicit deny.")

    if any_any_rules:
        for idx in any_any_rules:
            r = rules[idx]
            add("critical", "Firewall Rules", "Any-to-Any ALLOW Rule Detected",
                f"Rule #{idx+1} ('{r.get('descr','no description')}') on interface '{r.get('interface','')}' allows all traffic.",
                "Replace any-to-any rules with specific source/destination/port combinations.",
                rule_ref=idx)

    if len(disabled_rules) > 3:
        add("low", "Firewall Rules", f"{len(disabled_rules)} Disabled Rules Accumulating",
            f"Rules at positions {[i+1 for i in disabled_rules[:5]]}... are disabled but still present.",
            "Remove disabled rules periodically to keep the ruleset clean and auditable.")

    if no_log_rules:
        add("medium", "Firewall Rules", f"{len(no_log_rules)} ALLOW Rules Without Logging",
            f"{len(no_log_rules)} active allow rules do not have logging enabled.",
            "Enable logging on all allow rules to maintain an audit trail of permitted connections.")

    if wan_allow_rules:
        for idx in wan_allow_rules:
            r = rules[idx]
            add("high", "Firewall Rules", "WAN Allow Rule with Any Source",
                f"Rule #{idx+1} ('{r.get('descr','no description')}') allows inbound WAN traffic from any source.",
                "Restrict WAN allow rules to specific source IPs or use geographical IP blocking.",
                rule_ref=idx)

    if no_description_rules:
        add("low", "Firewall Rules", f"{len(no_description_rules)} Rules Without Descriptions",
            f"{len(no_description_rules)} rules have no description.",
            "Document all firewall rules with clear descriptions for auditing and team handover.")

    # ── VPN Analysis ───────────────────────────────────────────────────────

    openvpn = vpn.get("openvpn", {})
    for srv in openvpn.get("servers", []):
        cipher = srv.get("crypto", srv.get("cipher", "")).upper()
        digest = srv.get("digest", "").upper()
        tls_auth = srv.get("tls", srv.get("tlsauth", ""))
        protocol = srv.get("protocol", "")
        port = srv.get("local_port", "")

        if cipher and cipher in ("DES", "3DES", "RC4", "BF-CBC", "BLOWFISH"):
            add("critical", "VPN", f"Weak Cipher in OpenVPN Server",
                f"Server uses cipher '{cipher}' which is deprecated or broken.",
                "Use AES-256-GCM or CHACHA20-POLY1305 for OpenVPN encryption.")

        if digest and digest in ("MD5", "SHA1"):
            add("high", "VPN", "Weak HMAC Digest in OpenVPN",
                f"Server uses digest '{digest}' which is cryptographically weak.",
                "Switch to SHA256 or SHA512 for HMAC authentication.")

        if not tls_auth:
            add("medium", "VPN", "OpenVPN TLS Auth/Crypt Not Enabled",
                "TLS authentication key is not configured on an OpenVPN server.",
                "Enable tls-auth or tls-crypt to prevent unauthorized access to the TLS handshake.")

        if protocol and "udp" not in protocol.lower() and port not in ("443", "1194"):
            add("info", "VPN", "OpenVPN Using Non-Standard Port/Protocol",
                f"Server uses {protocol} on port {port}.",
                "Consider UDP 1194 (standard) or TCP 443 (firewall-friendly) for OpenVPN.")

    ipsec = vpn.get("ipsec", {})
    for phase in ipsec.get("phase1", []):
        encryption = phase.get("encryption-algorithm", {})
        if isinstance(encryption, dict):
            alg = encryption.get("name", "").upper()
        else:
            alg = str(encryption).upper()

        if alg in ("DES", "3DES", "BLOWFISH"):
            add("critical", "VPN", f"Weak IPsec Phase1 Encryption",
                f"IPsec Phase1 uses '{alg}'.",
                "Use AES-256-GCM or AES-128-GCM for IPsec Phase1.")

        auth = phase.get("authentication", phase.get("authmethod", ""))
        if auth in ("psk", "pre-shared-key"):
            add("medium", "VPN", "IPsec Using Pre-Shared Key Authentication",
                "IPsec Phase1 uses PSK authentication which is less secure than certificates.",
                "Consider migrating to certificate-based authentication (IKEv2 + EAP) for IPsec.")

    # ── DNS / Unbound ──────────────────────────────────────────────────────

    if dns:
        dnssec = dns.get("dnssec", "0")
        if dnssec not in ("1", "enabled", "true"):
            add("medium", "DNS", "DNSSEC Not Enabled",
                "Unbound DNS resolver does not have DNSSEC validation enabled.",
                "Enable DNSSEC validation in Unbound to protect against DNS spoofing and cache poisoning.")

        dns_rebind = dns.get("rebind_protection", dns.get("rebindprotection", "0"))
        if dns_rebind not in ("1", "enabled", "true"):
            add("medium", "DNS", "DNS Rebinding Protection Not Enabled",
                "Unbound is not configured to block DNS rebinding attacks.",
                "Enable DNS rebinding protection to prevent malicious internal DNS resolution.")

        query_forwarding = dns.get("forwarding", "0")
        if query_forwarding in ("1", "enabled"):
            add("info", "DNS", "DNS Query Forwarding Enabled",
                "Unbound is forwarding queries to an upstream resolver.",
                "Ensure upstream DNS is encrypted (DNS-over-TLS). Consider quad9 (9.9.9.9) or Cloudflare (1.1.1.1) with DoT.")

    # ── Logging & Monitoring ───────────────────────────────────────────────

    if not syslog or all(v in ("", "0") for v in syslog.values()):
        add("high", "Logging", "No Remote Syslog Configured",
            "No remote syslog server is configured.",
            "Configure remote syslog to an external SIEM or log aggregator (e.g., Graylog, Loki, Elastic). Local logs are lost on reboot.")

    # ── Users & Authentication ─────────────────────────────────────────────

    admin_count = user_summary.get("admin_count", 0)
    admin_users = user_summary.get("admin_users", [])

    if admin_count > 3:
        add("medium", "Authentication", f"High Number of Admin Accounts ({admin_count})",
            f"There are {admin_count} users with full administrative privileges.",
            "Follow least-privilege: limit full admin access. Use role-based access for read-only operators.")

    if "admin" in [u.lower() for u in admin_users]:
        add("high", "Authentication", "Default 'admin' Account Has Full Privileges",
            "The default 'admin' account is still active with page-all access.",
            "Rename the admin account or create a named admin user and disable the default admin account.")

    # ── NAT ───────────────────────────────────────────────────────────────

    for i, rule in enumerate(nat):
        dst = rule.get("destination", {})
        dst_any = dst.get("any") is not None or dst.get("network") == "any"
        if dst_any:
            add("medium", "NAT", f"NAT Rule #{i+1} Forwards All Ports",
                f"NAT rule '{rule.get('descr','no description')}' forwards all destination ports.",
                "Restrict NAT port forwarding to specific required ports only.")

    # ── Interface Best Practices ───────────────────────────────────────────

    iface_count = len(interfaces)
    if iface_count < 3:
        add("info", "Architecture", "Consider Network Segmentation",
            f"Only {iface_count} interface(s) defined. Flat networks increase blast radius.",
            "Consider segmenting with DMZ, IoT VLAN, Guest VLAN, and Management VLAN interfaces.")

    # ── Sort by severity ───────────────────────────────────────────────────

    findings.sort(key=lambda f: SEVERITY.get(f["severity"], 0), reverse=True)
    score = max(0, min(100, score))

    return {
        "findings": findings,
        "score": score,
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high": sum(1 for f in findings if f["severity"] == "high"),
            "medium": sum(1 for f in findings if f["severity"] == "medium"),
            "low": sum(1 for f in findings if f["severity"] == "low"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
            "total": len(findings),
        }
    }

# ─── TRAFFIC FLOW MAP ───────────────────────────────────────────────────────

def build_traffic_flow(data: dict) -> dict:
    """Build nodes and edges for the traffic flow diagram."""
    nodes = []
    edges = []
    node_ids = set()

    interfaces = data.get("interfaces", {})
    rules = data.get("rules", [])
    nat = data.get("nat", [])
    vpn = data.get("vpn", {})

    # Create interface nodes
    iface_map = {}
    for name, iface in interfaces.items():
        label = iface.get("descr", name) or name
        itype = "wan" if "wan" in name.lower() else ("lan" if "lan" in name.lower() else "internal")
        node_id = f"iface_{name}"
        nodes.append({
            "id": node_id,
            "label": label.upper(),
            "type": itype,
            "ip": iface.get("ipaddr", ""),
            "subnet": iface.get("subnet", ""),
            "enabled": iface.get("enable", "1") != "0",
        })
        iface_map[name] = node_id
        node_ids.add(node_id)

    # Internet node
    if any("wan" in n.lower() for n in interfaces):
        nodes.append({"id": "internet", "label": "INTERNET", "type": "internet", "ip": "", "subnet": ""})
        node_ids.add("internet")
        for name in interfaces:
            if "wan" in name.lower():
                edges.append({
                    "from": "internet",
                    "to": f"iface_{name}",
                    "label": "WAN",
                    "type": "wan",
                    "bidirectional": True
                })

    # VPN nodes
    openvpn = vpn.get("openvpn", {})
    if openvpn.get("servers") or openvpn.get("clients"):
        nodes.append({"id": "vpn_ovpn", "label": "OpenVPN", "type": "vpn", "ip": "", "subnet": ""})
        node_ids.add("vpn_ovpn")
        for name in interfaces:
            if "wan" in name.lower():
                edges.append({"from": "internet", "to": "vpn_ovpn", "label": "VPN Tunnel", "type": "vpn", "bidirectional": True})
                break

    ipsec = vpn.get("ipsec", {})
    if ipsec.get("phase1"):
        nodes.append({"id": "vpn_ipsec", "label": "IPsec", "type": "vpn", "ip": "", "subnet": ""})
        node_ids.add("vpn_ipsec")
        edges.append({"from": "internet", "to": "vpn_ipsec", "label": "IPsec Tunnel", "type": "vpn", "bidirectional": True})

    # Rule-based edges between interfaces
    edge_set = set()
    for rule in rules:
        if rule.get("disabled") in ("1", "true"):
            continue
        action = rule.get("type", rule.get("action", "pass")).lower()
        iface = rule.get("interface", "")
        src = rule.get("source", {})
        dst = rule.get("destination", {})

        src_net = src.get("network", "")
        dst_net = dst.get("network", "")

        src_node = iface_map.get(src_net) or iface_map.get(iface)
        dst_node = iface_map.get(dst_net)

        if src_node and dst_node and src_node != dst_node:
            ek = (src_node, dst_node, action)
            if ek not in edge_set:
                edge_set.add(ek)
                edges.append({
                    "from": src_node,
                    "to": dst_node,
                    "label": rule.get("descr", action.upper()),
                    "type": action,
                    "bidirectional": False,
                    "protocol": rule.get("protocol", "any"),
                })

    # NAT edges
    for rule in nat:
        src_iface = rule.get("interface", "wan")
        src_node = iface_map.get(src_iface, "internet")
        dst = rule.get("target", "")
        dst_node = None
        for iface_name, iface_id in iface_map.items():
            iface_ip = interfaces.get(iface_name, {}).get("ipaddr", "")
            if dst and iface_ip and dst.startswith(iface_ip.rsplit(".", 1)[0]):
                dst_node = iface_id
                break
        if dst_node and src_node != dst_node:
            edges.append({
                "from": src_node,
                "to": dst_node,
                "label": f"NAT → {rule.get('descr','Port Forward')}",
                "type": "nat",
                "bidirectional": False,
            })

    return {"nodes": nodes, "edges": edges}

# ─── API ENDPOINTS ──────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze_config(file: UploadFile = File(...)):
    """
    Accepts an OPNSense XML backup, parses it in-memory, returns analysis.
    The file is NEVER written to disk. All sensitive values are redacted.
    """
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Only .xml files are accepted.")

    content = await file.read()

    # Limit upload size to 20MB
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20MB).")

    # Parse XML
    data = parse_opnsense_xml(content)

    # Analyze
    analysis = analyze(data)

    # Build traffic flow
    flow = build_traffic_flow(data)

    # Prepare safe summary (no raw XML, no sensitive fields)
    result = {
        "meta": {
            "filename": file.filename,
            "file_hash": hashlib.sha256(content).hexdigest()[:16] + "...",
            "rules_count": len(data.get("rules", [])),
            "interfaces_count": len(data.get("interfaces", {})),
            "nat_rules_count": len(data.get("nat", [])),
            "aliases_count": len(data.get("aliases", [])),
        },
        "system": data.get("system", {}),
        "user_summary": data.get("user_summary", {}),
        "interfaces": {
            k: {
                "descr": v.get("descr", k),
                "ipaddr": v.get("ipaddr", ""),
                "subnet": v.get("subnet", ""),
                "enabled": v.get("enable", "1") != "0",
                "type": "wan" if "wan" in k.lower() else "internal",
                "blockbogons": v.get("blockbogons", "0"),
            }
            for k, v in data.get("interfaces", {}).items()
        },
        "rules_preview": [
            {
                "index": i,
                "action": r.get("type", r.get("action", "?")),
                "interface": r.get("interface", ""),
                "protocol": r.get("protocol", "any"),
                "source": r.get("source", {}),
                "destination": r.get("destination", {}),
                "descr": r.get("descr", "(no description)"),
                "disabled": r.get("disabled", "0"),
                "log": r.get("log", "0"),
            }
            for i, r in enumerate(data.get("rules", []))
        ],
        "nat_preview": [
            {
                "index": i,
                "interface": r.get("interface", ""),
                "protocol": r.get("protocol", "any"),
                "source": r.get("source", {}),
                "destination": r.get("destination", {}),
                "target": r.get("target", ""),
                "local_port": r.get("local-port", ""),
                "descr": r.get("descr", "(no description)"),
            }
            for i, r in enumerate(data.get("nat", []))
        ],
        "vpn_summary": {
            "openvpn_servers": len(data.get("vpn", {}).get("openvpn", {}).get("servers", [])),
            "openvpn_clients": len(data.get("vpn", {}).get("openvpn", {}).get("clients", [])),
            "ipsec_phases": len(data.get("vpn", {}).get("ipsec", {}).get("phase1", [])),
        },
        "analysis": analysis,
        "traffic_flow": flow,
    }

    return JSONResponse(content=result)


@app.get("/health")
async def health():
    return {"status": "ok", "message": "OPNSense Analyzer running"}


# Mount static files (frontend)
import os as _os
_static_dir = _os.environ.get("STATIC_DIR", "/app/frontend/static")
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
