"""
OPNSense Configuration Analyzer - Backend API
Supports modern OPNsense XML format (23.x / 24.x / 25.x).
All processing in-memory. Files never written to disk. Secrets redacted.
"""

import xml.etree.ElementTree as ET
import hashlib
import os
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="OPNSense Analyzer", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST", "GET"], allow_headers=["*"])

# ─── SECURITY: Redact sensitive values ──────────────────────────────────────

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "privkey", "psk", "prv",
    "pin", "passphrase", "ldap_bindpw", "radius_secret",
    "api_key", "apikey", "license_key", "auth_pass"
}

def scrub(key: str, value: str) -> str:
    if any(s in key.lower() for s in SENSITIVE_KEYS):
        return "***REDACTED***"
    return value

def node_to_dict(node) -> dict:
    """Recursively convert an XML node to a dict, scrubbing sensitive keys."""
    d = {}
    for child in node:
        val = node_to_dict(child) if len(child) else (child.text or "")
        if isinstance(val, str):
            val = scrub(child.tag, val)
        if child.tag in d:
            if not isinstance(d[child.tag], list):
                d[child.tag] = [d[child.tag]]
            d[child.tag].append(val)
        else:
            d[child.tag] = val
    return d

# ─── XML PARSING ─────────────────────────────────────────────────────────────

def parse_opnsense_xml(content: bytes) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML: {e}")

    opn = root.find("OPNsense")  # Modern OPNsense plugin config block
    data = {}

    # ── System ──────────────────────────────────────────────────────────────
    sys_node = root.find("system")
    data["system"] = {}
    if sys_node is not None:
        data["system"] = {
            "hostname": sys_node.findtext("hostname", "unknown"),
            "domain":   sys_node.findtext("domain", "unknown"),
            "timezone": sys_node.findtext("timezone", "unknown"),
            "language": sys_node.findtext("language", "en_US"),
        }
        # Version lives in revision block
        rev = root.find("revision")
        if rev is not None:
            data["system"]["version"] = rev.findtext("description", "unknown")

        # Users — count only, never dump credentials
        users = sys_node.findall("user")
        admin_users = []
        for u in users:
            name = u.findtext("name", "")
            privs = [p.text for p in u.findall("priv") if p.text]
            if "page-all" in privs or not privs:  # root/no explicit priv = admin
                admin_users.append(name)
        data["user_summary"] = {
            "total_users": len(users),
            "admin_users": admin_users,
            "admin_count": len(admin_users),
        }

    # ── Interfaces ───────────────────────────────────────────────────────────
    interfaces = {}
    ifaces_node = root.find("interfaces")
    if ifaces_node is not None:
        for iface in ifaces_node:
            tag = iface.tag
            # Skip interface groups (type=group) and loopback
            iface_type = iface.findtext("type", "")
            if iface_type in ("group", "none") or tag == "lo0":
                continue
            descr = iface.findtext("descr", tag)
            ipaddr = iface.findtext("ipaddr", "")
            subnet = iface.findtext("subnet", "")
            hw_if  = iface.findtext("if", "")
            enabled = iface.findtext("enable", "1")

            # Determine WAN vs internal
            is_wan = tag == "wan" or "wanip" in ipaddr.lower() or ipaddr == "dhcp"
            is_wg  = hw_if.startswith("wg")

            interfaces[tag] = {
                "key":          tag,
                "descr":        descr,
                "if":           hw_if,
                "ipaddr":       ipaddr if ipaddr != "dhcp" else "DHCP",
                "subnet":       subnet,
                "enabled":      enabled != "0",
                "type":         "wan" if is_wan else ("wireguard" if is_wg else "internal"),
                "blockbogons":  iface.findtext("blockbogons", "0"),
                "blockpriv":    iface.findtext("blockpriv", "0"),
                "mtu":          iface.findtext("mtu", ""),
            }
    data["interfaces"] = interfaces

    # ── VLANs ────────────────────────────────────────────────────────────────
    vlans = []
    vlans_node = root.find("vlans")
    if vlans_node is not None:
        for vlan in vlans_node.findall("vlan"):
            vlans.append({
                "if":    vlan.findtext("if", ""),
                "tag":   vlan.findtext("tag", ""),
                "descr": vlan.findtext("descr", ""),
                "vlanif": vlan.findtext("vlanif", ""),
            })
    data["vlans"] = vlans

    # ── Firewall Rules (modern: OPNsense/Firewall/Filter/rules) ──────────────
    rules = []
    if opn is not None:
        fw = opn.find("Firewall")
        if fw is not None:
            filt = fw.find("Filter")
            if filt is not None:
                rules_node = filt.find("rules")
                if rules_node is not None:
                    for rule in rules_node:
                        rules.append({
                            "uuid":            rule.get("uuid", ""),
                            "enabled":         rule.findtext("enabled", "1"),
                            "action":          rule.findtext("action", "pass"),
                            "quick":           rule.findtext("quick", "1"),
                            "interface":       rule.findtext("interface", ""),
                            "direction":       rule.findtext("direction", "in"),
                            "ipprotocol":      rule.findtext("ipprotocol", "inet"),
                            "protocol":        rule.findtext("protocol", "any"),
                            "source_net":      rule.findtext("source_net", "any"),
                            "source_not":      rule.findtext("source_not", "0"),
                            "source_port":     rule.findtext("source_port", ""),
                            "destination_net": rule.findtext("destination_net", "any"),
                            "destination_not": rule.findtext("destination_not", "0"),
                            "destination_port":rule.findtext("destination_port", ""),
                            "log":             rule.findtext("log", "0"),
                            "description":     rule.findtext("description", ""),
                            "sequence":        rule.findtext("sequence", "0"),
                            "categories":      rule.findtext("categories", ""),
                            "gateway":         rule.findtext("gateway", ""),
                        })
    # Sort by sequence
    rules.sort(key=lambda r: int(r.get("sequence") or 0))
    data["rules"] = rules

    # ── NAT Rules ────────────────────────────────────────────────────────────
    nat_rules = []
    nat_node = root.find("nat")
    if nat_node is not None:
        for rule in nat_node.findall("rule"):
            if rule.findtext("nordr") == "1":
                continue  # skip no-redirect rules
            src = rule.find("source")
            dst = rule.find("destination")
            nat_rules.append({
                "disabled":   rule.findtext("disabled", "0"),
                "interface":  rule.findtext("interface", "wan"),
                "protocol":   rule.findtext("protocol", "any"),
                "source_net": src.findtext("network", "any") if src is not None else "any",
                "source_port":src.findtext("port", "") if src is not None else "",
                "dest_net":   dst.findtext("network", "any") if dst is not None else "any",
                "dest_port":  dst.findtext("port", "") if dst is not None else "",
                "target":     rule.findtext("target", ""),
                "local_port": rule.findtext("local-port", ""),
                "descr":      rule.findtext("descr", ""),
                "category":   rule.findtext("category", ""),
                "sequence":   rule.findtext("sequence", "0"),
            })
    nat_rules.sort(key=lambda r: int(r.get("sequence") or 0))
    data["nat"] = nat_rules

    # ── Aliases ───────────────────────────────────────────────────────────────
    aliases = []
    if opn is not None:
        fw = opn.find("Firewall")
        if fw is not None:
            alias_node = fw.find("Alias/aliases")
            if alias_node is not None:
                for alias in alias_node:
                    aliases.append({
                        "name":        alias.findtext("name", ""),
                        "type":        alias.findtext("type", ""),
                        "description": alias.findtext("description", ""),
                        "content":     alias.findtext("content", ""),
                        "enabled":     alias.findtext("enabled", "1"),
                    })
    data["aliases"] = aliases

    # ── WireGuard ─────────────────────────────────────────────────────────────
    wg_servers = []
    wg_clients = []
    if opn is not None:
        wg = opn.find("wireguard")
        if wg is not None:
            srv_node = wg.find("server/servers")
            if srv_node is not None:
                for srv in srv_node:
                    wg_servers.append({
                        "name":           srv.findtext("name", ""),
                        "enabled":        srv.findtext("enabled", "0"),
                        "instance":       srv.findtext("instance", ""),
                        "port":           srv.findtext("port", ""),
                        "tunneladdress":  srv.findtext("tunneladdress", ""),
                        "dns":            srv.findtext("dns", ""),
                        "mtu":            srv.findtext("mtu", ""),
                        "disableroutes":  srv.findtext("disableroutes", "0"),
                        "pubkey":         srv.findtext("pubkey", ""),
                        # privkey intentionally excluded (never returned)
                    })
            cli_node = wg.find("client/clients")
            if cli_node is not None:
                for cli in cli_node:
                    wg_clients.append({
                        "name":          cli.findtext("name", ""),
                        "enabled":       cli.findtext("enabled", "0"),
                        "tunneladdress": cli.findtext("tunneladdress", ""),
                        "serveraddress": cli.findtext("serveraddress", ""),
                        "serverport":    cli.findtext("serverport", ""),
                        "keepalive":     cli.findtext("keepalive", ""),
                        "pubkey":        cli.findtext("pubkey", ""),
                        # psk intentionally excluded
                    })
    data["wireguard"] = {"servers": wg_servers, "clients": wg_clients}

    # ── OpenVPN ───────────────────────────────────────────────────────────────
    ovpn_servers, ovpn_clients = [], []
    ovpn_node = root.find("openvpn")
    if ovpn_node is not None:
        for srv in ovpn_node.findall("openvpn-server"):
            ovpn_servers.append({
                "mode":      srv.findtext("mode", ""),
                "protocol":  srv.findtext("protocol", ""),
                "port":      srv.findtext("local_port", ""),
                "cipher":    srv.findtext("crypto", srv.findtext("cipher", "")),
                "digest":    srv.findtext("digest", ""),
                "tls":       srv.findtext("tls", ""),
                "descr":     srv.findtext("description", srv.findtext("descr", "")),
            })
        for cli in ovpn_node.findall("openvpn-client"):
            ovpn_clients.append({
                "server_addr": cli.findtext("server_addr", ""),
                "protocol":    cli.findtext("protocol", ""),
                "port":        cli.findtext("server_port", ""),
                "cipher":      cli.findtext("crypto", cli.findtext("cipher", "")),
                "digest":      cli.findtext("digest", ""),
            })
    data["openvpn"] = {"servers": ovpn_servers, "clients": ovpn_clients}

    # ── DNS (unboundplus) ─────────────────────────────────────────────────────
    data["dns"] = {}
    if opn is not None:
        ub = opn.find("unboundplus")
        if ub is not None:
            gen = ub.find("general")
            adv = ub.find("advanced")
            data["dns"] = {
                "enabled":         gen.findtext("enabled", "0") if gen is not None else "0",
                "dnssec":          gen.findtext("dnssec", "0") if gen is not None else "0",
                "port":            gen.findtext("port", "53") if gen is not None else "53",
                "active_interface":gen.findtext("active_interface", "") if gen is not None else "",
                "hideidentity":    adv.findtext("hideidentity", "0") if adv is not None else "0",
                "hideversion":     adv.findtext("hideversion", "0") if adv is not None else "0",
                "dnssecstripped":  adv.findtext("dnssecstripped", "0") if adv is not None else "0",
            }

    # ── Syslog ────────────────────────────────────────────────────────────────
    data["syslog"] = {"enabled": "0", "remote_destinations": 0}
    if opn is not None:
        sl = opn.find("Syslog")
        if sl is not None:
            gen = sl.find("general")
            dests = sl.find("destinations")
            data["syslog"] = {
                "enabled":             gen.findtext("enabled", "0") if gen is not None else "0",
                "loglocal":            gen.findtext("loglocal", "0") if gen is not None else "0",
                "remote_destinations": len(list(dests)) if dests is not None else 0,
            }

    # ── IDS/IPS ───────────────────────────────────────────────────────────────
    data["ids"] = {"enabled": "0", "active_rules": 0}
    if opn is not None:
        ids = opn.find("IDS")
        if ids is not None:
            settings = ids.find("general")
            if settings is None:
                settings = ids.find("settings")
            enabled_rules = [f for f in ids.findall("files/file") if f.findtext("enabled") == "1"]
            data["ids"] = {
                "enabled":      settings.findtext("enabled", "0") if settings is not None else "0",
                "active_rules": len(enabled_rules),
            }

    # ── Zenarmor ─────────────────────────────────────────────────────────────
    data["zenarmor"] = {"present": False}
    if opn is not None:
        zen = opn.find("Zenarmor")
        if zen is not None:
            data["zenarmor"] = {"present": True}

    return data

# ─── ANALYSIS ENGINE ─────────────────────────────────────────────────────────

SEVERITY_SCORE = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

def analyze(data: dict) -> dict:
    findings = []
    score = 100

    rules      = data.get("rules", [])
    interfaces = data.get("interfaces", {})
    wg         = data.get("wireguard", {})
    openvpn    = data.get("openvpn", {})
    dns        = data.get("dns", {})
    syslog     = data.get("syslog", {})
    nat        = data.get("nat", [])
    ids        = data.get("ids", {})
    users      = data.get("user_summary", {})
    vlans      = data.get("vlans", [])

    def add(severity, category, title, detail, recommendation, rule_ref=None):
        nonlocal score
        score -= SEVERITY_SCORE[severity]
        findings.append({
            "severity": severity, "category": category,
            "title": title, "detail": detail,
            "recommendation": recommendation, "rule_ref": rule_ref,
        })

    active_rules = [r for r in rules if r.get("enabled", "1") == "1"]

    # ── Firewall Rules ────────────────────────────────────────────────────────

    any_any_pass = []
    wan_any_src_pass = []
    no_log_pass = []
    no_desc = []
    disabled_rules = [r for r in rules if r.get("enabled", "1") != "1"]
    has_block_all = False

    for r in active_rules:
        action   = r.get("action", "pass").lower()
        iface    = r.get("interface", "")
        src      = r.get("source_net", "any")
        dst      = r.get("destination_net", "any")
        log      = r.get("log", "0")
        descr    = r.get("description", "").strip()
        src_any  = src in ("any", "") or src.lower() == "any"
        dst_any  = dst in ("any", "") or dst.lower() == "any"
        is_wan   = "wan" in iface.lower()

        if not descr:
            no_desc.append(r)

        if action == "block" and src_any and dst_any:
            has_block_all = True

        if action == "pass" and src_any and dst_any:
            any_any_pass.append(r)

        if action == "pass" and is_wan and src_any:
            wan_any_src_pass.append(r)

        if action == "pass" and log == "0":
            no_log_pass.append(r)

    if not has_block_all:
        add("medium", "Firewall", "No Explicit Default-Deny Block Rule Found",
            "No block rule with source=any / destination=any was detected. OPNsense has an implicit deny, but an explicit rule makes the policy auditable.",
            "Add a block rule at the lowest sequence with source=any, destination=any and logging enabled.")

    for r in any_any_pass:
        add("critical", "Firewall", f"Any-to-Any ALLOW on '{r.get('interface','?')}'",
            f"Rule '{r.get('description','(no description)')}' (seq {r.get('sequence','?')}) allows all traffic from any source to any destination.",
            "Replace with specific source/destination/port combinations.")

    for r in wan_any_src_pass:
        add("high", "Firewall", f"WAN ALLOW from Any Source — Port {r.get('destination_port','any')}",
            f"Rule '{r.get('description','(no description)')}' (seq {r.get('sequence','?')}) permits inbound WAN traffic from any IP.",
            "Restrict inbound WAN rules to specific source IPs, geo-blocks, or known ranges wherever possible.")

    if len(no_log_pass) > 5:
        add("medium", "Firewall", f"{len(no_log_pass)} ALLOW Rules Without Logging",
            f"{len(no_log_pass)} active allow rules have logging disabled.",
            "Enable logging on allow rules — especially WAN and inter-VLAN — to maintain an audit trail.")

    if len(disabled_rules) > 5:
        add("low", "Firewall", f"{len(disabled_rules)} Disabled Rules Accumulating",
            f"{len(disabled_rules)} rules are disabled but still in the ruleset.",
            "Remove or document disabled rules regularly to keep the ruleset maintainable.")

    if len(no_desc) > 3:
        add("low", "Firewall", f"{len(no_desc)} Rules Without Descriptions",
            f"{len(no_desc)} rules have no description.",
            "Document every rule with a clear description — who requested it, why, and when.")

    # ── Interfaces ────────────────────────────────────────────────────────────

    wan_ifaces = [i for i in interfaces.values() if i["type"] == "wan"]
    for iface in wan_ifaces:
        if iface.get("blockbogons") != "1":
            add("high", "Interfaces", f"Bogon Blocking Disabled on WAN '{iface['descr']}'",
                f"Interface '{iface['descr']}' ({iface['if']}) does not block bogon/martian networks.",
                "Enable 'Block bogon networks' on all WAN interfaces.")
        if iface.get("blockpriv") != "1":
            add("medium", "Interfaces", f"Private Network Blocking Disabled on WAN '{iface['descr']}'",
                f"Interface '{iface['descr']}' ({iface['if']}) does not block RFC1918 addresses inbound from WAN.",
                "Enable 'Block private networks' on all WAN interfaces to prevent spoofed RFC1918 traffic.")

    if not vlans and len(interfaces) < 4:
        add("info", "Architecture", "Consider VLAN Segmentation",
            f"Only {len(interfaces)} interface(s) detected with no VLANs. Flat networks increase blast radius.",
            "Use VLANs to segment IoT, Guest, Servers, and Management traffic.")

    # ── WireGuard ─────────────────────────────────────────────────────────────

    wg_servers = wg.get("servers", [])
    wg_clients = wg.get("clients", [])

    for srv in wg_servers:
        if not srv.get("port") and srv.get("disableroutes") == "0":
            add("info", "WireGuard", f"WireGuard Instance '{srv.get('name','?')}' Has No Listen Port Set",
                "No explicit listen port configured — WireGuard will use a system-assigned port.",
                "Set an explicit listen port for reproducibility and firewall rule stability.")
        if not srv.get("dns"):
            add("low", "WireGuard", f"No DNS Configured on WireGuard Server '{srv.get('name','?')}'",
                "The WireGuard instance has no DNS server configured for clients.",
                "Set the DNS field to your internal resolver so VPN clients use your DNS.")

    if wg_servers or wg_clients:
        # Check if WAN allow rules exist for WireGuard ports
        wg_ports = {s.get("port") for s in wg_servers if s.get("port")}
        rule_ports = {r.get("destination_port") for r in active_rules if r.get("action") == "pass" and "wan" in r.get("interface","").lower()}
        for port in wg_ports:
            if port not in rule_ports:
                add("info", "WireGuard", f"No WAN Allow Rule Found for WireGuard Port {port}",
                    f"WireGuard server listens on port {port} but no matching WAN allow rule was found.",
                    "Ensure a WAN firewall rule allows UDP traffic to this port, or check if it's handled via another rule.")

    # ── OpenVPN ───────────────────────────────────────────────────────────────

    for srv in openvpn.get("servers", []):
        cipher = srv.get("cipher", "").upper()
        digest = srv.get("digest", "").upper()
        tls    = srv.get("tls", "")
        if cipher and cipher in ("DES", "3DES", "RC4", "BF-CBC", "BLOWFISH", "CAST5"):
            add("critical", "OpenVPN", f"Weak Cipher: {cipher}",
                f"OpenVPN server '{srv.get('descr','?')}' uses deprecated cipher {cipher}.",
                "Migrate to AES-256-GCM or CHACHA20-POLY1305.")
        if digest and digest in ("MD5", "SHA1"):
            add("high", "OpenVPN", f"Weak HMAC Digest: {digest}",
                f"OpenVPN server uses {digest} for packet authentication.",
                "Switch to SHA256 or SHA512.")
        if not tls:
            add("medium", "OpenVPN", "TLS Auth/Crypt Not Configured",
                "No TLS auth or TLS crypt key is set on an OpenVPN server.",
                "Enable tls-crypt (preferred) or tls-auth to prevent unauthenticated TLS handshakes.")

    # ── DNS ───────────────────────────────────────────────────────────────────

    if dns:
        if dns.get("dnssec") != "1":
            add("medium", "DNS", "DNSSEC Validation Disabled",
                "Unbound DNS resolver does not validate DNSSEC signatures.",
                "Enable DNSSEC in Services → Unbound DNS → General.")
        if dns.get("hideidentity") != "1":
            add("low", "DNS", "DNS Identity Not Hidden",
                "Unbound will respond to 'id.server' and 'hostname.bind' queries, revealing resolver identity.",
                "Enable 'Hide Identity' in Unbound advanced settings.")
        if dns.get("hideversion") != "1":
            add("low", "DNS", "DNS Version Not Hidden",
                "Unbound will reveal its version string to querying clients.",
                "Enable 'Hide Version' in Unbound advanced settings.")

    # ── Syslog ────────────────────────────────────────────────────────────────

    if syslog.get("remote_destinations", 0) == 0:
        add("high", "Logging", "No Remote Syslog Destination Configured",
            "All logs are stored locally only. Local logs are lost on reset or hardware failure.",
            "Configure at least one remote syslog destination (SIEM, Graylog, Loki, etc.) under System → Logging → Remote.")

    # ── IDS/IPS ───────────────────────────────────────────────────────────────

    if ids.get("enabled") != "1":
        add("medium", "IDS/IPS", "Intrusion Detection System Not Enabled",
            "Suricata IDS/IPS is not active. Threats passing through the firewall will not be inspected.",
            "Enable IDS/IPS under Services → Intrusion Detection and enable relevant rulesets (ET Open at minimum).")
    elif ids.get("active_rules", 0) == 0:
        add("medium", "IDS/IPS", "IDS Enabled But No Active Rulesets",
            "Suricata is enabled but no rule files are active — it will not detect anything.",
            "Enable at least the Emerging Threats Open ruleset under Services → Intrusion Detection → Download.")

    # ── NAT ───────────────────────────────────────────────────────────────────

    active_nat = [r for r in nat if r.get("disabled") != "1"]
    for r in active_nat:
        if not r.get("dest_port") and r.get("interface") == "wan":
            add("medium", "NAT", f"NAT Rule '{r.get('descr','?')}' Forwards All Ports",
                f"Port forward rule '{r.get('descr','(no description)')}' has no destination port restriction.",
                "Restrict NAT rules to specific ports only.")

    # ── Users ─────────────────────────────────────────────────────────────────

    if users.get("admin_count", 0) > 2:
        add("medium", "Authentication", f"{users['admin_count']} Full Admin Accounts",
            f"Accounts with full admin access: {', '.join(users.get('admin_users', []))}",
            "Apply least-privilege. Use scoped operator roles for non-root admins.")

    if "root" in users.get("admin_users", []) and users.get("total_users", 0) == 1:
        add("low", "Authentication", "Only the Root Account Exists",
            "All administration is done via the root account with no named user accounts.",
            "Create named administrator accounts with appropriate roles for accountability and auditability.")

    # Sort and cap score
    findings.sort(key=lambda f: SEVERITY_SCORE.get(f["severity"], 0), reverse=True)
    score = max(0, min(100, score))

    return {
        "findings": findings,
        "score": score,
        "summary": {
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "high":     sum(1 for f in findings if f["severity"] == "high"),
            "medium":   sum(1 for f in findings if f["severity"] == "medium"),
            "low":      sum(1 for f in findings if f["severity"] == "low"),
            "info":     sum(1 for f in findings if f["severity"] == "info"),
            "total":    len(findings),
        }
    }

# ─── TRAFFIC FLOW MAP ────────────────────────────────────────────────────────

def build_traffic_flow(data: dict) -> dict:
    interfaces = data.get("interfaces", {})
    rules      = data.get("rules", [])
    nat        = data.get("nat", [])
    wg         = data.get("wireguard", {})

    nodes = []
    edges = []
    seen_nodes = set()

    def add_node(nid, label, ntype, ip="", subnet=""):
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            nodes.append({"id": nid, "label": label, "type": ntype, "ip": ip, "subnet": subnet})

    # Internet node
    add_node("internet", "INTERNET", "internet")

    # Interface nodes
    iface_id_map = {}  # interface key → node id
    for key, iface in interfaces.items():
        if not iface.get("enabled", True):
            continue
        nid = f"iface_{key}"
        iface_id_map[key] = nid
        ntype = iface["type"]
        add_node(nid, iface["descr"], ntype, iface.get("ipaddr",""), iface.get("subnet",""))

    # Connect internet → WAN
    for key, iface in interfaces.items():
        if iface["type"] == "wan" and iface.get("enabled", True):
            edges.append({"from": "internet", "to": iface_id_map[key],
                         "label": "WAN", "type": "wan", "bidirectional": True})

    # WireGuard tunnel nodes
    for srv in wg.get("servers", []):
        if srv.get("enabled") == "1" and not srv.get("disableroutes") == "1":
            nid = f"wg_{srv['name']}"
            add_node(nid, srv["name"], "wireguard", srv.get("tunneladdress",""))
            # Connect to internet via WAN
            for key, iface in interfaces.items():
                if iface["type"] == "wan":
                    edges.append({"from": iface_id_map[key], "to": nid,
                                 "label": f"WG:{srv.get('port','?')}", "type": "vpn", "bidirectional": True})
                    break

    # Outbound WireGuard clients (tunnels to external)
    for cli in wg.get("clients", []):
        if cli.get("enabled") == "1" and cli.get("serveraddress"):
            nid = f"wgcli_{cli['name']}"
            add_node(nid, cli["name"], "vpn_out", cli.get("serveraddress",""))
            edges.append({"from": "internet", "to": nid,
                         "label": f"WG→{cli.get('serveraddress','?')}", "type": "vpn", "bidirectional": True})

    # Rule-based inter-interface edges (deduplicated)
    seen_edges = set()
    active_rules = [r for r in rules if r.get("enabled","1") == "1"]
    for rule in active_rules:
        action = rule.get("action","pass").lower()
        if action not in ("pass",):
            continue
        src_key = rule.get("interface","")
        dst_net  = rule.get("destination_net","any")
        dst_key  = None

        # Try to match destination network to an interface
        for key, iface in interfaces.items():
            ip = iface.get("ipaddr","")
            if dst_net == key or (ip and dst_net.startswith(ip.rsplit(".",1)[0])):
                dst_key = key
                break

        src_node = iface_id_map.get(src_key)
        dst_node = iface_id_map.get(dst_key) if dst_key else None

        if src_node and dst_node and src_node != dst_node:
            ek = (src_node, dst_node)
            if ek not in seen_edges:
                seen_edges.add(ek)
                port = rule.get("destination_port","")
                proto = rule.get("protocol","any")
                lbl = rule.get("description","") or f"{proto}/{port}" if port else proto
                edges.append({"from": src_node, "to": dst_node,
                             "label": lbl[:30], "type": "pass", "bidirectional": False})

    # NAT port-forward edges (WAN → internal target)
    for r in nat:
        if r.get("disabled") == "1":
            continue
        target_ip = r.get("target","")
        src_iface = r.get("interface","wan")
        src_node  = iface_id_map.get(src_iface, "internet")
        # Find which interface the target IP belongs to
        dst_node  = None
        for key, iface in interfaces.items():
            ip = iface.get("ipaddr","")
            if target_ip and ip and target_ip.startswith(ip.rsplit(".",1)[0]):
                dst_node = iface_id_map.get(key)
                break
        if dst_node and src_node != dst_node:
            port = r.get("local_port","")
            edges.append({"from": src_node, "to": dst_node,
                         "label": f"NAT:{port}" if port else f"NAT:{r.get('descr','')}",
                         "type": "nat", "bidirectional": False})

    return {"nodes": nodes, "edges": edges}

# ─── API ENDPOINTS ────────────────────────────────────────────────────────────

@app.post("/api/analyze")
async def analyze_config(file: UploadFile = File(...)):
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Only .xml files are accepted.")

    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (max 20MB).")

    data     = parse_opnsense_xml(content)
    analysis = analyze(data)
    flow     = build_traffic_flow(data)

    result = {
        "meta": {
            "filename":        file.filename,
            "file_hash":       hashlib.sha256(content).hexdigest()[:16] + "...",
            "rules_count":     len(data.get("rules", [])),
            "interfaces_count":len(data.get("interfaces", {})),
            "nat_rules_count": len(data.get("nat", [])),
            "aliases_count":   len(data.get("aliases", [])),
            "vlans_count":     len(data.get("vlans", [])),
            "wg_tunnels":      len(data.get("wireguard",{}).get("servers",[])),
        },
        "system":      data.get("system", {}),
        "user_summary":data.get("user_summary", {}),
        "interfaces":  data.get("interfaces", {}),
        "vlans":       data.get("vlans", []),
        "rules_preview": [
            {
                "index":       i,
                "enabled":     r.get("enabled","1"),
                "action":      r.get("action","pass"),
                "interface":   r.get("interface",""),
                "direction":   r.get("direction","in"),
                "protocol":    r.get("protocol","any"),
                "source":      r.get("source_net","any"),
                "source_port": r.get("source_port",""),
                "destination": r.get("destination_net","any"),
                "dest_port":   r.get("destination_port",""),
                "log":         r.get("log","0"),
                "description": r.get("description",""),
                "sequence":    r.get("sequence",""),
                "gateway":     r.get("gateway",""),
            }
            for i, r in enumerate(data.get("rules", []))
        ],
        "nat_preview": [
            {
                "index":      i,
                "disabled":   r.get("disabled","0"),
                "interface":  r.get("interface",""),
                "protocol":   r.get("protocol",""),
                "source":     r.get("source_net","any"),
                "dest":       r.get("dest_net","any"),
                "dest_port":  r.get("dest_port",""),
                "target":     r.get("target",""),
                "local_port": r.get("local_port",""),
                "descr":      r.get("descr",""),
                "category":   r.get("category",""),
            }
            for i, r in enumerate(data.get("nat", []))
        ],
        "aliases":     data.get("aliases", []),
        "wireguard":   data.get("wireguard", {}),
        "openvpn_summary": {
            "servers": len(data.get("openvpn",{}).get("servers",[])),
            "clients": len(data.get("openvpn",{}).get("clients",[])),
        },
        "dns":      data.get("dns", {}),
        "syslog":   data.get("syslog", {}),
        "ids":      data.get("ids", {}),
        "zenarmor": data.get("zenarmor", {}),
        "analysis":      analysis,
        "traffic_flow":  flow,
    }
    return JSONResponse(content=result)


@app.get("/health")
async def health():
    return {"status": "ok"}


_static_dir = os.environ.get("STATIC_DIR", "/app/frontend/static")
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
