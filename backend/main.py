"""
OPNSense Configuration Analyzer - Backend API
Comprehensive audit engine for OPNsense 23.x / 24.x / 25.x
All processing in-memory. Files never written to disk. Secrets redacted.
"""

import xml.etree.ElementTree as ET
import hashlib, os, base64, ipaddress, datetime
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="OPNSense Analyzer", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["POST","GET"], allow_headers=["*"])

# ─── REDACTION ────────────────────────────────────────────────────────────────
SENSITIVE_KEYS = {"password","passwd","secret","privkey","psk","prv","pin",
                  "passphrase","ldap_bindpw","radius_secret","api_key","apikey",
                  "license_key","auth_pass","otp_seed","authorizedkeys"}

def scrub(key, value):
    return "***REDACTED***" if any(s in key.lower() for s in SENSITIVE_KEYS) else value

def xt(node, tag, default=""):
    """Safe findtext"""
    v = node.findtext(tag, default) if node is not None else default
    return (v or default).strip()

# ─── CERT PARSING ─────────────────────────────────────────────────────────────
def parse_cert_dates(b64_crt):
    """Extract not-before / not-after from a base64 DER or PEM certificate."""
    try:
        raw = b64_crt.strip()
        # Could be PEM in base64 or raw base64 DER
        try:
            der = base64.b64decode(raw + "==")
        except Exception:
            return None, None
        # Try to decode as PEM first (base64-encoded PEM)
        try:
            pem_text = der.decode("utf-8", errors="ignore")
            if "BEGIN CERTIFICATE" in pem_text:
                # Extract DER from PEM
                lines = [l for l in pem_text.splitlines()
                         if l and "BEGIN" not in l and "END" not in l]
                der = base64.b64decode("".join(lines) + "==")
        except Exception:
            pass
        # Use cryptography if available, else manual ASN.1 parse
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_der_x509_certificate(der, default_backend())
            return cert.not_valid_before_utc.isoformat(), cert.not_valid_after_utc.isoformat()
        except Exception:
            pass
        # Fallback: rough ASN.1 scan for UTCTime / GeneralizedTime
        def find_dates(data):
            dates = []
            i = 0
            while i < len(data) - 15:
                tag = data[i]
                if tag in (0x17, 0x18):  # UTCTime or GeneralizedTime
                    length = data[i+1]
                    val = data[i+2:i+2+length].decode("ascii", errors="ignore")
                    dates.append(val)
                    if len(dates) == 2:
                        break
                i += 1
            return dates
        dates = find_dates(der)
        if len(dates) >= 2:
            def parse_dt(s):
                try:
                    if len(s) == 13:  # UTCTime YYMMDDHHMMSSZ
                        y = int(s[:2]); y += 2000 if y < 50 else 1900
                        return f"{y}-{s[2:4]}-{s[4:6]}T{s[6:8]}:{s[8:10]}:{s[10:12]}Z"
                    elif len(s) >= 14:  # GeneralizedTime YYYYMMDDHHMMSSZ
                        return f"{s[:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}Z"
                except Exception:
                    pass
                return s
            return parse_dt(dates[0]), parse_dt(dates[1])
    except Exception:
        pass
    return None, None

def cert_days_remaining(not_after_iso):
    try:
        na = not_after_iso.replace("Z","").rstrip("+00:00")
        dt = datetime.datetime.fromisoformat(na)
        now = datetime.datetime.utcnow()
        return (dt - now).days
    except Exception:
        return None

# ─── IP HELPERS ───────────────────────────────────────────────────────────────
def is_private(ip_str):
    try:
        return ipaddress.ip_address(ip_str.split("/")[0]).is_private
    except Exception:
        return False

def ip_in_range(ip_str, range_from, range_to):
    try:
        ip  = ipaddress.ip_address(ip_str)
        frm = ipaddress.ip_address(range_from)
        too = ipaddress.ip_address(range_to)
        return frm <= ip <= too
    except Exception:
        return False

# ─── XML PARSING ─────────────────────────────────────────────────────────────
def parse_opnsense_xml(content: bytes) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(status_code=400, detail=f"Invalid XML: {e}")

    opn = root.find("OPNsense")
    data = {}

    # ── System ──────────────────────────────────────────────────────────────
    sys_node = root.find("system")
    rev_node = root.find("revision")
    data["system"] = {
        "hostname": xt(sys_node,"hostname","unknown"),
        "domain":   xt(sys_node,"domain","unknown"),
        "timezone": xt(sys_node,"timezone","unknown"),
        "language": xt(sys_node,"language","en_US"),
        "version":  xt(rev_node,"description","unknown"),
        "last_change_by":   xt(rev_node,"username","unknown"),
        "last_change_time": xt(rev_node,"time",""),
    }

    # ── Users ────────────────────────────────────────────────────────────────
    users_data = []
    if sys_node is not None:
        for u in sys_node.findall("user"):
            name     = xt(u,"name")
            privs    = [p.text for p in u.findall("priv") if p.text]
            has_otp  = bool(xt(u,"otp_seed"))
            has_keys = bool(xt(u,"authorizedkeys"))
            api_keys = u.find("apikeys")
            n_api    = len(list(api_keys)) if api_keys is not None else 0
            disabled = xt(u,"disabled","0") == "1"
            expires  = xt(u,"expires","")
            has_pw   = bool(xt(u,"password"))
            is_admin = "page-all" in privs or not privs
            users_data.append({
                "name":     name,
                "uid":      xt(u,"uid",""),
                "is_admin": is_admin,
                "disabled": disabled,
                "has_otp":  has_otp,
                "has_password": has_pw,
                "has_ssh_keys": has_keys,
                "api_key_count": n_api,
                "expires":  expires,
                "privs":    privs,
            })
    data["users"] = users_data
    data["user_summary"] = {
        "total_users":  len(users_data),
        "admin_users":  [u["name"] for u in users_data if u["is_admin"]],
        "admin_count":  sum(1 for u in users_data if u["is_admin"]),
        "otp_enabled":  sum(1 for u in users_data if u["has_otp"]),
        "total_api_keys": sum(u["api_key_count"] for u in users_data),
    }

    # ── SSH / WebGUI ─────────────────────────────────────────────────────────
    ssh_node = sys_node.find("ssh") if sys_node is not None else None
    data["ssh"] = {
        "enabled":        xt(ssh_node,"enabled","") in ("enabled","1"),
        "port":           xt(ssh_node,"port","22"),
        "password_auth":  xt(ssh_node,"passwordauth","0") == "1",
        "permit_root":    xt(ssh_node,"permitrootlogin","0") == "1",
        "interfaces":     xt(ssh_node,"interfaces",""),
    }
    wg_node = sys_node.find("webgui") if sys_node is not None else None
    data["webgui"] = {
        "protocol":  xt(wg_node,"protocol","https"),
        "port":      xt(wg_node,"port","443") or "443",
        "interfaces":xt(wg_node,"interfaces",""),
        "certref":   xt(wg_node,"ssl-certref",""),
        "no_redirect":xt(wg_node,"disablehttpredirect","0") == "1",
    }

    # ── Certificates ─────────────────────────────────────────────────────────
    certs = []
    for c in root.findall("cert"):
        crt_b64  = xt(c,"crt")
        not_bef, not_aft = parse_cert_dates(crt_b64) if crt_b64 else (None,None)
        days_rem = cert_days_remaining(not_aft) if not_aft else None
        caref    = xt(c,"caref","")
        certs.append({
            "refid":       xt(c,"refid"),
            "descr":       xt(c,"descr"),
            "caref":       caref,
            "self_signed": caref == "",
            "not_before":  not_bef,
            "not_after":   not_aft,
            "days_remaining": days_rem,
        })
    # CAs
    for c in root.findall("ca"):
        crt_b64  = xt(c,"crt")
        not_bef, not_aft = parse_cert_dates(crt_b64) if crt_b64 else (None,None)
        days_rem = cert_days_remaining(not_aft) if not_aft else None
        certs.append({
            "refid":       xt(c,"refid"),
            "descr":       xt(c,"descr") + " (CA)",
            "caref":       "",
            "self_signed": True,
            "not_before":  not_bef,
            "not_after":   not_aft,
            "days_remaining": days_rem,
        })
    data["certs"] = certs

    # ── Interfaces ───────────────────────────────────────────────────────────
    interfaces = {}
    ifaces_node = root.find("interfaces")
    if ifaces_node is not None:
        for iface in ifaces_node:
            tag      = iface.tag
            itype    = xt(iface,"type","")
            if itype in ("group","none") or tag in ("lo0","loopback"):
                continue
            hw_if    = xt(iface,"if","")
            ipaddr   = xt(iface,"ipaddr","")
            is_wan   = tag == "wan" or itype == "wan"
            is_wg    = hw_if.startswith("wg")
            interfaces[tag] = {
                "key":         tag,
                "descr":       xt(iface,"descr",tag),
                "if":          hw_if,
                "ipaddr":      "DHCP" if ipaddr == "dhcp" else ipaddr,
                "subnet":      xt(iface,"subnet",""),
                "enabled":     xt(iface,"enable","1") != "0",
                "type":        "wan" if is_wan else ("wireguard" if is_wg else "internal"),
                "blockbogons": xt(iface,"blockbogons","0"),
                "blockpriv":   xt(iface,"blockpriv","0"),
                "spoofcheck":  xt(iface,"spoofcheck","0"),
                "mtu":         xt(iface,"mtu",""),
                "ipaddrv6":    xt(iface,"ipaddrv6",""),
            }
    data["interfaces"] = interfaces

    # ── VLANs ────────────────────────────────────────────────────────────────
    vlans = []
    vn = root.find("vlans")
    if vn is not None:
        for v in vn.findall("vlan"):
            vlans.append({"if":xt(v,"if"),"tag":xt(v,"tag"),"descr":xt(v,"descr"),"vlanif":xt(v,"vlanif")})
    data["vlans"] = vlans

    # ── Firewall Rules ────────────────────────────────────────────────────────
    rules = []
    if opn is not None:
        fw   = opn.find("Firewall")
        filt = fw.find("Filter") if fw is not None else None
        rn   = filt.find("rules") if filt is not None else None
        if rn is not None:
            for r in rn:
                rules.append({
                    "uuid":         r.get("uuid",""),
                    "enabled":      xt(r,"enabled","1"),
                    "action":       xt(r,"action","pass"),
                    "quick":        xt(r,"quick","1"),
                    "interface":    xt(r,"interface",""),
                    "floating":     xt(r,"floating","0"),
                    "direction":    xt(r,"direction","in"),
                    "ipprotocol":   xt(r,"ipprotocol","inet"),
                    "protocol":     xt(r,"protocol","any"),
                    "source_net":   xt(r,"source_net","any"),
                    "source_not":   xt(r,"source_not","0"),
                    "source_port":  xt(r,"source_port",""),
                    "dest_net":     xt(r,"destination_net","any"),
                    "dest_not":     xt(r,"destination_not","0"),
                    "dest_port":    xt(r,"destination_port",""),
                    "log":          xt(r,"log","0"),
                    "description":  xt(r,"description",""),
                    "sequence":     xt(r,"sequence","0"),
                    "gateway":      xt(r,"gateway",""),
                    "categories":   xt(r,"categories",""),
                    "sched":        xt(r,"sched",""),
                })
    rules.sort(key=lambda r: int(r.get("sequence") or 0))
    data["rules"] = rules

    # ── NAT Rules ────────────────────────────────────────────────────────────
    nat_rules = []
    nat_node = root.find("nat")
    if nat_node is not None:
        for r in nat_node.findall("rule"):
            if xt(r,"nordr") == "1":
                continue
            src = r.find("source")
            dst = r.find("destination")
            nat_rules.append({
                "disabled":   xt(r,"disabled","0"),
                "interface":  xt(r,"interface","wan"),
                "protocol":   xt(r,"protocol","any"),
                "source_net": xt(src,"network","any") if src is not None else "any",
                "source_port":xt(src,"port","") if src is not None else "",
                "dest_net":   xt(dst,"network","any") if dst is not None else "any",
                "dest_port":  xt(dst,"port","") if dst is not None else "",
                "target":     xt(r,"target",""),
                "local_port": xt(r,"local-port",""),
                "descr":      xt(r,"descr",""),
                "category":   xt(r,"category",""),
                "sequence":   xt(r,"sequence","0"),
            })
    nat_rules.sort(key=lambda r: int(r.get("sequence") or 0))
    data["nat"] = nat_rules

    # ── Aliases ───────────────────────────────────────────────────────────────
    aliases = []
    if opn is not None:
        fw   = opn.find("Firewall")
        an   = fw.find("Alias/aliases") if fw is not None else None
        if an is not None:
            for a in an:
                aliases.append({
                    "name":        xt(a,"name"),
                    "type":        xt(a,"type"),
                    "description": xt(a,"description"),
                    "content":     xt(a,"content"),
                    "enabled":     xt(a,"enabled","1"),
                })
    data["aliases"] = aliases

    # ── WireGuard ─────────────────────────────────────────────────────────────
    wg_servers, wg_clients = [], []
    if opn is not None:
        wg = opn.find("wireguard")
        if wg is not None:
            sn = wg.find("server/servers")
            if sn is not None:
                for s in sn:
                    wg_servers.append({
                        "name":          xt(s,"name"),
                        "enabled":       xt(s,"enabled","0"),
                        "instance":      xt(s,"instance",""),
                        "port":          xt(s,"port",""),
                        "tunneladdress": xt(s,"tunneladdress",""),
                        "dns":           xt(s,"dns",""),
                        "mtu":           xt(s,"mtu",""),
                        "disableroutes": xt(s,"disableroutes","0"),
                        "pubkey":        xt(s,"pubkey",""),
                    })
            cn = wg.find("client/clients")
            if cn is not None:
                for c in cn:
                    allowed = xt(c,"tunneladdress","")
                    full_tunnel = "0.0.0.0/0" in allowed or "::/0" in allowed
                    keepalive  = xt(c,"keepalive","")
                    server_addr= xt(c,"serveraddress","")
                    wg_clients.append({
                        "name":           xt(c,"name"),
                        "enabled":        xt(c,"enabled","0"),
                        "tunneladdress":  allowed,
                        "serveraddress":  server_addr,
                        "serverport":     xt(c,"serverport",""),
                        "keepalive":      keepalive,
                        "pubkey":         xt(c,"pubkey",""),
                        "full_tunnel":    full_tunnel,
                        "behind_nat":     not bool(server_addr) or is_private(server_addr),
                        "missing_keepalive": not bool(keepalive),
                    })
    data["wireguard"] = {"servers":wg_servers,"clients":wg_clients}

    # ── OpenVPN ───────────────────────────────────────────────────────────────
    ovpn_servers, ovpn_clients = [], []
    on = root.find("openvpn")
    if on is not None:
        for s in on.findall("openvpn-server"):
            ovpn_servers.append({
                "mode":    xt(s,"mode"),
                "protocol":xt(s,"protocol"),
                "port":    xt(s,"local_port"),
                "cipher":  xt(s,"crypto",xt(s,"cipher","")),
                "digest":  xt(s,"digest"),
                "tls":     xt(s,"tls"),
                "descr":   xt(s,"description",xt(s,"descr","")),
            })
        for c in on.findall("openvpn-client"):
            ovpn_clients.append({
                "server_addr": xt(c,"server_addr"),
                "protocol":    xt(c,"protocol"),
                "port":        xt(c,"server_port"),
                "cipher":      xt(c,"crypto",xt(c,"cipher","")),
                "digest":      xt(c,"digest"),
            })
    data["openvpn"] = {"servers":ovpn_servers,"clients":ovpn_clients}

    # ── DHCP ─────────────────────────────────────────────────────────────────
    dhcp = {}
    dhcpd = root.find("dhcpd")
    if dhcpd is not None:
        for iface in dhcpd:
            leases = iface.findall("staticmap")
            rng    = iface.find("range")
            frm    = xt(rng,"from","") if rng is not None else ""
            to     = xt(rng,"to","") if rng is not None else ""
            # detect pool/static overlaps
            overlaps = []
            for l in leases:
                lip = xt(l,"ipaddr","")
                if lip and frm and to and ip_in_range(lip,frm,to):
                    overlaps.append(lip)
            # pool size
            pool_size = 0
            if frm and to:
                try:
                    pool_size = int(ipaddress.ip_address(to)) - int(ipaddress.ip_address(frm)) + 1
                except Exception:
                    pass
            dhcp[iface.tag] = {
                "enabled":      xt(iface,"enable","0"),
                "range_from":   frm,
                "range_to":     to,
                "pool_size":    pool_size,
                "dns_server":   xt(iface,"dnsserver",""),
                "gateway":      xt(iface,"gateway",""),
                "deny_unknown": xt(iface,"denyunknown","0"),
                "static_count": len(leases),
                "pool_overlaps": overlaps,
                "static_leases": [
                    {"mac":xt(l,"mac"),"ip":xt(l,"ipaddr"),"hostname":xt(l,"hostname")}
                    for l in leases
                ],
            }
    data["dhcp"] = dhcp

    # ── Static Routes ─────────────────────────────────────────────────────────
    routes = []
    sr = root.find("staticroutes")
    if sr is not None:
        for r in sr.findall("route"):
            routes.append({
                "network": xt(r,"network"),
                "gateway": xt(r,"gateway"),
                "descr":   xt(r,"descr"),
                "disabled":xt(r,"disabled","0"),
            })
    data["static_routes"] = routes

    # ── DNS (unboundplus) ─────────────────────────────────────────────────────
    data["dns"] = {}
    if opn is not None:
        ub  = opn.find("unboundplus")
        if ub is not None:
            gen = ub.find("general")
            adv = ub.find("advanced")
            data["dns"] = {
                "enabled":         xt(gen,"enabled","0"),
                "dnssec":          xt(gen,"dnssec","0"),
                "port":            xt(gen,"port","53"),
                "active_interface":xt(gen,"active_interface",""),
                "hideidentity":    xt(adv,"hideidentity","0"),
                "hideversion":     xt(adv,"hideversion","0"),
                "dnssecstripped":  xt(adv,"dnssecstripped","0"),
            }

    # ── Syslog ────────────────────────────────────────────────────────────────
    data["syslog"] = {"enabled":"0","remote_destinations":0}
    if opn is not None:
        sl  = opn.find("Syslog")
        if sl is not None:
            gen   = sl.find("general")
            dests = sl.find("destinations")
            data["syslog"] = {
                "enabled":             xt(gen,"enabled","0"),
                "loglocal":            xt(gen,"loglocal","0"),
                "remote_destinations": len(list(dests)) if dests is not None else 0,
            }

    # ── IDS ───────────────────────────────────────────────────────────────────
    data["ids"] = {"enabled":"0","active_rules":0}
    if opn is not None:
        ids = opn.find("IDS")
        if ids is not None:
            settings = ids.find("general")
            if settings is None:
                settings = ids.find("settings")
            enabled_rules = [f for f in ids.findall("files/file") if xt(f,"enabled") == "1"]
            data["ids"] = {
                "enabled":      xt(settings,"enabled","0"),
                "active_rules": len(enabled_rules),
            }

    # ── Security plugins ──────────────────────────────────────────────────────
    data["crowdsec"] = {"present":False,"agent_enabled":"0","bouncer_enabled":"0"}
    data["zenarmor"] = {"present":False}
    if opn is not None:
        cs = opn.find("crowdsec")
        if cs is not None:
            gen = cs.find("general")
            data["crowdsec"] = {
                "present":          True,
                "agent_enabled":    xt(gen,"agent_enabled","0"),
                "bouncer_enabled":  xt(gen,"firewall_bouncer_enabled","0"),
            }
        if opn.find("Zenarmor") is not None:
            data["zenarmor"] = {"present":True}

    # ── Services ──────────────────────────────────────────────────────────────
    data["services"] = {}
    if opn is not None:
        # UPnP
        upnp = opn.find("miniupnpd")
        if upnp is None:
            upnp = root.find("miniupnpd")
        data["services"]["upnp"] = {
            "enabled": xt(upnp,"enable","0") == "1" if upnp is not None else False
        }
        # SNMP
        snmp = opn.find("SNMP")
        if snmp is None:
            snmp = root.find("snmpd")
        data["services"]["snmp"] = {
            "enabled":   xt(snmp,"enabled","0") == "1" if snmp is not None else False,
            "community": xt(snmp,"syslocation","") if snmp is not None else "",
        }
        # mDNS repeater
        mdns = opn.find("MDNSRepeater")
        data["services"]["mdns"] = {
            "enabled":    xt(mdns,"enabled","0") == "1" if mdns is not None else False,
            "interfaces": xt(mdns,"interfaces","") if mdns is not None else "",
        }
        # CrowdSec
        data["services"]["crowdsec"] = data["crowdsec"]
        # Netdata
        nd = opn.find("netdata")
        data["services"]["netdata"] = {"present": nd is not None}
        # ACME
        acme = opn.find("AcmeClient")
        if acme is not None:
            acme_gen = acme.find("settings")
            data["services"]["acme"] = {
                "enabled":      xt(acme_gen,"enabled","0") == "1",
                "auto_renewal": xt(acme_gen,"autoRenewal","0") == "1",
            }
        # Gateways
        gw_node = opn.find("Gateways")
        gateways = []
        if gw_node is not None:
            for gw in gw_node.findall("gateway_item"):
                gateways.append({
                    "name":      xt(gw,"name"),
                    "interface": xt(gw,"interface"),
                    "descr":     xt(gw,"descr"),
                    "disabled":  xt(gw,"disabled","0"),
                    "defaultgw": xt(gw,"defaultgw","0"),
                    "monitor_disable": xt(gw,"monitor_disable","0"),
                })
        data["gateways"] = gateways

    return data


# ─── ANALYSIS ENGINE ─────────────────────────────────────────────────────────
SEV = {"critical":10,"high":5,"medium":2,"low":1,"info":0}

def analyze(data: dict) -> dict:
    findings   = []
    score      = 100
    rules      = data.get("rules",[])
    interfaces = data.get("interfaces",{})
    wg         = data.get("wireguard",{})
    openvpn    = data.get("openvpn",{})
    dns        = data.get("dns",{})
    syslog     = data.get("syslog",{})
    nat        = data.get("nat",[])
    ids        = data.get("ids",{})
    users      = data.get("users",[])
    user_sum   = data.get("user_summary",{})
    certs      = data.get("certs",[])
    ssh        = data.get("ssh",{})
    webgui     = data.get("webgui",{})
    dhcp       = data.get("dhcp",{})
    services   = data.get("services",{})
    crowdsec   = data.get("crowdsec",{})
    vlans      = data.get("vlans",[])
    aliases    = data.get("aliases",[])
    routes     = data.get("static_routes",[])
    gateways   = data.get("gateways",[])

    # Track per-category deduction caps to avoid a single noisy category zeroing the score
    _cat_spent = {}
    _CAT_CAP   = {"critical":30,"high":20,"medium":10,"low":5,"info":0}

    def add(sev, cat, title, detail, rec, rule_ref=None):
        nonlocal score
        cap  = _CAT_CAP.get(sev, 0)
        spent= _cat_spent.get((sev,cat),0)
        deduct = SEV[sev]
        if cap > 0 and spent + deduct > cap:
            deduct = max(0, cap - spent)
        _cat_spent[(sev,cat)] = spent + SEV[sev]
        score -= deduct
        findings.append({"severity":sev,"category":cat,"title":title,
                         "detail":detail,"recommendation":rec,"rule_ref":rule_ref})

    active_rules = [r for r in rules if r.get("enabled","1")=="1"]
    alias_names  = {a["name"] for a in aliases if a.get("enabled","1")=="1"}

    # ── Build rule lookup helpers ─────────────────────────────────────────────
    wan_allow_ports = set()  # ports reachable from internet
    for r in active_rules:
        if r.get("action","pass")=="pass" and "wan" in r.get("interface","").lower():
            p = r.get("dest_port","")
            if p: wan_allow_ports.add(p)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 1. FIREWALL RULES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    any_any_pass, wan_any_src, no_log_pass, no_desc = [],[],[],[]
    disabled_rules = [r for r in rules if r.get("enabled","1")!="1"]
    scheduled_rules = [r for r in active_rules if r.get("sched","")]
    floating_rules  = [r for r in active_rules if r.get("floating","0")=="1" or r.get("interface","")==""]
    has_block_all   = False
    has_antilockout = False

    for r in active_rules:
        action  = r.get("action","pass").lower()
        iface   = r.get("interface","")
        src     = r.get("source_net","any")
        dst     = r.get("dest_net","any")
        port    = r.get("dest_port","")
        descr   = r.get("description","").strip()
        log_on  = r.get("log","0")=="1"
        src_any = src in ("any","")
        dst_any = dst in ("any","")
        is_wan  = "wan" in iface.lower()

        if not descr: no_desc.append(r)
        if action=="block" and src_any and dst_any: has_block_all = True
        if action=="pass"  and src_any and dst_any: any_any_pass.append(r)
        if action=="pass"  and is_wan  and src_any: wan_any_src.append(r)
        if action=="pass"  and not log_on:          no_log_pass.append(r)
        # Anti-lockout heuristic: LAN→webgui port pass
        if action=="pass" and port in ("80","443","443/tcp","80/tcp") and not is_wan:
            has_antilockout = True

        # Alias reference check — skip built-in OPNsense interface keywords
        _builtin = {"any","(self)","wanip","lan","wan","loopback","localhost",
                    "l2tp","pppoe","pptp","Interfaces","Group","interface_group"} | set(interfaces.keys())
        for ref_field in (src, dst):
            if (ref_field and ref_field not in _builtin
                    and not ref_field[0].isdigit()
                    and "/" not in ref_field
                    and not ref_field.startswith("!")):
                if ref_field not in alias_names:
                    add("low","Firewall",f"Rule References Undefined Alias '{ref_field}'",
                        f"Rule '{descr or r.get('uuid','?')}' references alias '{ref_field}' which was not found in the aliases list.",
                        "Create the missing alias or correct the rule. Undefined aliases may silently fail.")

    # Rule shadowing detection
    shadowed = _detect_shadowed_rules(active_rules)
    for r, shadow_by in shadowed:
        add("medium","Firewall",f"Rule Shadowed by Earlier Rule",
            f"Rule '{r.get('description','(no desc)')}' (seq {r.get('sequence','?')}) on interface '{r.get('interface','?')}' "
            f"is completely covered by rule '{shadow_by.get('description','(no desc)')}' (seq {shadow_by.get('sequence','?')}) and will never match.",
            "Reorder rules or remove the shadowed rule to keep the ruleset accurate.")

    if not has_block_all:
        add("medium","Firewall","No Explicit Default-Deny Rule",
            "No block-all rule detected. OPNsense has an implicit deny but an explicit rule makes auditing clearer.",
            "Add a block rule at the end: source=any, destination=any, with logging enabled.")

    for r in any_any_pass:
        add("critical","Firewall",f"Any-to-Any ALLOW on '{r.get('interface','?')}'",
            f"Rule '{r.get('description','(no desc)')}' (seq {r.get('sequence','?')}) allows all traffic on all ports.",
            "Replace with specific source/destination/port combinations.")

    for r in wan_any_src:
        add("high","Firewall",f"WAN ALLOW from Any Source — Port {r.get('dest_port','any')}",
            f"Rule '{r.get('description','(no desc)')}' permits inbound WAN from any IP to port {r.get('dest_port','any')}.",
            "Restrict to known source IPs or apply geo-IP block aliases on WAN rules.")

    if len(no_log_pass) > 5:
        add("medium","Firewall",f"{len(no_log_pass)} ALLOW Rules Without Logging",
            f"{len(no_log_pass)} active allow rules have logging disabled, limiting audit capability.",
            "Enable logging on all allow rules, especially WAN and inter-VLAN rules.")

    if len(disabled_rules) > 5:
        add("low","Firewall",f"{len(disabled_rules)} Disabled Rules Accumulating",
            f"{len(disabled_rules)} disabled rules are still in the ruleset.",
            "Delete unused rules. Disabled rules add noise and may be re-enabled accidentally.")

    if len(no_desc) > 3:
        add("low","Firewall",f"{len(no_desc)} Undocumented Rules",
            f"{len(no_desc)} rules have no description.",
            "Document every rule: who requested it, why, and when.")

    if scheduled_rules:
        add("info","Firewall",f"{len(scheduled_rules)} Time-Scheduled Rules",
            f"Rules with schedules create time-limited access windows that may be forgotten: "
            f"{', '.join(r.get('description','?') for r in scheduled_rules[:3])}.",
            "Review scheduled rules regularly. Ensure schedules reflect current business requirements.")

    for r in floating_rules:
        if r.get("action","pass")=="pass" and r.get("source_net","any")=="any":
            add("high","Firewall",f"Permissive Floating Rule: '{r.get('description','?')}'",
                "Floating rules apply across ALL interfaces and bypass interface-level rules. "
                f"Rule '{r.get('description','(no desc)')}' allows traffic from any source.",
                "Floating rules should be as specific as possible. Restrict source/destination aggressively.")

    # Unused aliases
    used_in_rules = set()
    for r in rules:
        for f in (r.get("source_net",""),r.get("dest_net",""),r.get("source_port",""),r.get("dest_port","")):
            if f: used_in_rules.add(f)
    unused_aliases = [a for a in aliases if a.get("enabled","1")=="1" and a["name"] not in used_in_rules]
    if len(unused_aliases) > 3:
        add("info","Firewall",f"{len(unused_aliases)} Unused Aliases",
            f"Aliases defined but not referenced in any rule: "
            f"{', '.join(a['name'] for a in unused_aliases[:5])}{'...' if len(unused_aliases)>5 else ''}.",
            "Remove unused aliases to keep the configuration clean.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 2. PORT EXPOSURE MAP (build a list of internet-reachable ports)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    exposed_ports = []
    for r in active_rules:
        if r.get("action")=="pass" and "wan" in r.get("interface","").lower():
            exposed_ports.append({
                "port":    r.get("dest_port","any"),
                "proto":   r.get("protocol","any"),
                "source":  r.get("source_net","any"),
                "descr":   r.get("description",""),
            })
    for r in nat:
        if r.get("disabled","0")!="1":
            exposed_ports.append({
                "port":   r.get("dest_port","any"),
                "proto":  r.get("protocol","any"),
                "source": "any",
                "descr":  f"NAT→{r.get('target','')}:{r.get('local_port','')} ({r.get('descr','')})",
            })
    data["_exposed_ports"] = exposed_ports

    # Check SSH/WebGUI exposure on WAN
    ssh_port   = ssh.get("port","22")
    webgui_port= webgui.get("port","443")
    all_exposed_ports = {e["port"] for e in exposed_ports}
    if ssh_port in all_exposed_ports or "22" in all_exposed_ports:
        add("critical","Services","SSH Exposed on WAN",
            f"SSH (port {ssh_port}) appears reachable from the internet based on WAN firewall rules.",
            "Remove the WAN allow rule for SSH. Use a VPN for remote management access.")
    if webgui_port in all_exposed_ports or "443" in all_exposed_ports:
        add("high","Services","Web Management UI May Be WAN-Accessible",
            f"The OPNsense web GUI (port {webgui_port}) may be reachable from the internet.",
            "Restrict GUI access to LAN/management interfaces only. Never expose it on WAN.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 3. INTERFACES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for iface in interfaces.values():
        if iface["type"]=="wan":
            if iface.get("blockbogons")!="1":
                add("high","Interfaces",f"Bogon Blocking Disabled on WAN '{iface['descr']}'",
                    f"Interface '{iface['descr']}' ({iface['if']}) does not block bogon/martian networks.",
                    "Enable 'Block bogon networks' on all WAN interfaces.")
            if iface.get("blockpriv")!="1":
                add("medium","Interfaces",f"Private Network Blocking Disabled on WAN '{iface['descr']}'",
                    f"RFC1918 addresses are not blocked inbound on '{iface['descr']}'.",
                    "Enable 'Block private networks' on all WAN interfaces.")

    if not vlans and len(interfaces) < 4:
        add("info","Architecture","Consider VLAN Network Segmentation",
            f"Only {len(interfaces)} interface(s) with no VLANs detected. Flat networks increase blast radius of a breach.",
            "Segment IoT, Guest, Servers, and Management into separate VLANs with inter-VLAN firewall rules.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 4. SSH
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if ssh.get("enabled"):
        if ssh.get("password_auth"):
            add("high","SSH","SSH Password Authentication Enabled",
                "SSH allows password-based login, which is vulnerable to brute-force attacks.",
                "Disable password authentication and use SSH key pairs only.")
        if ssh.get("permit_root"):
            add("high","SSH","SSH Root Login Permitted",
                "Direct root login via SSH is allowed.",
                "Disable PermitRootLogin. Log in as a named user and escalate via sudo if needed.")
        if ssh.get("port","22") == "22":
            add("low","SSH","SSH on Default Port 22",
                "SSH is running on the default port 22, increasing exposure to automated scanners.",
                "Move SSH to a non-standard port and restrict with firewall rules.")
        if not ssh.get("interfaces",""):
            add("medium","SSH","SSH Listening on All Interfaces",
                "SSH is not bound to specific interfaces and may be reachable on all interfaces.",
                "Bind SSH to management/LAN interfaces only under System → Settings → Administration.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 5. WEB GUI
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if webgui.get("protocol")=="http":
        add("critical","WebGUI","Web UI Running on Plain HTTP",
            "The OPNsense management interface is served over unencrypted HTTP.",
            "Switch to HTTPS immediately under System → Settings → Administration.")
    if webgui.get("no_redirect"):
        add("medium","WebGUI","HTTP→HTTPS Redirect Disabled",
            "The automatic redirect from HTTP to HTTPS is disabled, allowing accidental plain-text sessions.",
            "Re-enable HTTP to HTTPS redirect in System → Settings → Administration.")
    if not webgui.get("interfaces",""):
        add("medium","WebGUI","Web UI Listening on All Interfaces",
            "The web UI is not bound to specific interfaces. It may be accessible on WAN.",
            "Bind the web GUI to LAN/management interfaces only.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 6. CERTIFICATES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    webgui_certref = webgui.get("certref","")
    for c in certs:
        days = c.get("days_remaining")
        if days is not None:
            if days < 0:
                add("critical","Certificates",f"Certificate EXPIRED: '{c['descr']}'",
                    f"Certificate '{c['descr']}' expired {abs(days)} days ago.",
                    "Renew this certificate immediately. Expired certs cause browser warnings and service failures.")
            elif days < 14:
                add("critical","Certificates",f"Certificate Expiring in {days} Days: '{c['descr']}'",
                    f"Certificate '{c['descr']}' expires on {c.get('not_after','?')}.",
                    "Renew immediately — less than 14 days remaining.")
            elif days < 30:
                add("high","Certificates",f"Certificate Expiring in {days} Days: '{c['descr']}'",
                    f"Certificate '{c['descr']}' expires on {c.get('not_after','?')}.",
                    "Renew within the week. Consider enabling ACME auto-renewal.")
            elif days < 60:
                add("medium","Certificates",f"Certificate Expiring in {days} Days: '{c['descr']}'",
                    f"Certificate '{c['descr']}' expires on {c.get('not_after','?')}.",
                    "Schedule renewal. Less than 60 days remaining.")
        if c.get("self_signed") and c.get("refid") == webgui_certref:
            add("low","Certificates","Web UI Using Self-Signed Certificate",
                "The OPNsense web interface is using a self-signed certificate.",
                "Use a trusted certificate via ACME/Let's Encrypt for the web UI.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 7. USERS & AUTH
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for u in users:
        if u["is_admin"] and not u["has_otp"] and not u["disabled"]:
            add("high","Authentication",f"Admin Account '{u['name']}' Has No MFA/OTP",
                f"Administrator '{u['name']}' has no OTP/TOTP configured, relying on password only.",
                "Enable two-factor authentication for all admin accounts under System → Access → Users.")
        if not u["has_password"] and not u["disabled"]:
            add("critical","Authentication",f"Account '{u['name']}' Has No Password",
                f"User '{u['name']}' has no password hash set.",
                "Set a strong password or disable this account immediately.")
        if u["api_key_count"] > 0:
            add("info","Authentication",f"User '{u['name']}' Has {u['api_key_count']} API Key(s)",
                f"Each API key is an independent access credential that bypasses password/OTP.",
                "Audit API keys regularly. Remove keys no longer in use.")

    if user_sum.get("admin_count",0) > 2:
        add("medium","Authentication",f"{user_sum['admin_count']} Full Admin Accounts",
            f"Accounts with full admin access: {', '.join(user_sum.get('admin_users',[]))}.",
            "Apply least-privilege. Use scoped operator roles where possible.")

    if user_sum.get("total_api_keys",0) > 3:
        add("medium","Authentication",f"{user_sum['total_api_keys']} Total API Keys Present",
            "A large number of API keys increases the attack surface.",
            "Audit and remove unused API keys. Rotate active ones regularly.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 8. WireGuard
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for srv in wg.get("servers",[]):
        if srv.get("enabled")!="1": continue
        if not srv.get("dns"):
            add("low","WireGuard",f"No DNS on WireGuard Instance '{srv['name']}'",
                "No DNS server configured for this WireGuard instance. Clients may leak DNS.",
                "Set a DNS server (e.g. your internal resolver) on the WireGuard interface.")
        if not srv.get("port"):
            add("info","WireGuard",f"WireGuard '{srv['name']}' Has No Explicit Port",
                "No listen port set — WireGuard uses an auto-assigned port.",
                "Set an explicit listen port for firewall rule stability.")

    for cli in wg.get("clients",[]):
        if cli.get("enabled")!="1": continue
        if cli.get("full_tunnel"):
            add("info","WireGuard",f"WireGuard Peer '{cli['name']}' Is Full-Tunnel",
                f"Peer '{cli['name']}' routes all traffic (0.0.0.0/0) through the tunnel.",
                "Verify this is intentional. Full-tunnel peers route ALL client traffic through your firewall.")
        if cli.get("missing_keepalive") and cli.get("behind_nat"):
            add("low","WireGuard",f"WireGuard Peer '{cli['name']}' Behind NAT Without Keepalive",
                f"Peer '{cli['name']}' appears to be behind NAT but has no PersistentKeepalive set.",
                "Set PersistentKeepalive (25s recommended) for peers behind NAT to prevent tunnel dropout.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 9. OpenVPN
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for srv in openvpn.get("servers",[]):
        cipher = srv.get("cipher","").upper()
        digest = srv.get("digest","").upper()
        if cipher in ("DES","3DES","RC4","BF-CBC","BLOWFISH","CAST5"):
            add("critical","OpenVPN",f"Weak Cipher: {cipher}",
                f"OpenVPN server '{srv.get('descr','?')}' uses deprecated cipher {cipher}.",
                "Migrate to AES-256-GCM or CHACHA20-POLY1305.")
        if digest in ("MD5","SHA1"):
            add("high","OpenVPN",f"Weak HMAC Digest: {digest}",
                f"Server uses {digest} for packet authentication.",
                "Switch to SHA256 or SHA512.")
        if not srv.get("tls"):
            add("medium","OpenVPN","TLS Auth/Crypt Not Configured",
                "No TLS auth/crypt key on an OpenVPN server.",
                "Enable tls-crypt (preferred) or tls-auth.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 10. DNS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if dns:
        if dns.get("dnssec")!="1":
            add("medium","DNS","DNSSEC Validation Disabled",
                "Unbound does not validate DNSSEC signatures.",
                "Enable DNSSEC in Services → Unbound DNS → General.")
        if dns.get("hideidentity")!="1":
            add("low","DNS","DNS Identity Not Hidden",
                "Unbound reveals resolver identity via 'id.server' queries.",
                "Enable 'Hide Identity' in Unbound advanced settings.")
        if dns.get("hideversion")!="1":
            add("low","DNS","DNS Version Not Hidden",
                "Unbound reveals its version string to querying clients.",
                "Enable 'Hide Version' in Unbound advanced settings.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 11. LOGGING
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if syslog.get("remote_destinations",0)==0:
        add("high","Logging","No Remote Syslog Configured",
            "All logs are local only. Logs are lost on reset or hardware failure.",
            "Configure a remote syslog destination (Graylog, Loki, Elastic, etc.).")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 12. IDS/IPS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if ids.get("enabled")!="1":
        add("medium","IDS/IPS","Intrusion Detection Not Enabled",
            "Suricata IDS/IPS is not active.",
            "Enable IDS/IPS under Services → Intrusion Detection with ET Open rulesets at minimum.")
    elif ids.get("active_rules",0)==0:
        add("medium","IDS/IPS","IDS Enabled But No Active Rulesets",
            "Suricata is running but no rule files are active.",
            "Enable rulesets under Services → Intrusion Detection → Download.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 13. SERVICES
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if services.get("upnp",{}).get("enabled"):
        add("high","Services","UPnP Is Enabled",
            "UPnP allows internal devices to automatically open ports through the firewall without admin approval.",
            "Disable UPnP unless explicitly required. If needed, restrict to specific interfaces.")

    if services.get("snmp",{}).get("enabled"):
        add("medium","Services","SNMP Is Enabled",
            "SNMP exposes system information and can be a foothold for attackers if misconfigured.",
            "Ensure SNMP v3 is used, disable SNMPv1/v2c, use strong community strings, and restrict source IPs.")

    if not crowdsec.get("present"):
        add("info","Services","CrowdSec Not Installed",
            "CrowdSec community threat intelligence is not present.",
            "Consider installing CrowdSec for collaborative IP reputation blocking.")
    elif crowdsec.get("agent_enabled")=="1" and crowdsec.get("bouncer_enabled")!="1":
        add("low","Services","CrowdSec Agent Active But Bouncer Disabled",
            "CrowdSec is collecting data but the firewall bouncer is not enforcing blocks.",
            "Enable the CrowdSec firewall bouncer to actually block malicious IPs.")

    if services.get("mdns",{}).get("enabled"):
        ifaces_mdns = services.get("mdns",{}).get("interfaces","")
        add("info","Services",f"mDNS Repeater Active Across {len(ifaces_mdns.split(','))} Interfaces",
            f"mDNS/Bonjour is being repeated across interfaces: {ifaces_mdns}.",
            "Verify mDNS repeater scope is intentional. Avoid repeating across high-security VLANs.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 14. NAT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for r in [x for x in nat if x.get("disabled","0")!="1"]:
        if not r.get("dest_port"):
            add("medium","NAT",f"NAT Rule Forwards All Ports: '{r.get('descr','?')}'",
                f"Port forward has no destination port restriction.",
                "Restrict to specific required ports only.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 15. DHCP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    for iface_key, d in dhcp.items():
        if d.get("pool_overlaps"):
            for ip in d["pool_overlaps"]:
                add("medium","DHCP",f"Static Lease IP {ip} Inside DHCP Pool on '{iface_key}'",
                    f"Static lease IP {ip} falls within the dynamic pool {d['range_from']}–{d['range_to']}. "
                    "This can cause IP conflicts.",
                    "Move the static lease IP outside the dynamic pool range, or shrink the pool.")
        if d.get("pool_size",0) > 0 and d.get("pool_size",0) < 10:
            add("low","DHCP",f"Very Small DHCP Pool on '{iface_key}' ({d['pool_size']} addresses)",
                f"Only {d['pool_size']} addresses available in the dynamic pool.",
                "Expand the DHCP pool or review whether all devices have static leases.")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 16. COMPLIANCE CHECKLIST
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    compliance = _build_compliance(data, findings)
    data["_compliance"] = compliance

    findings.sort(key=lambda f: SEV.get(f["severity"],0), reverse=True)
    score = max(0, min(100, score))

    return {
        "findings": findings,
        "score":    score,
        "summary": {
            "critical": sum(1 for f in findings if f["severity"]=="critical"),
            "high":     sum(1 for f in findings if f["severity"]=="high"),
            "medium":   sum(1 for f in findings if f["severity"]=="medium"),
            "low":      sum(1 for f in findings if f["severity"]=="low"),
            "info":     sum(1 for f in findings if f["severity"]=="info"),
            "total":    len(findings),
        },
        "compliance":    compliance,
        "exposed_ports": exposed_ports,
    }


# ─── RULE SHADOWING ───────────────────────────────────────────────────────────
def _detect_shadowed_rules(active_rules):
    """Detect rules completely shadowed by an earlier rule on the same interface."""
    shadowed = []
    interface_rules = {}
    for r in active_rules:
        iface = r.get("interface","")
        interface_rules.setdefault(iface,[]).append(r)

    for iface, rules in interface_rules.items():
        for i, rule in enumerate(rules):
            for earlier in rules[:i]:
                if _rule_covers(earlier, rule):
                    shadowed.append((rule, earlier))
                    break
    return shadowed

def _rule_covers(broad, specific):
    """Return True if 'broad' makes 'specific' unreachable."""
    if broad.get("action") != specific.get("action"):
        return False
    if broad.get("direction","in") != specific.get("direction","in"):
        return False
    def covers_net(b, s):
        if b in ("any",""):
            return True
        if b == s:
            return True
        try:
            bn = ipaddress.ip_network(b, strict=False)
            sn = ipaddress.ip_network(s, strict=False)
            return bn.supernet_of(sn)
        except Exception:
            return False
    def covers_port(b, s):
        if not b or b=="any": return True
        if not s or s=="any": return False
        return b == s
    def covers_proto(b, s):
        if not b or b=="any": return True
        return b.lower() == (s or "any").lower()

    return (covers_net(broad.get("source_net","any"), specific.get("source_net","any")) and
            covers_net(broad.get("dest_net","any"),   specific.get("dest_net","any"))   and
            covers_port(broad.get("dest_port",""),    specific.get("dest_port",""))     and
            covers_proto(broad.get("protocol","any"), specific.get("protocol","any")))


# ─── COMPLIANCE CHECKLIST ─────────────────────────────────────────────────────
def _build_compliance(data, findings):
    sev_set = {f["title"] for f in findings}
    def check(passed, label, detail, ref=""):
        return {"passed":passed,"label":label,"detail":detail,"ref":ref}

    ssh  = data.get("ssh",{})
    dns  = data.get("dns",{})
    ids  = data.get("ids",{})
    sl   = data.get("syslog",{})
    wgui = data.get("webgui",{})
    cs   = data.get("crowdsec",{})
    users= data.get("users",[])
    rules= data.get("rules",[])
    active= [r for r in rules if r.get("enabled","1")=="1"]

    all_admin_otp = all(u["has_otp"] for u in users if u["is_admin"] and not u["disabled"])
    any_any_exists = any(
        r.get("action")=="pass" and r.get("source_net","any")=="any" and r.get("dest_net","any")=="any"
        for r in active
    )

    items = [
        check(wgui.get("protocol")=="https",
              "Web UI uses HTTPS","Management interface must be served over TLS.","CIS OPNsense 1.1"),
        check(not wgui.get("no_redirect",False),
              "HTTP redirects to HTTPS","Plain HTTP should redirect to HTTPS.","CIS 1.2"),
        check(ssh.get("enabled") and not ssh.get("password_auth"),
              "SSH uses key auth only","Password authentication disabled for SSH.","CIS 2.1"),
        check(ssh.get("enabled") and not ssh.get("permit_root"),
              "SSH root login disabled","Direct root SSH login is not permitted.","CIS 2.2"),
        check(dns.get("dnssec")=="1",
              "DNSSEC validation enabled","Unbound validates DNSSEC signatures.","CIS 3.1"),
        check(dns.get("hideidentity")=="1",
              "DNS identity hidden","Resolver does not reveal its identity.","CIS 3.2"),
        check(dns.get("hideversion")=="1",
              "DNS version hidden","Resolver does not reveal version string.","CIS 3.3"),
        check(ids.get("enabled")=="1",
              "IDS/IPS enabled","Suricata intrusion detection is active.","CIS 4.1"),
        check(ids.get("enabled")=="1" and ids.get("active_rules",0)>0,
              "IDS has active rulesets","At least one IDS ruleset is loaded.","CIS 4.2"),
        check(sl.get("remote_destinations",0)>0,
              "Remote syslog configured","Logs are shipped to an external server.","CIS 5.1"),
        check(not any_any_exists,
              "No any-to-any allow rules","Ruleset contains no overly permissive rules.","CIS 6.1"),
        check(all_admin_otp,
              "All admins have MFA/OTP","Every admin account has OTP configured.","CIS 7.1"),
        check(not data.get("services",{}).get("upnp",{}).get("enabled",False),
              "UPnP disabled","UPnP is not enabled.","CIS 8.1"),
        check(cs.get("present") and cs.get("bouncer_enabled")=="1",
              "CrowdSec bouncer active","CrowdSec is installed and bouncing.","Best Practice"),
        check(bool(data.get("vlans",[])) or len(data.get("interfaces",{}))>=4,
              "Network segmentation in use","VLANs or multiple interfaces segment the network.","CIS 9.1"),
        check(any((c.get("days_remaining") or 0) > 30 for c in data.get("certs",[])),
              "Certificates not near expiry","No certificates expiring within 30 days.","CIS 10.1"),
        check(not data.get("services",{}).get("snmp",{}).get("enabled",False),
              "SNMP disabled or secured","SNMP service is not running.","CIS 8.2"),
    ]
    passed = sum(1 for i in items if i["passed"])
    return {"items":items,"passed":passed,"total":len(items),"score_pct":round(passed/len(items)*100)}


# ─── TRAFFIC FLOW MAP ────────────────────────────────────────────────────────
def build_traffic_flow(data):
    interfaces = data.get("interfaces",{})
    rules      = data.get("rules",[])
    nat        = data.get("nat",[])
    wg         = data.get("wireguard",{})

    nodes, edges = [], []
    seen_n, seen_e = set(), set()

    def add_node(nid, label, ntype, ip="", subnet=""):
        if nid not in seen_n:
            seen_n.add(nid)
            nodes.append({"id":nid,"label":label,"type":ntype,"ip":ip,"subnet":subnet})

    add_node("internet","INTERNET","internet")

    iface_map = {}
    for key, iface in interfaces.items():
        if not iface.get("enabled",True): continue
        nid  = f"iface_{key}"
        iface_map[key] = nid
        add_node(nid, iface["descr"], iface["type"], iface.get("ipaddr",""), iface.get("subnet",""))

    for key, iface in interfaces.items():
        if iface["type"]=="wan" and iface.get("enabled",True):
            edges.append({"from":"internet","to":iface_map[key],"label":"WAN","type":"wan","bidirectional":True})

    for srv in wg.get("servers",[]):
        if srv.get("enabled")=="1":
            nid = f"wg_{srv['name']}"
            add_node(nid, srv["name"], "wireguard", srv.get("tunneladdress",""))
            for key, iface in interfaces.items():
                if iface["type"]=="wan":
                    ek = ("internet",nid)
                    if ek not in seen_e:
                        seen_e.add(ek)
                        edges.append({"from":iface_map[key],"to":nid,"label":f"WG:{srv.get('port','?')}","type":"vpn","bidirectional":True})
                    break

    for cli in wg.get("clients",[]):
        if cli.get("enabled")=="1" and cli.get("serveraddress"):
            nid = f"wgcli_{cli['name']}"
            add_node(nid, cli["name"], "vpn_out", cli.get("serveraddress",""))
            ek = ("internet",nid)
            if ek not in seen_e:
                seen_e.add(ek)
                edges.append({"from":"internet","to":nid,"label":f"WG→{cli.get('serveraddress','?')[:15]}","type":"vpn","bidirectional":True})

    active_rules = [r for r in rules if r.get("enabled","1")=="1"]
    for rule in active_rules:
        if rule.get("action","pass")!="pass": continue
        src_key = rule.get("interface","")
        dst_net = rule.get("dest_net","any")
        dst_key = None
        for key, iface in interfaces.items():
            ip = iface.get("ipaddr","")
            if dst_net==key or (ip and ip!="DHCP" and dst_net.startswith(ip.rsplit(".",1)[0])):
                dst_key = key
                break
        src_node = iface_map.get(src_key)
        dst_node = iface_map.get(dst_key) if dst_key else None
        if src_node and dst_node and src_node!=dst_node:
            ek = (src_node, dst_node)
            if ek not in seen_e:
                seen_e.add(ek)
                port  = rule.get("dest_port","")
                proto = rule.get("protocol","any")
                lbl   = rule.get("description","") or (f"{proto}/{port}" if port else proto)
                edges.append({"from":src_node,"to":dst_node,"label":lbl[:28],"type":"pass","bidirectional":False})

    for r in nat:
        if r.get("disabled","0")=="1": continue
        target_ip = r.get("target","")
        src_node  = iface_map.get(r.get("interface","wan"),"internet")
        dst_node  = None
        for key, iface in interfaces.items():
            ip = iface.get("ipaddr","")
            if target_ip and ip and ip!="DHCP" and target_ip.startswith(ip.rsplit(".",1)[0]):
                dst_node = iface_map.get(key)
                break
        if dst_node and src_node!=dst_node:
            port = r.get("local_port","")
            ek   = (src_node, dst_node, "nat", port)
            if ek not in seen_e:
                seen_e.add(ek)
                edges.append({"from":src_node,"to":dst_node,
                              "label":f"NAT:{port}" if port else f"NAT:{r.get('descr','')}",
                              "type":"nat","bidirectional":False})

    return {"nodes":nodes,"edges":edges}


# ─── API ─────────────────────────────────────────────────────────────────────
@app.post("/api/analyze")
async def analyze_config(file: UploadFile = File(...)):
    if not file.filename.endswith(".xml"):
        raise HTTPException(status_code=400, detail="Only .xml files accepted.")
    content = await file.read()
    if len(content) > 20*1024*1024:
        raise HTTPException(status_code=413, detail="File too large (max 20MB).")

    data     = parse_opnsense_xml(content)
    analysis = analyze(data)
    flow     = build_traffic_flow(data)

    return JSONResponse(content={
        "meta": {
            "filename":         file.filename,
            "file_hash":        hashlib.sha256(content).hexdigest()[:16]+"...",
            "rules_count":      len(data.get("rules",[])),
            "active_rules":     sum(1 for r in data.get("rules",[]) if r.get("enabled","1")=="1"),
            "interfaces_count": len(data.get("interfaces",{})),
            "nat_rules_count":  len(data.get("nat",[])),
            "aliases_count":    len(data.get("aliases",[])),
            "vlans_count":      len(data.get("vlans",[])),
            "wg_tunnels":       len(data.get("wireguard",{}).get("servers",[])),
            "wg_peers":         len(data.get("wireguard",{}).get("clients",[])),
            "certs_count":      len(data.get("certs",[])),
        },
        "system":       data.get("system",{}),
        "user_summary": data.get("user_summary",{}),
        "users":        data.get("users",[]),
        "ssh":          data.get("ssh",{}),
        "webgui":       data.get("webgui",{}),
        "interfaces":   data.get("interfaces",{}),
        "vlans":        data.get("vlans",[]),
        "certs":        data.get("certs",[]),
        "gateways":     data.get("gateways",[]),
        "static_routes":data.get("static_routes",[]),
        "dhcp_summary": {
            k: {"enabled":v.get("enabled"),"pool_size":v.get("pool_size"),
                "static_count":v.get("static_count"),"range_from":v.get("range_from"),
                "range_to":v.get("range_to"),"pool_overlaps":v.get("pool_overlaps",[]),
                "static_leases":v.get("static_leases",[])}
            for k,v in data.get("dhcp",{}).items()
        },
        "rules_preview": [{
            "index":i,"enabled":r.get("enabled","1"),"action":r.get("action","pass"),
            "interface":r.get("interface",""),"direction":r.get("direction","in"),
            "protocol":r.get("protocol","any"),"source":r.get("source_net","any"),
            "source_port":r.get("source_port",""),"destination":r.get("dest_net","any"),
            "dest_port":r.get("dest_port",""),"log":r.get("log","0"),
            "description":r.get("description",""),"sequence":r.get("sequence",""),
            "gateway":r.get("gateway",""),"floating":r.get("floating","0"),
            "sched":r.get("sched",""),
        } for i,r in enumerate(data.get("rules",[]))],
        "nat_preview": [{
            "index":i,"disabled":r.get("disabled","0"),"interface":r.get("interface",""),
            "protocol":r.get("protocol",""),"source":r.get("source_net","any"),
            "dest":r.get("dest_net","any"),"dest_port":r.get("dest_port",""),
            "target":r.get("target",""),"local_port":r.get("local_port",""),
            "descr":r.get("descr",""),"category":r.get("category",""),
        } for i,r in enumerate(data.get("nat",[]))],
        "aliases":      data.get("aliases",[]),
        "wireguard":    data.get("wireguard",{}),
        "openvpn_summary": {
            "servers":len(data.get("openvpn",{}).get("servers",[])),
            "clients":len(data.get("openvpn",{}).get("clients",[])),
        },
        "dns":      data.get("dns",{}),
        "syslog":   data.get("syslog",{}),
        "ids":      data.get("ids",{}),
        "crowdsec": data.get("crowdsec",{}),
        "zenarmor": data.get("zenarmor",{}),
        "services": data.get("services",{}),
        "analysis":      analysis,
        "traffic_flow":  flow,
        "exposed_ports": analysis.get("exposed_ports",[]),
        "compliance":    analysis.get("compliance",{}),
    })

@app.get("/health")
async def health():
    return {"status":"ok"}

_static_dir = os.environ.get("STATIC_DIR","/app/frontend/static")
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="warning")
