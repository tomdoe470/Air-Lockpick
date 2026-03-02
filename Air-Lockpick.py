#!/usr/bin/env python3
# ============================================================
#   AIR-LOCKPICK v1.0 — WiFi Recon & Red Team Support Tool
#   Use ONLY on networks you are authorized to test
# ============================================================

import subprocess, sys, os, re, time, signal, csv, tempfile

class C:
    RESET="\033[0m"; RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
    CYAN="\033[96m"; WHITE="\033[97m"; BOLD="\033[1m"; DIM="\033[2m"
    MAGENTA="\033[95m"

OUI_DB = {
    "00:50:F2":("Microsoft","Windows devices"),
    "00:1A:11":("Google","Google Nest / Chromecast"),
    "B8:27:EB":("Raspberry Pi Foundation","IoT / Embedded"),
    "DC:A6:32":("Raspberry Pi Foundation","IoT / Embedded"),
    "FC:EC:DA":("Ubiquiti","UniFi AP"),
    "68:72:51":("Ubiquiti","UniFi AP"),
    "44:D9:E7":("Ubiquiti","UniFi AP"),
    "00:18:0A":("TP-Link","SOHO Router/AP"),
    "14:CF:92":("TP-Link","SOHO Router/AP"),
    "50:C7:BF":("TP-Link","SOHO Router/AP"),
    "00:25:9C":("Cisco","Enterprise AP"),
    "00:1B:67":("Cisco","Enterprise networking"),
    "80:1F:02":("Huawei","Android / Router"),
    "F8:23:B2":("Huawei","Android / Router"),
    "00:1E:58":("D-Link","SOHO Router/AP"),
    "9C:D3:6D":("Netgear","SOHO Router/AP"),
    "00:1B:2F":("ASUSTek","SOHO Router/AP"),
    "10:BF:48":("ASUSTek","SOHO Router/AP"),
    "64:09:80":("Samsung","Android device"),
    "28:6F:7F":("Xiaomi","MIUI / Android"),
    "7C:1E:52":("Intel","WiFi adapter"),
    "34:02:86":("Intel","WiFi adapter"),
    "00:0C:29":("VMware","VM adapter"),
}

SSID_ISP_PATTERNS = [
    (r"^FIBERTEL",   "Fibertel (Claro AR)",  "Routers ZTE/Arcadyan"),
    (r"^ARNET",      "Telecom / Arnet",       "Routers ZTE/Huawei"),
    (r"^Telecentro", "Telecentro",            "Routers Sagemcom"),
    (r"^CLARO_",     "Claro",                 "Routers Huawei/ZTE"),
    (r"^Personal",   "Personal (Telecom)",    "Routers ZTE/Alcatel"),
    (r"^Movistar_",  "Movistar (Telefónica)", "Routers Askey/Arcadyan"),
    (r"^SPEEDY",     "Movistar / Speedy",     "Routers Arcadyan"),
    (r"^Flow",       "Flow (Cablevision)",    "Routers Technicolor"),
    (r"^DIRECT-",    "Wi-Fi Direct",          "P2P device"),
    (r"^AndroidAP",  "Android Hotspot",       "Mobile tethering"),
    (r"^iPhone",     "iOS Hotspot",           "Mobile tethering"),
    (r"^NETGEAR",    "Netgear default",       "Unconfigured SOHO"),
    (r"^ASUS_",      "ASUS default",          "Unconfigured SOHO"),
    (r"^TP-LINK_",   "TP-Link default",       "Unconfigured SOHO — HIGH PRIORITY"),
    (r"^dlink",      "D-Link default",        "Unconfigured SOHO"),
    (r"^Linksys",    "Linksys default",       "Unconfigured SOHO"),
    (r"^HUAWEI-",    "Huawei default",        "Unconfigured SOHO"),
    (r"^eduroam",    "Educational/eduroam",   "Enterprise WPA2-Enterprise"),
]

ENC_ASSESS = {
    "WPA3":("🛡  WPA3","GREEN", "SAE — resistant to offline attacks."),
    "WPA2":("🔐 WPA2","YELLOW","Capture PMKID/handshake → offline dict attack."),
    "WPA": ("⚠  WPA TKIP","RED","Deprecated — multiple known attacks."),
    "WEP": ("💀 WEP","RED",   "Critically broken — crackable in minutes."),
    "OPN": ("📡 OPEN","RED",  "No encryption — all traffic visible."),
}

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except: return "",""

def sep(w=60, col="CYAN"): print(f"{getattr(C,col)}{'═'*w}{C.RESET}")
def cp(col, msg): print(f"{getattr(C,col,C.RESET)}{msg}{C.RESET}")

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ╔═══════════════════════════════════════════════════════╗
  ║  AIR-LOCKPICK v1.0 │ WiFi Recon & Red Team Support   ║
  ║  ⚠  Use ONLY on networks you are authorized to test   ║
  ╚═══════════════════════════════════════════════════════╝{C.RESET}\n""")

def check_root():
    if os.geteuid()!=0: cp("RED","✗ Root required (sudo)."); sys.exit(1)

def check_deps():
    missing=[d for d in ["airmon-ng","airodump-ng","wash","iw"] if not run(f"which {d}")[0]]
    if missing:
        cp("YELLOW",f"⚠  Missing: {', '.join(missing)}")
        cp("DIM","   sudo apt install aircrack-ng wash iw")
        if any(m in missing for m in ["airodump-ng","airmon-ng"]): sys.exit(1)

# ── Interface ──────────────────────────────────────────────

def get_interfaces():
    out,_=run("iw dev 2>/dev/null | grep -E 'Interface|type'")
    ifaces,cur=[],None
    for line in out.splitlines():
        line=line.strip()
        if line.startswith("Interface"): cur=line.split()[-1]
        elif line.startswith("type") and cur:
            ifaces.append((cur,line.split()[-1])); cur=None
    return ifaces

def select_iface(ifaces):
    sep(); cp("BOLD","  [1/4] Interface Detection"); sep()
    if not ifaces: cp("RED","No wireless interfaces."); sys.exit(1)
    print()
    for i,(iface,mode) in enumerate(ifaces):
        col="GREEN" if mode=="monitor" else "YELLOW"
        cp(col,f"  [{i+1}] {iface:<14} mode: {mode}")
    print()
    while True:
        try:
            idx=int(input(f"{C.CYAN}  → Select [1-{len(ifaces)}]: {C.RESET}").strip())-1
            if 0<=idx<len(ifaces): return ifaces[idx]
        except: pass
        cp("RED","  Invalid.")

def enable_monitor(iface, mode):
    sep(); cp("BOLD","  [2/4] Monitor Mode"); sep(); print()
    if mode=="monitor": cp("GREEN",f"  ✔ {iface} already in monitor mode."); return iface
    cp("YELLOW",f"  Switching {iface} → monitor mode...")
    run("airmon-ng check kill"); run(f"airmon-ng start {iface}"); time.sleep(2)
    new=[i for i,m in get_interfaces() if m=="monitor"]
    if new: cp("GREEN",f"  ✔ Monitor: {new[0]}"); return new[0]
    mon=iface+"mon"; cp("YELLOW",f"  Assuming: {mon}"); return mon

# ── Scan ───────────────────────────────────────────────────

def scan(mon, duration=20):
    sep(); cp("BOLD","  [3/4] Scanning"); sep(); print()
    cp("CYAN",f"  Scanning on {mon} for {duration}s...")
    tmpdir=tempfile.mkdtemp(); base=os.path.join(tmpdir,"alp")
    proc=subprocess.Popen(f"airodump-ng --output-format csv -w {base} {mon}",
        shell=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for i in range(duration):
        pct=int((i+1)/duration*44)
        print(f"\r  {C.CYAN}[{'█'*pct+'░'*(44-pct)}] {i+1}/{duration}s{C.RESET}",end="",flush=True)
        time.sleep(1)
    print(); proc.terminate(); proc.wait(); time.sleep(1)
    csvf=base+"-01.csv"
    if not os.path.exists(csvf): cp("RED","No capture file. Check interface."); sys.exit(1)
    return parse_csv(csvf)

def parse_csv(f):
    aps,clients,section=[],[],None
    with open(f,"r",errors="replace") as fh:
        for row in csv.reader(fh):
            if not row: continue
            first=row[0].strip()
            if first.startswith("BSSID"):   section="ap";  continue
            if first.startswith("Station"): section="cl";  continue
            if section=="ap" and len(row)>=14:
                b=row[0].strip()
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",b): continue
                aps.append({"bssid":b,"channel":row[3].strip(),"speed":row[4].strip(),
                            "privacy":row[5].strip(),"cipher":row[6].strip(),"auth":row[7].strip(),
                            "power":row[8].strip(),"beacons":row[9].strip(),"data":row[10].strip(),
                            "ssid":row[13].strip() or "<hidden>","clients":[]})
            elif section=="cl" and len(row)>=6:
                s=row[0].strip()
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",s): continue
                clients.append({"mac":s,"ap":row[5].strip(),"power":row[3].strip(),
                                "probes":",".join(row[6:]).strip()})
    for c in clients:
        for a in aps:
            if a["bssid"].lower()==c["ap"].lower(): a["clients"].append(c)
    return aps,clients

# ── Table ──────────────────────────────────────────────────

def show_table(aps):
    sep(); cp("BOLD","  Discovered Networks"); sep(); print()
    cp("BOLD",f"  {'#':<4}{'SSID':<28}{'BSSID':<19}{'CH':>4}{'PWR':>6}  {'ENC':<12}{'CLT'}")
    print(f"  {C.DIM}{'─'*68}{C.RESET}")
    ec_map={"WPA3":"GREEN","WPA2":"YELLOW","WPA ":"RED","WEP":"RED","OPN":"MAGENTA"}
    for i,ap in enumerate(aps):
        prv=ap["privacy"]; ec="WHITE"
        for k,v in ec_map.items():
            if k in prv: ec=v; break
        try: pi=int(ap["power"]); pc="GREEN" if pi>-60 else ("YELLOW" if pi>-75 else "RED")
        except: pc="DIM"
        cl=len(ap["clients"]); clc="CYAN" if cl>0 else "DIM"
        print(f"  {C.BOLD}[{i+1:>2}]{C.RESET}"
              f"{C.WHITE}{ap['ssid'][:27]:<28}{C.RESET}"
              f"{C.DIM}{ap['bssid']:<19}{C.RESET}"
              f"{C.CYAN}{ap['channel']:>3} {C.RESET}"
              f"{getattr(C,pc)}{ap['power']:>5}{C.RESET}  "
              f"{getattr(C,ec)}{prv:<12}{C.RESET}"
              f"{getattr(C,clc)}{cl:>3}{C.RESET}")
    print()

# ── Helpers ────────────────────────────────────────────────

def get_vendor(mac):
    p=mac.upper()[:8]
    return OUI_DB.get(p, OUI_DB.get(mac.upper()[:7],("Unknown Vendor","—")))

def guess_isp(ssid):
    for pat,isp,tech in SSID_ISP_PATTERNS:
        if re.match(pat,ssid,re.IGNORECASE): return isp,tech
    return None,None

def sig_q(p):
    try:
        v=int(p)
        if v>-50: return "Excellent","GREEN"
        if v>-60: return "Good","GREEN"
        if v>-70: return "Fair","YELLOW"
        if v>-80: return "Weak","RED"
        return "Very Weak","RED"
    except: return "Unknown","DIM"

def mac_block(mac, label=""):
    vendor,tech=get_vendor(mac)
    rand=(int(mac.split(":")[0],16)&0x02)!=0
    print(f"\n  {C.BOLD}{C.CYAN}{'─'*52}{C.RESET}")
    print(f"  {C.BOLD}{label} MAC:{C.RESET} {C.WHITE}{mac}{C.RESET}")
    print(f"  {C.CYAN}  Vendor : {C.RESET}{vendor}")
    print(f"  {C.CYAN}  Tech   : {C.RESET}{tech}")
    cp("YELLOW" if rand else "GREEN",
       "  ⚠  Randomized/Private MAC" if rand else "  ✔  Globally unique MAC (trackable)")

def wash_scan(mon, ch, bssid):
    out,_=run(f"wash -i {mon} -c {ch} -s 2>/dev/null | grep -i '{bssid[:8]}'",timeout=15)
    for line in (out or "").splitlines():
        p=line.split()
        if len(p)>=5:
            return {"wps_version":p[2],"locked":p[3],
                    "manufacturer":" ".join(p[5:]) if len(p)>5 else "?"}
    return None

# ── Recommendations ────────────────────────────────────────

def recos(ap, wd, ek, isp):
    recs=[]
    def p(lvl,txt):
        icons={"CRITICAL":f"{C.RED}[!!!]{C.RESET}","HIGH":f"{C.YELLOW}[!! ]{C.RESET}",
               "MEDIUM":f"{C.CYAN}[ ! ]{C.RESET}","INFO":f"{C.DIM}[ i ]{C.RESET}"}
        return f"  {icons.get(lvl,'[   ]')} {txt}"

    if ek=="OPN":
        recs+=[p("CRITICAL","Open network — capture traffic with Wireshark/tcpdump."),
               p("CRITICAL","ARP poisoning / MITM trivial — no authentication needed.")]
    elif ek=="WEP":
        recs+=[p("CRITICAL","WEP — crackable in minutes with aircrack-ng."),
               p("HIGH","aireplay-ng -3 (ARP replay) → aircrack-ng -b <bssid> *.cap")]
    elif ek=="WPA":
        recs.append(p("HIGH","WPA/TKIP deprecated — capture 4-way handshake → hashcat."))
    elif ek=="WPA2":
        recs+=[p("HIGH","Capture PMKID: hcxdumptool -i <mon> --filterlist_ap=<bssid>"),
               p("HIGH","Crack: hashcat -m 22000 out.hc22000 rockyou.txt")]
        if ap["auth"] and "PSK" in ap["auth"]:
            recs.append(p("MEDIUM","PSK — check vendor default creds if SSID is default."))
    elif ek=="WPA3":
        recs+=[p("INFO","WPA3/SAE — resistant to offline attacks."),
               p("INFO","Check Transition mode → possible WPA2 downgrade attack.")]

    if wd:
        lk=wd.get("locked","?")
        if lk not in ("Yes","yes","1","True"):
            recs+=[p("CRITICAL",f"WPS Active! → reaver -i <mon> -b {ap['bssid']} -vv"),
                   p("HIGH","Pixie Dust: reaver -i <mon> -b <bssid> -K 1")]
        else:
            recs.append(p("MEDIUM","WPS Locked — wait timeout then retry PIN."))

    if ap["clients"]:
        recs+=[p("HIGH",f"{len(ap['clients'])} client(s) — deauth to capture handshake."),
               p("HIGH",f"aireplay-ng -0 5 -a {ap['bssid']} -c <client_mac> <mon>"),
               p("MEDIUM","Evil Twin — clone SSID+BSSID, force reconnect, harvest creds.")]
        for cl in ap["clients"]:
            if cl.get("probes"):
                recs.append(p("MEDIUM",f"Client probing '{cl['probes'][:50]}' → Evil Twin target."))

    if any(d in ap["ssid"] for d in ["TP-LINK","NETGEAR","ASUS_","dlink","Linksys","HUAWEI-"]):
        recs.append(p("HIGH","Default SSID — try vendor default credentials immediately."))

    try:
        if int(ap["power"])>-60: recs.append(p("INFO","Strong signal — optimal for all attack vectors."))
    except: pass

    if isp: recs.append(p("INFO",f"ISP: {isp} — research known CPE default creds & CVEs."))
    if ap["ssid"]=="<hidden>":
        recs+=[p("MEDIUM","Hidden SSID — sniff probe responses to reveal it."),
               p("MEDIUM","Deauth client → force reassociation broadcast reveals SSID.")]
    if not recs: recs.append(p("INFO","No high-priority vectors. Manual review suggested."))
    return recs

# ── Deep Analysis ──────────────────────────────────────────

def deep(ap, mon):
    sep(); cp("BOLD",f"  ◈ DEEP ANALYSIS — {ap['ssid']}"); sep()

    print(f"\n  {C.BOLD}{'═'*52}{C.RESET}")
    cp("BOLD","  ▸ ACCESS POINT")
    print(f"  {C.BOLD}{'═'*52}{C.RESET}\n")
    print(f"  {C.CYAN}SSID    :{C.RESET} {C.WHITE}{ap['ssid']}{C.RESET}")
    print(f"  {C.CYAN}BSSID   :{C.RESET} {ap['bssid']}")
    print(f"  {C.CYAN}Channel :{C.RESET} {ap['channel']}   Speed: {ap['speed']} Mbps")
    sq,sc=sig_q(ap["power"])
    print(f"  {C.CYAN}Signal  :{C.RESET} {ap['power']} dBm  ({getattr(C,sc)}{sq}{C.RESET})")
    print(f"  {C.CYAN}Beacons :{C.RESET} {ap['beacons']}   Data frames: {ap['data']}")

    print(f"\n  {C.BOLD}{'─'*52}{C.RESET}")
    cp("BOLD","  ▸ ENCRYPTION")
    print(f"  {C.BOLD}{'─'*52}{C.RESET}\n")
    prv=ap["privacy"]; ek="OPN"
    for k in ["WPA3","WPA2","WPA","WEP"]:
        if k in prv: ek=k; break
    lbl,ec,note=ENC_ASSESS.get(ek,("?","DIM","?"))
    print(f"  {C.CYAN}Privacy :{C.RESET} {prv}  Cipher: {ap['cipher']}  Auth: {ap['auth']}")
    print(f"  {getattr(C,ec)}{lbl}{C.RESET}")
    print(f"  {C.DIM}  → {note}{C.RESET}")

    print(f"\n  {C.BOLD}{'─'*52}{C.RESET}")
    cp("BOLD","  ▸ VENDOR & NETWORK ID")
    print(f"  {C.BOLD}{'─'*52}{C.RESET}")
    mac_block(ap["bssid"],"AP")
    isp,tech=guess_isp(ap["ssid"])
    if isp:
        print(f"  {C.CYAN}  ISP/Org : {C.RESET}{isp}")
        print(f"  {C.CYAN}  CPE     : {C.RESET}{tech}")
    else: cp("DIM","  ISP/Org : Not identified from SSID")

    print(f"\n  {C.BOLD}{'─'*52}{C.RESET}")
    cp("BOLD",f"  ▸ CONNECTED CLIENTS ({len(ap['clients'])})")
    print(f"  {C.BOLD}{'─'*52}{C.RESET}")
    if ap["clients"]:
        for j,cl in enumerate(ap["clients"]):
            mac_block(cl["mac"],f"Client #{j+1}")
            print(f"  {C.CYAN}  Signal : {C.RESET}{cl['power']} dBm")
            if cl.get("probes"):
                print(f"  {C.CYAN}  Probes : {C.DIM}{cl['probes'][:70]}{C.RESET}")
    else: cp("DIM","  No clients currently associated.")

    print(f"\n  {C.BOLD}{'─'*52}{C.RESET}")
    cp("BOLD","  ▸ WPS STATUS")
    print(f"  {C.BOLD}{'─'*52}{C.RESET}\n")
    cp("DIM",f"  Running wash on channel {ap['channel']}...")
    wd=wash_scan(mon,ap["channel"],ap["bssid"])
    if wd:
        lk=wd.get("locked","?")
        if lk in ("Yes","yes","1"):
            cp("YELLOW","  🔒 WPS Locked — lockout active. Retry after timeout.")
        else:
            cp("RED","  ⚡ WPS Active — PIN/Pixie Dust attack possible!")
        print(f"  {C.CYAN}  Version : {C.RESET}{wd.get('wps_version','?')}")
        print(f"  {C.CYAN}  Vendor  : {C.RESET}{wd.get('manufacturer','?')}")
    else: cp("DIM","  WPS not detected or wash unavailable.")

    print(f"\n  {C.BOLD}{'═'*52}{C.RESET}")
    cp("BOLD","  ▸ RED TEAM RECOMMENDATIONS")
    print(f"  {C.BOLD}{'═'*52}{C.RESET}\n")
    isp2,_=guess_isp(ap["ssid"])
    for r in recos(ap,wd,ek,isp2): print(r)
    print()

# ── Main ───────────────────────────────────────────────────

def restore(mon):
    print(f"\n{C.YELLOW}  Restoring {mon} to managed mode...{C.RESET}")
    run(f"airmon-ng stop {mon}")
    run("service NetworkManager restart 2>/dev/null || nmcli networking on 2>/dev/null || true")
    cp("GREEN","  ✔ Interface restored. Goodbye.\n")

def main():
    banner(); check_root(); check_deps()
    ifaces=get_interfaces()
    orig_iface,orig_mode=select_iface(ifaces)
    mon=enable_monitor(orig_iface,orig_mode)

    def cleanup(sig=None,frame=None):
        restore(mon); sys.exit(0)
    signal.signal(signal.SIGINT,cleanup)
    signal.signal(signal.SIGTERM,cleanup)

    try:
        dur=20; print()
        try:
            d=input(f"{C.CYAN}  Scan duration seconds [default 20]: {C.RESET}").strip()
            if d.isdigit() and int(d)>5: dur=int(d)
        except: pass

        aps,_=scan(mon,dur)
        if not aps: cp("RED","  No networks found."); cleanup()

        while True:
            show_table(aps)
            cp("DIM","  [number]=analyze  [r]=rescan  [q]=quit\n")
            ch=input(f"{C.CYAN}  → Select AP [1-{len(aps)}, r, q]: {C.RESET}").strip().lower()
            if ch=="q": break
            elif ch=="r": aps,_=scan(mon,dur)
            else:
                try:
                    idx=int(ch)-1
                    if 0<=idx<len(aps):
                        deep(aps[idx],mon)
                        input(f"\n{C.DIM}  Press Enter to continue...{C.RESET}")
                    else: cp("RED","  Invalid.")
                except ValueError: cp("RED","  Invalid.")
    finally:
        restore(mon)

if __name__=="__main__":
    main()
