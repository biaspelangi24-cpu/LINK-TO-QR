import qrcode
import argparse
import os
import sys
import ipaddress
import json
from pyzbar.pyzbar import decode
from PIL import Image
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import difflib

# ===== WARNA =====
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

print(f"""
{BLUE}====================================
       QR TOOL by Bias 07
===================================={RESET}

--input <link>        = buat QR
--scan  <file>        = scan QR dari gambar
--verbose             = tampilkan detail analisis
--json                = export hasil ke JSON
""")

parser = argparse.ArgumentParser()
parser.add_argument("--input", help="Buat QR dari link")
parser.add_argument("--scan", help="Scan QR dari file gambar")
parser.add_argument("--verbose", action="store_true")
parser.add_argument("--json", action="store_true")
args = parser.parse_args()

# ===== KONFIG =====
LEGIT_DOMAINS = ["google.com", "facebook.com", "instagram.com", "whatsapp.com", "paypal.com"]
SUSPICIOUS_PATHS = ["login", "verify", "update", "reset", "bonus", "free"]
SUSPICIOUS_PARAMS = ["redirect", "url", "next", "continue"]

# ===== ANALISIS LINK =====
def analyze_link(link):
    score = 100
    issues = []

    lower = link.lower()

    if lower.startswith("http://"):
        score -= 20
        issues.append("HTTP tidak terenkripsi")

    if not lower.startswith("http"):
        score -= 40
        issues.append("Format URL tidak valid")

    for word in SUSPICIOUS_PATHS:
        if word in lower:
            score -= 15
            issues.append(f"Kata/path mencurigakan: {word}")

    return score, issues

# ===== ANALISIS DOMAIN (TYPOSQUATTING) =====
def analyze_domain(domain):
    for legit in LEGIT_DOMAINS:
        ratio = difflib.SequenceMatcher(None, domain, legit).ratio()
        if ratio > 0.7 and domain != legit:
            return f"Mirip domain populer ({legit}) → kemungkinan palsu"
    return None

# ===== ANALISIS IP =====
def analyze_ip(host):
    try:
        ip = ipaddress.ip_address(host)
    except:
        return None

    if ip.is_private:
        return f"IP PRIVATE ({ip})"
    if ip.is_loopback:
        return f"LOOPBACK ({ip})"
    if ip.is_global:
        return f"IP PUBLIC ({ip})"
    return f"IP ({ip})"

# ===== LOG =====
def save_log(data):
    with open("scan_history.log", "a") as f:
        f.write(f"{datetime.now()} | {data['score']}% | {data['link']}\n")

# ===== GENERATE =====
if args.input:
    img = qrcode.make(args.input)
    img.save("qr_result.png")
    print(f"{GREEN}✔ QR berhasil dibuat{RESET}")
    print("File : qr_result.png")
    sys.exit()

# ===== SCAN =====
if args.scan:
    if not os.path.exists(args.scan):
        print(f"{RED}File tidak ditemukan{RESET}")
        sys.exit()

    img = Image.open(args.scan)
    qr = decode(img)

    if not qr:
        print(f"{RED}QR tidak terdeteksi{RESET}")
        sys.exit()

    link = qr[0].data.decode("utf-8")
    parsed = urlparse(link)
    params = parse_qs(parsed.query)

    score, issues = analyze_link(link)

    domain_warning = None
    if parsed.hostname:
        domain_warning = analyze_domain(parsed.hostname)
        if domain_warning:
            score -= 25
            issues.append(domain_warning)

    ip_info = analyze_ip(parsed.hostname) if parsed.hostname else None

    for p in SUSPICIOUS_PARAMS:
        if p in params:
            score -= 10
            issues.append(f"Parameter mencurigakan: {p}")

    score = max(score, 0)

    # ===== STATUS =====
    if score >= 80:
        status = f"{GREEN}AMAN{RESET}"
    elif score >= 50:
        status = f"{YELLOW}WASPADA{RESET}"
    else:
        status = f"{RED}BERBAHAYA{RESET}"

    print(f"\n{BLUE} HASIL ANALISIS ELITE{RESET}")
    print("━━━━━━━━━━━━━━━━━━━━━━")
    print("Link   :", link)
    print("Score  :", f"{score}% →", status)

    for i in issues:
        print(f"{YELLOW}- {i}{RESET}")

    if ip_info:
        print("IP     :", ip_info)

    result = {
        "link": link,
        "score": score,
        "issues": issues,
        "ip": ip_info,
        "time": str(datetime.now())
    }

    save_log(result)

    if args.json:
        with open("scan_result.json", "w") as f:
            json.dump(result, f, indent=2)
        print(f"{GREEN} Hasil disimpan ke scan_result.json{RESET}")

    if args.verbose:
        print(f"{BLUE} Mode verbose aktif{RESET}")
        print("Host   :", parsed.hostname)
        print("Path   :", parsed.path)
        print("Params :", params)

    sys.exit()

print(f"{YELLOW} Gunakan --input atau --scan{RESET}")
