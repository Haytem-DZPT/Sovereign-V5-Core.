#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════════
# PRODUCT: DZPT Sovereign V5 - Cyber Intelligence Platform (Enterprise MVP)
# FILE: sovereign_cli.py
# ══════════════════════════════════════════════════════════════════════════════

import os
import re
import sys
import json
import random
import asyncio
import logging
import subprocess
from enum import Enum
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

logging.basicConfig(level=logging.WARNING)

# ══════════════════════════════════════════════════════════════════════════════
# ANSI TERMINAL COLORS
# ══════════════════════════════════════════════════════════════════════════════
C_CYAN = "\033[96m"
C_PINK = "\033[95m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS WITH FALLBACK
# ══════════════════════════════════════════════════════════════════════════════
try:
    import aiohttp
    from bs4 import BeautifulSoup
except ImportError:
    print(f"{C_RED}[!] Missing dependencies. Run: pip install aiohttp beautifulsoup4 fpdf{C_RESET}")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ══════════════════════════════════════════════════════════════════════════════

class TechCategory(str, Enum):
    WEB_SERVER = "Web Server"
    CMS = "CMS"
    FRONTEND_FW = "Frontend Framework"
    BACKEND_FW = "Backend Framework"
    LANGUAGE = "Language"
    SECURITY = "Security"

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

from dataclasses import dataclass, field

@dataclass
class TechMatch:
    name: str
    category: TechCategory
    version: Optional[str] = None
    confidence: float = 1.0
    evidence: list[str] = field(default_factory=list)
    cve_hints: list[str] = field(default_factory=list)

@dataclass
class ScanContext:
    url: str
    status_code: int
    headers: dict[str, str]
    html: str
    cookies: dict[str, str]

@dataclass
class TechSignature:
    name: str
    category: TechCategory
    header_rules: dict[str, list] = field(default_factory=dict)
    html_rules: list = field(default_factory=list)
    cookie_keys: list[str] = field(default_factory=list)
    cve_versions: dict[str, str] = field(default_factory=dict)

# ══════════════════════════════════════════════════════════════════════════════
# DEFENSIVE SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class DefensiveScanner:
    FIVE_MB_LIMIT = 5 * 1024 * 1024

    def __init__(self):
        self.secret_patterns = {
            "Google API Key": re.compile(r'AIzaSy[A-Za-z0-9-_]{35}'),
            "OpenAI API Key": re.compile(r'sk-[A-Za-z0-9]{32,48}'),
            "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "Generic Password": re.compile(r'(?i)(password|passwd|secret_key)\s*=\s*[\'"][^\'"]{4,32}[\'"]')
        }
        self.dangerous_extensions = {".exe", ".bat", ".sh", ".cmd", ".msi"}
        self.suspicious_keywords = re.compile(r'(?i)(hack|virus|malware|trojan|exploit)')

    def scan_directory(self, root_dir: str) -> list[dict]:
        findings = []
        target_path = Path(root_dir)
        if not target_path.exists() or not target_path.is_dir():
            print(f"{C_RED}[-] Path not found or not a directory.{C_RESET}")
            return findings

        print(f"{C_CYAN}[*] Scanning directory: {root_dir}{C_RESET}")
        for file_path in target_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix.lower() in self.dangerous_extensions:
                findings.append({"file": str(file_path), "type": "Dangerous Extension", "severity": Severity.MEDIUM.value, "detail": f"Extension: {file_path.suffix}"})
                self._print_finding(findings[-1])
            if self.suspicious_keywords.search(file_path.name):
                findings.append({"file": str(file_path), "type": "Suspicious Name", "severity": Severity.LOW.value, "detail": "Keyword match in filename"})
                self._print_finding(findings[-1])
            try:
                if file_path.stat().st_size == 0: continue
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    chunk = f.read(self.FIVE_MB_LIMIT)
                    for secret_type, pattern in self.secret_patterns.items():
                        matches = pattern.findall(chunk)
                        if matches:
                            findings.append({"file": str(file_path), "type": "Leaked Secret", "severity": Severity.CRITICAL.value, "detail": f"{secret_type} (Count: {len(matches)})"})
                            self._print_finding(findings[-1])
            except: pass
        return findings

    def _print_finding(self, f):
        color = C_RED if f["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value) else C_YELLOW
        print(f"{color}[!] [{f['severity']}] {f['type']}{C_RESET} -> {Path(f['file']).name} ({f['detail']})")


# ══════════════════════════════════════════════════════════════════════════════
# OFFENSIVE RECON ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class OffensiveReconEngine:
    def __init__(self):
        self.signatures = [
            TechSignature(name="Nginx", category=TechCategory.WEB_SERVER, header_rules={"server": [(r"nginx(?:/([0-9.]+))?", 1, "Server Header", 1.0)]}, cve_versions={"1.18": "CVE-2021-23017"}),
            TechSignature(name="Apache", category=TechCategory.WEB_SERVER, header_rules={"server": [(r"Apache(?:/([0-9.]+))?", 1, "Server Header", 1.0)]}, cve_versions={"2.4.49": "CVE-2021-41773"}),
            TechSignature(name="WordPress", category=TechCategory.CMS, html_rules=[(r"/wp-content/", None, "wp-content path", 0.95), (r'<meta name="generator" content="WordPress ([0-9.]+)"', 1, "Generator Meta", 1.0)], cookie_keys=["wordpress_logged_in_"], cve_versions={"5.8": "CVE-2021-39200"}),
            TechSignature(name="Cloudflare", category=TechCategory.SECURITY, header_rules={"server": [(r"cloudflare", None, "Cloudflare Proxy", 1.0)], "cf-ray": [(r".*", None, "CF-Ray Header", 1.0)]}, cookie_keys=["__cfuid", "cf_clearance"])
        ]

    def _evaluate(self, sig: TechSignature, ctx: ScanContext) -> Optional[TechMatch]:
        evidence, version, confidence = [], None, 0.0
        for h_name, rules in sig.header_rules.items():
            h_val = ctx.headers.get(h_name.lower(), "")
            if not h_val: continue
            for pattern, ver_group, label, weight in rules:
                m = re.search(pattern, h_val, re.IGNORECASE)
                if m:
                    evidence.append(f"[Header:{h_name}] {label}")
                    confidence = max(confidence, weight)
                    if ver_group and version is None:
                        try: version = m.group(ver_group)
                        except IndexError: pass
        for pattern, ver_group, label, weight in sig.html_rules:
            m = re.search(pattern, ctx.html, re.IGNORECASE)
            if m:
                evidence.append(f"[HTML] {label}")
                confidence = max(confidence, weight)
                if ver_group and version is None:
                    try: version = m.group(ver_group)
                    except IndexError: pass
        for c_key in sig.cookie_keys:
            if any(c_key in k for k in ctx.cookies):
                evidence.append(f"[Cookie] {c_key}")
                confidence = max(confidence, 0.90)
        if not evidence: return None
        cve_hints = []
        if version and sig.cve_versions:
            for ver_tag, cve in sig.cve_versions.items():
                if version.startswith(ver_tag): cve_hints.append(f"{cve} (v{version})")
        return TechMatch(name=sig.name, category=sig.category, version=version, confidence=confidence, evidence=evidence, cve_hints=cve_hints)

    def _render(self, match: TechMatch):
        ver_str = f" v{match.version}" if match.version else ""
        print(f"{C_GREEN}[+] {match.name}{ver_str}{C_RESET} | {match.category.value} | Confidence: {int(match.confidence*100)}%")
        for ev in match.evidence: print(f"    └── {ev}")
        for cve in match.cve_hints: print(f"    {C_RED}└── [!] {cve}{C_RESET}")

def _to_dict(self: TechMatch) -> dict:
    return {"technology": self.name, "category": self.category.value, "version": self.version, "confidence_score": self.confidence, "evidence_extracted": self.evidence, "threat_cve_mapping": self.cve_hints}
TechMatch.to_finding = _to_dict


# ══════════════════════════════════════════════════════════════════════════════
# AI SIMULATION LAYER
# ══════════════════════════════════════════════════════════════════════════════

class AISimulationLayer:
    def __init__(self):
        self.insights = [
            {"triggers": {"WordPress", "Nginx"}, "analysis": "[AI Risk Analysis]: Detected common but vulnerable stack (WordPress + Nginx). Immediate patch recommended.", "severity": Severity.MEDIUM.value},
            {"triggers": {"React", "Cloudflare"}, "analysis": "[AI Risk Analysis]: Modern decoupled SPA with Edge Protection. Attack surface is low.", "severity": Severity.INFO.value}
        ]

    def correlate(self, findings: list[dict]) -> list[dict]:
        ai_assessments = []
        detected_names = {f["technology"] for f in findings}
        has_cves = any(f.get("threat_cve_mapping") for f in findings)
        if has_cves:
            ai_assessments.append({"type": "AI Risk Assertion", "severity": Severity.HIGH.value, "insight": "[AI Risk Analysis]: Active unpatched CVEs detected. Immediate patching mandatory."})
        for rule in self.insights:
            if rule["triggers"].issubset(detected_names):
                ai_assessments.append({"type": "AI Architectural Correlation", "severity": rule["severity"], "insight": rule["analysis"]})
        if not ai_assessments:
            ai_assessments.append({"type": "AI Baseline", "severity": Severity.INFO.value, "insight": "[AI Risk Analysis]: No complex risk signatures detected."})
        return ai_assessments


# ══════════════════════════════════════════════════════════════════════════════
# SMART RECON ENGINE (WAF Evasion + Subdomains)
# ══════════════════════════════════════════════════════════════════════════════

class AISmartReconEngine(OffensiveReconEngine):
    def __init__(self):
        super().__init__()
        self.ai_brain = AISimulationLayer()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"
        ]

    def _extract_domain(self, url: str) -> str:
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        return domain[4:] if domain.startswith("www.") else domain

    async def _harvest_subdomains(self, domain: str) -> list[str]:
        subdomains = {domain}
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        print(f"{C_CYAN}[*] Fetching subdomains from crt.sh...{C_RESET}")
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for entry in data:
                            for sub in entry.get("name_value", "").split("\n"):
                                sub = sub.strip().lower()
                                if sub and not sub.startswith("*") and sub.endswith(domain):
                                    subdomains.add(sub)
                        print(f"{C_GREEN}[+] Found {len(subdomains)} subdomains.{C_RESET}")
        except: print(f"{C_YELLOW}[!] crt.sh unavailable. Scanning root domain only.{C_RESET}")
        return sorted(list(subdomains))

    async def _fetch_with_evasion(self, session: aiohttp.ClientSession, url: str) -> Optional[ScanContext]:
        for attempt in range(3):
            headers = {"User-Agent": random.choice(self.user_agents), "Accept-Language": "en-US,en;q=0.9"}
            try:
                async with session.get(url, headers=headers, allow_redirects=True, ssl=False) as resp:
                    if resp.status in (403, 406, 429):
                        delay = random.uniform(1.0, 3.0)
                        print(f"    {C_YELLOW}[!] WAF Block ({resp.status}). Retrying in {delay:.1f}s...{C_RESET}")
                        await asyncio.sleep(delay)
                        continue
                    html = await resp.text(errors="replace")
                    return ScanContext(url=str(resp.url), status_code=resp.status, headers={k.lower(): v for k, v in resp.headers.items()}, html=html, cookies={k: v.value for k, v in resp.cookies.items()})
            except: pass
        return None

    async def execute_smart_scan(self, raw_url: str) -> dict:
        if not raw_url.startswith(("http://", "https://")): raw_url = "https://" + raw_url
        domain = self._extract_domain(raw_url)
        targets = await self._harvest_subdomains(domain)
        all_findings = []
        infra_map = {}
        print(f"\n{C_PINK}╔═══════════════ TARGET ANALYSIS FOOTPRINT ═══════════════╗{C_RESET}")
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session:
            for sub in targets:
                sub_url = f"https://{sub}"
                print(f"\n{C_CYAN}[*] Scanning: {sub_url}{C_RESET}")
                ctx = await self._fetch_with_evasion(session, sub_url)
                if not ctx:
                    print(f"    {C_RED}[-] Failed to connect.{C_RESET}")
                    continue
                node_findings = []
                for sig in self.signatures:
                    match = self._evaluate(sig, ctx)
                    if match:
                        d = match.to_finding()
                        node_findings.append(d)
                        all_findings.append(d)
                        self._render(match)
                if node_findings: infra_map[sub] = node_findings
        print(f"\n{C_PINK}╚══════════════════════════════════════════════════════════╝{C_RESET}")
        print(f"\n{C_CYAN}[*] Running AI Expert Analysis...{C_RESET}")
        ai_insights = self.ai_brain.correlate(all_findings)
        print(f"{C_PINK}╔═════════════════════ EXPERT SYSTEM ═════════════════════╗{C_RESET}")
        for ai in ai_insights:
            color = C_RED if ai["severity"] in (Severity.CRITICAL.value, Severity.HIGH.value) else C_CYAN
            print(f"{color}{ai['insight']}{C_RESET}\n")
        print(f"{C_PINK}╚══════════════════════════════════════════════════════════╝{C_RESET}")
        return {"scanned_root": domain, "subdomains_mapped_count": len(targets), "infrastructure_map": infra_map, "ai_expert_insights": ai_insights}


# ══════════════════════════════════════════════════════════════════════════════
# PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def export_to_investor_pdf(json_file_path: str) -> None:
    try:
        from fpdf import FPDF
    except ImportError:
        print(f"{C_YELLOW}[*] Installing fpdf...{C_RESET}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fpdf"])
        from fpdf import FPDF

    path_target = Path(json_file_path)
    if not path_target.exists():
        print(f"{C_RED}[-] File not found.{C_RESET}")
        return

    with open(path_target, "r", encoding="utf-8") as f:
        data = json.load(f)

    metadata = data.get("metadata", {})
    engine_build = metadata.get("engine_build", "Sovereign V5")
    timestamp = metadata.get("execution_timestamp", "")
    is_offensive = "AI Smart Recon" in engine_build or "Offensive" in engine_build
    target_name = metadata.get("scanned_target_root", metadata.get("scanned_directory", "Unknown"))

    findings_table = []
    ai_insights = []

    if is_offensive:
        infra_map = data.get("captured_infrastructure_map", {})
        ai_insights = data.get("expert_system_assertions", [])
        for sub_node, techs in infra_map.items():
            for t in techs:
                findings_table.append([sub_node, f"{t.get('technology')} v{t.get('version') or '?'}", f"{int(t.get('confidence_score', 1)*100)}%"])
    else:
        local_findings = data.get("findings", [])
        for f in local_findings:
            findings_table.append([Path(f.get("file", "")).name, f.get("type", "Risk"), f.get("severity", "INFO")])

    top_findings = findings_table[:3]

    class DarkPDF(FPDF):
        def header(self):
            self.set_fill_color(10, 10, 12)
            self.rect(0, 0, 210, 297, 'F')
            self.set_text_color(255, 20, 147)
            self.set_font('Courier', 'B', 16)
            self.cell(0, 10, 'DZPT SOVEREIGN V5 - INTELLIGENCE REPORT', 0, 1, 'C')
            self.set_draw_color(0, 255, 255)
            self.line(10, 22, 200, 22)
            self.ln(8)
        def footer(self):
            self.set_y(-15)
            self.set_font('Courier', 'I', 8)
            self.set_text_color(100, 100, 100)
            self.cell(0, 10, f'Page {self.page_no()} | DZPT Sovereign Security Group Canada', 0, 0, 'C')

    pdf = DarkPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font('Courier', 'B', 12)
    pdf.set_text_color(0, 255, 255)
    pdf.cell(0, 8, '1. EXECUTIVE BRIEF', 0, 1, 'L')
    pdf.ln(2)
    pdf.set_font('Courier', '', 10)
    pdf.set_text_color(240, 240, 240)
    pdf.cell(0, 6, f"Engine: {engine_build}", 0, 1, 'L')
    pdf.cell(0, 6, f"Target: {target_name}", 0, 1, 'L')
    pdf.cell(0, 6, f"Date: {timestamp}", 0, 1, 'L')
    pdf.cell(0, 6, f"Discoveries: {len(findings_table)}", 0, 1, 'L')
    pdf.ln(6)

    pdf.set_font('Courier', 'B', 12)
    pdf.set_text_color(0, 255, 255)
    pdf.cell(0, 8, '2. TOP FINDINGS', 0, 1, 'L')
    pdf.ln(2)
    pdf.set_font('Courier', 'B', 10)
    pdf.set_fill_color(30, 30, 35)
    pdf.set_text_color(255, 20, 147)
    cw1, cw2, cw3 = 65, 85, 40
    pdf.cell(cw1, 7, 'Asset', 1, 0, 'C', True)
    pdf.cell(cw2, 7, 'Component / Risk', 1, 0, 'C', True)
    pdf.cell(cw3, 7, 'Confidence/Risk', 1, 1, 'C', True)
    pdf.set_font('Courier', '', 9)
    pdf.set_text_color(220, 220, 220)
    for row in top_findings:
        pdf.cell(cw1, 7, str(row[0]), 1, 0, 'L')
        pdf.cell(cw2, 7, str(row[1]), 1, 0, 'L')
        pdf.cell(cw3, 7, str(row[2]), 1, 1, 'C')
    pdf.ln(6)

    if is_offensive and ai_insights:
        pdf.set_font('Courier', 'B', 12)
        pdf.set_text_color(0, 255, 255)
        pdf.cell(0, 8, '3. AI EXPERT ANALYSIS', 0, 1, 'L')
        pdf.ln(2)
        pdf.set_font('Courier', '', 9)
        pdf.set_fill_color(20, 15, 20)
        pdf.set_text_color(240, 220, 240)
        for ai in ai_insights:
            pdf.multi_cell(190, 6, f"[{ai.get('type')}] ({ai.get('severity')}):\n{ai.get('insight')}\n", 1, 'L', True)
            pdf.ln(2)

    out_name = f"Sovereign_V5_Investor_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(out_name, 'F')
    print(f"\n{C_GREEN}[+] PDF Generated: {out_name}{C_RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

def render_branding():
    os.system("clear" if os.name == "posix" else "cls")
    print(f"{C_CYAN}{C_BOLD}═══════════════════════════════════════════════════════════════════{C_RESET}")
    print(f"  {C_PINK}{C_BOLD}DZPT SOVEREIGN V5{C_RESET} — {C_CYAN}Enterprise Cyber Intelligence Platform{C_RESET}")
    print(f"  {C_GREEN}Termux CLI Environment | Ready for Investor Demo{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}═══════════════════════════════════════════════════════════════════{C_RESET}")

def runtime_menu_loop():
    defensive_engine = DefensiveScanner()
    smart_offensive_engine = AISmartReconEngine()

    while True:
        render_branding()
        print(f"{C_BOLD}SELECT OPERATION:{C_RESET}\n")
        print(f"  {C_CYAN}[1]{C_RESET} {C_BOLD}DEFENSIVE SCAN (Local Files){C_RESET}")
        print(f"  {C_PINK}[2]{C_RESET} {C_BOLD}OFFENSIVE RECON (Website + AI){C_RESET}")
        print(f"  {C_GREEN}[3]{C_RESET} {C_BOLD}GENERATE PDF REPORT{C_RESET}")
        print(f"  {C_RED}[4]{C_RESET} {C_BOLD}EXIT{C_RESET}\n")

        selection = input(f"{C_CYAN}Sovereign > {C_RESET}").strip()

        if selection == "1":
            print(f"\n{C_CYAN}--- DEFENSIVE SCAN ---{C_RESET}")
            dir_path = input(f"{C_BOLD}[>] Folder path: {C_RESET}").strip()
            findings = defensive_engine.scan_directory(dir_path)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname = f"defensive_scan_report_{ts}.json"
            report = {"metadata": {"engine_build": "Sovereign V5 (Defensive)", "execution_timestamp": datetime.now().isoformat(), "scanned_directory": dir_path, "total_alerts_logged": len(findings)}, "findings": findings}
            with open(fname, "w") as rf: json.dump(report, rf, indent=4)
            print(f"\n{C_GREEN}[+] Report saved: {fname}{C_RESET}")
            input(f"\n{C_YELLOW}[Enter] to continue...{C_RESET}")

        elif selection == "2":
            print(f"\n{C_PINK}--- OFFENSIVE RECON ---{C_RESET}")
            target = input(f"{C_BOLD}[>] Target URL: {C_RESET}").strip()
            if target:
                metrics = asyncio.run(smart_offensive_engine.execute_smart_scan(target))
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                fname = f"offensive_recon_report_{ts}.json"
                report = {"metadata": {"engine_build": "Sovereign V5 (AI Smart Recon)", "execution_timestamp": datetime.now().isoformat(), "scanned_target_root": metrics["scanned_root"], "subdomains_mapped_total": metrics["subdomains_mapped_count"]}, "captured_infrastructure_map": metrics["infrastructure_map"], "expert_system_assertions": metrics["ai_expert_insights"]}
                with open(fname, "w") as rf: json.dump(report, rf, indent=4)
                print(f"\n{C_GREEN}[+] Report saved: {fname}{C_RESET}")
            input(f"\n{C_YELLOW}[Enter] to continue...{C_RESET}")

        elif selection == "3":
            print(f"\n{C_GREEN}--- GENERATE PDF ---{C_RESET}")
            json_path = input(f"{C_BOLD}[>] JSON report path: {C_RESET}").strip()
            export_to_investor_pdf(json_path)
            input(f"\n{C_YELLOW}[Enter] to continue...{C_RESET}")

        elif selection == "4":
            print(f"\n{C_RED}[*] Terminating session. Goodbye.{C_RESET}")
            sys.exit(0)
        else:
            print(f"{C_RED}[!] Invalid selection.{C_RESET}")

if __name__ == "__main__":
    try:
        runtime_menu_loop()
    except KeyboardInterrupt:
        print(f"\n\n{C_RED}[-] Interrupted.{C_RESET}")
        sys.exit(0)