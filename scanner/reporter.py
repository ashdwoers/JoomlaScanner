import json
import os
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    COLOR_AVAILABLE = True
except ImportError:
    COLOR_AVAILABLE = False

    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""


def get_severity_color(cvss_score, cvss_severity):
    if not COLOR_AVAILABLE:
        return ""

    score = cvss_score or 0
    severity = (cvss_severity or "").upper()

    if score >= 9.0 or severity == "CRITICAL":
        return Fore.RED + Style.BRIGHT
    elif score >= 7.0 or severity == "HIGH":
        return Fore.RED
    elif score >= 4.0 or severity == "MEDIUM":
        return Fore.YELLOW
    elif score > 0 or severity == "LOW":
        return Fore.CYAN
    return Fore.WHITE


def reset_color():
    if COLOR_AVAILABLE:
        return Style.RESET_ALL
    return ""


class Reporter:
    def __init__(self):
        pass

    @staticmethod
    def _format_size(size_bytes):
        """Format a byte count into a human-readable string."""
        if size_bytes is None:
            return "unknown size"
        try:
            size_bytes = int(size_bytes)
        except (TypeError, ValueError):
            return "unknown size"
        for unit in ("B", "KB", "MB", "GB"):
            if abs(size_bytes) < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"

    @staticmethod
    def _ensure_output_path(output_file, ext, target_url):
        """Resolve the output path: use given path, or auto-generate inside reports/."""
        if output_file:
            path = Path(output_file)
        else:
            reports_dir = Path(__file__).parent.parent / "reports"
            # Build a safe filename from the target hostname
            hostname = "unknown"
            try:
                parsed = urlparse(target_url or "")
                hostname = parsed.hostname or "unknown"
            except Exception:
                pass
            safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = reports_dir / f"{safe_host}_{timestamp}.{ext}"

        # Create parent directories if needed
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _separate_confirmed_potential(self, items):
        """Separate items into confirmed and potential (unknown version) lists."""
        confirmed = []
        potential = []
        for item in items:
            cves = item.get("cves", [])
            has_confirmed = any(v.get("match_type") == "confirmed" for v in cves)
            has_potential = any(v.get("match_type") == "potential" for v in cves)
            if has_confirmed:
                confirmed.append(item)
            elif has_potential:
                potential.append(item)
        return confirmed, potential

    def generate_json_report(self, scan_data, output_file=None):
        comp_vulns = scan_data.get("component_vulnerabilities", [])
        mod_vulns = scan_data.get("module_vulnerabilities", [])

        confirmed_comps, potential_comps = self._separate_confirmed_potential(comp_vulns)
        confirmed_mods, potential_mods = self._separate_confirmed_potential(mod_vulns)

        report = {
            "scanner": "JoomlaScanner",
            "version": "1.0.1",
            "scan_date": datetime.now().isoformat(),
            "target": scan_data.get("target_url"),
            "joomla": {
                "version": scan_data.get("joomla_version"),
                "detection_method": scan_data.get("joomla_detection_method"),
                "confidence": scan_data.get("confidence", "unknown"),
            },
            "backup_files": scan_data.get("backup_files", []),
            "components": scan_data.get("components", []),
            "modules": scan_data.get("modules", []),
            "vulnerabilities": {
                "joomla_core": scan_data.get("joomla_vulnerabilities", []),
                "components": confirmed_comps,
                "modules": confirmed_mods,
            },
            "check_manually": {
                "description": "Version unknown - CVEs reported for these components/modules. Verify manually.",
                "components": potential_comps,
                "modules": potential_mods,
            },
            "enumerated": {
                "components": scan_data.get("components", []),
                "modules": scan_data.get("modules", []),
            },
            "summary": scan_data.get("summary", {}),
            "statistics": {
                "total_components_found": scan_data.get("total_components", 0),
                "total_vulnerabilities": scan_data.get("summary", {}).get("total", 0),
                "critical": scan_data.get("summary", {}).get("critical", 0),
                "high": scan_data.get("summary", {}).get("high", 0),
                "medium": scan_data.get("summary", {}).get("medium", 0),
                "low": scan_data.get("summary", {}).get("low", 0),
            },
        }

        json_output = json.dumps(report, indent=2)

        path = self._ensure_output_path(output_file, "json", scan_data.get("target_url"))
        with open(path, "w") as f:
            f.write(json_output)
        print(f"[+] JSON report saved to: {path}")

        return json_output

    def generate_html_report(self, scan_data, output_file=None):
        html = self._generate_html(scan_data)

        path = self._ensure_output_path(output_file, "html", scan_data.get("target_url"))
        with open(path, "w") as f:
            f.write(html)
        print(f"[+] HTML report saved to: {path}")

        return html

    def print_console_report(self, scan_data):
        c = get_severity_color
        r = reset_color

        print("\n" + "=" * 60)
        print(f"{Fore.CYAN}  JoomlaScanner Report{r()}")
        print("=" * 60)

        print(f"\nTarget: {scan_data.get('target_url')}")

        joomla_ver = scan_data.get("joomla_version")
        if joomla_ver:
            print(
                f"Joomla Version: {Fore.GREEN}{joomla_ver}{r()} (method: {scan_data.get('joomla_detection_method')})"
            )
        else:
            print(f"Joomla Version: {Fore.YELLOW}Unknown{r()}")

        # Backup files
        backup_files = scan_data.get("backup_files", [])
        if backup_files:
            print(f"\n{Fore.RED}Backup/Sensitive Files Found ({len(backup_files)}):{r()}")
            for bf in backup_files:
                size = self._format_size(bf.get("content_length"))
                print(f"  - {bf['filename']} ({size}) — {bf['url']}")

        print(f"\nComponents Found: {scan_data.get('total_components', 0)}")

        summary = scan_data.get("summary", {})
        print(f"\nVulnerability Summary:")
        print(f"  Total: {summary.get('total', 0)}")
        print(f"  {c(0, 'CRITICAL')}Critical: {summary.get('critical', 0)}{r()}")
        print(f"  {c(7, 'HIGH')}High: {summary.get('high', 0)}{r()}")
        print(f"  {c(4, 'MEDIUM')}Medium: {summary.get('medium', 0)}{r()}")
        print(f"  {c(0.1, 'LOW')}Low: {summary.get('low', 0)}{r()}")

        joomla_vulns = scan_data.get("joomla_vulnerabilities", [])
        if joomla_vulns:
            print(
                f"\n{Fore.RED}Joomla Core Vulnerabilities ({len(joomla_vulns)}):{r()}"
            )
            for vuln in joomla_vulns:
                color = c(vuln.get("cvss_score"), vuln.get("cvss_severity"))
                print(
                    f"  - {vuln.get('cve_id')}: {color}{vuln.get('cvss_score', 'N/A')}{r()} - {vuln.get('cvss_severity', 'N/A')}"
                )
                print(
                    f"    Fixed in: {Fore.GREEN}{vuln.get('fixed_version', 'Unknown')}{r()}"
                )

        # Separate confirmed vs potential (unknown version) vulnerabilities
        comp_vulns = scan_data.get("component_vulnerabilities", [])
        confirmed_comps = [c_ for c_ in comp_vulns if any(
            v.get("match_type") == "confirmed" for v in c_.get("cves", [])
        )]
        potential_comps = [c_ for c_ in comp_vulns if any(
            v.get("match_type") == "potential" for v in c_.get("cves", [])
        ) and not any(
            v.get("match_type") == "confirmed" for v in c_.get("cves", [])
        )]

        modules_vulns = scan_data.get("module_vulnerabilities", [])
        confirmed_mods = [m_ for m_ in modules_vulns if any(
            v.get("match_type") == "confirmed" for v in m_.get("cves", [])
        )]
        potential_mods = [m_ for m_ in modules_vulns if any(
            v.get("match_type") == "potential" for v in m_.get("cves", [])
        ) and not any(
            v.get("match_type") == "confirmed" for v in m_.get("cves", [])
        )]

        if confirmed_comps:
            print(f"\n{Fore.RED}Component Vulnerabilities ({len(confirmed_comps)}):{r()}")
            for comp in confirmed_comps:
                print(f"  - {comp.get('name')}: {comp.get('version')}")
                for vuln in comp.get("cves", []):
                    if vuln.get("match_type") == "confirmed":
                        color = c(vuln.get("cvss_score"), vuln.get("cvss_severity"))
                        print(
                            f"    * {vuln.get('cve_id')}: {color}{vuln.get('cvss_score', 'N/A')}{r()} - {vuln.get('cvss_severity', 'N/A')}"
                        )
                        print(
                            f"      Fixed in: {Fore.GREEN}{vuln.get('fixed_version', 'Unknown')}{r()}"
                        )

        if confirmed_mods:
            print(f"\n{Fore.RED}Module Vulnerabilities ({len(confirmed_mods)}):{r()}")
            for mod in confirmed_mods:
                print(f"  - {mod.get('name')}: {mod.get('version')}")
                for vuln in mod.get("cves", []):
                    if vuln.get("match_type") == "confirmed":
                        color = c(vuln.get("cvss_score"), vuln.get("cvss_severity"))
                        print(
                            f"    * {vuln.get('cve_id')}: {color}{vuln.get('cvss_score', 'N/A')}{r()} - {vuln.get('cvss_severity', 'N/A')}"
                        )
                        print(
                            f"      Fixed in: {Fore.GREEN}{vuln.get('fixed_version', 'Unknown')}{r()}"
                        )

        if potential_comps or potential_mods:
            print(f"\n{Fore.YELLOW}{'=' * 60}{r()}")
            print(f"{Fore.YELLOW}  Check Manually for Potential Vuln/Exploitable{r()}")
            print(f"{Fore.YELLOW}{'=' * 60}{r()}")
            print(f"{Fore.YELLOW}  (Version unknown - CVEs reported for these components/modules){r()}")

            if potential_comps:
                print(f"\n  {Fore.YELLOW}Components ({len(potential_comps)}):{r()}")
                for comp in potential_comps:
                    print(f"    - {comp.get('name')} (version: unknown)")
                    for vuln in comp.get("cves", []):
                        color = c(vuln.get("cvss_score"), vuln.get("cvss_severity"))
                        print(
                            f"      * {vuln.get('cve_id')}: {color}{vuln.get('cvss_score', 'N/A')}{r()} - {vuln.get('cvss_severity', 'N/A')}"
                        )

            if potential_mods:
                print(f"\n  {Fore.YELLOW}Modules ({len(potential_mods)}):{r()}")
                for mod in potential_mods:
                    print(f"    - {mod.get('name')} (version: unknown)")
                    for vuln in mod.get("cves", []):
                        color = c(vuln.get("cvss_score"), vuln.get("cvss_severity"))
                        print(
                            f"      * {vuln.get('cve_id')}: {color}{vuln.get('cvss_score', 'N/A')}{r()} - {vuln.get('cvss_severity', 'N/A')}"
                        )

        # Enumerated Components and Modules
        all_components = scan_data.get("components", [])
        all_modules = scan_data.get("modules", [])
        if all_components or all_modules:
            print(f"\n{Fore.CYAN}{'=' * 60}{r()}")
            print(f"{Fore.CYAN}  Enumerated Components and Modules{r()}")
            print(f"{Fore.CYAN}{'=' * 60}{r()}")

            if all_components:
                print(f"\n  {Fore.CYAN}Components ({len(all_components)}):{r()}")
                for comp in all_components:
                    name = comp.get("name")
                    ver = comp.get("version", "unknown")
                    is_core = comp.get("is_core", False)
                    is_vuln = comp.get("is_vulnerable", False)
                    cve_count = len(comp.get("cves", []))
                    tags = ""
                    if is_core:
                        tags += " [CORE]"
                    if is_vuln:
                        tags += f" {Fore.RED}[{cve_count} CVE{'s' if cve_count != 1 else ''}]{r()}"
                    print(f"    - {name} (version: {ver}){tags}")

            if all_modules:
                print(f"\n  {Fore.CYAN}Modules ({len(all_modules)}):{r()}")
                for mod in all_modules:
                    name = mod.get("name")
                    ver = mod.get("version", "unknown")
                    is_vuln = mod.get("is_vulnerable", False)
                    cve_count = len(mod.get("cves", []))
                    tags = ""
                    if is_vuln:
                        tags += f" {Fore.RED}[{cve_count} CVE{'s' if cve_count != 1 else ''}]{r()}"
                    print(f"    - {name} (version: {ver}){tags}")

        print("\n" + "=" * 60)

    _SEVERITY_COLORS = {
        "critical": "#d63939",
        "high": "#f76707",
        "medium": "#f59f00",
        "low": "#2fb344",
    }

    _SEVERITY_BG = {
        "critical": "#fbe4e4",
        "high": "#fff0e6",
        "medium": "#fff8e1",
        "low": "#e6f9ed",
    }

    def _sev_badge(self, severity, score):
        """Return an inline-styled severity badge."""
        sev = (severity or "low").lower()
        color = self._SEVERITY_COLORS.get(sev, "#666")
        bg = self._SEVERITY_BG.get(sev, "#eee")
        label = f"{severity or 'N/A'} {score}" if score else (severity or "N/A")
        return f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:600;color:{color};background:{bg};">{label}</span>'

    def _build_vuln_html(self, vuln):
        """Build HTML for a single CVE entry."""
        severity = (vuln.get("cvss_severity") or "low").lower()
        color = self._SEVERITY_COLORS.get(severity, "#666")
        description = vuln.get("description") or "No description"
        short_desc = (description[:150] + "...") if len(description) > 150 else description
        fixed = vuln.get("fixed_version")
        fixed_html = f' | Fixed: <strong>{fixed}</strong>' if fixed else ''
        badge = self._sev_badge(vuln.get("cvss_severity"), vuln.get("cvss_score"))
        return f'''<div style="border:1px solid #e0e0e0;border-radius:4px;padding:8px 12px;margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:4px;">
                <a href="https://nvd.nist.gov/vuln/detail/{vuln.get("cve_id")}" target="_blank" rel="noopener" style="font-weight:700;color:#1a6dcc;text-decoration:none;">{vuln.get("cve_id")}</a>
                {badge}
            </div>
            <div style="color:#666;font-size:.85em;margin-top:4px;">{short_desc}</div>
            <div style="color:#999;font-size:.75em;margin-top:4px;">{vuln.get("published_date", "")}{fixed_html}</div>
        </div>'''

    def _build_component_html(self, comp, show_cves=True):
        """Build HTML for a component/module with its CVEs."""
        cves = comp.get("cves", [])
        cves_html = ""
        if show_cves and cves:
            cards = "".join(self._build_vuln_html(v) for v in cves)
            cves_html = f'<div style="margin-top:8px;">{cards}</div>'
        count = len(cves)
        return f'''<div style="border:1px solid #e0e0e0;border-radius:4px;padding:8px 12px;margin-bottom:8px;">
            <strong>{comp.get("name")}</strong> <span style="color:#888;">(version: {comp.get("version", "unknown")})</span>
            <span style="display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75em;background:#eee;color:#555;margin-left:6px;">{count} CVE{"s" if count != 1 else ""}</span>
            {cves_html}
        </div>'''

    def _build_enum_table_html(self, items, item_type="component"):
        """Build a plain HTML table for enumerated components or modules."""
        if not items:
            return f'<p style="color:#888;">No {item_type}s detected.</p>'

        rows = ""
        for item in items:
            name = item.get("name", "unknown")
            version = item.get("version", "unknown")
            is_core = item.get("is_core", False)
            is_vulnerable = item.get("is_vulnerable", False)
            cve_count = len(item.get("cves", []))

            ver_html = f'<span style="padding:1px 6px;border-radius:3px;font-size:.8em;background:#fff8e1;color:#f59f00;">unknown</span>' if version == "unknown" else version

            tags = ""
            if is_core:
                tags += '<span style="padding:1px 6px;border-radius:3px;font-size:.8em;background:#e0f0ff;color:#1a6dcc;margin-right:4px;">CORE</span>'
            if is_vulnerable:
                tags += f'<span style="padding:1px 6px;border-radius:3px;font-size:.8em;background:#fbe4e4;color:#d63939;">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>'
            else:
                tags += '<span style="padding:1px 6px;border-radius:3px;font-size:.8em;background:#e6f9ed;color:#2fb344;">No known CVEs</span>'

            rows += f"""<tr>
                    <td style="padding:6px 8px;"><strong>{name}</strong></td>
                    <td style="padding:6px 8px;">{ver_html}</td>
                    <td style="padding:6px 8px;">{tags}</td>
                </tr>"""

        return f"""<div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:.9em;">
                <thead><tr style="border-bottom:2px solid #e0e0e0;text-align:left;">
                    <th style="padding:6px 8px;">Name</th>
                    <th style="padding:6px 8px;">Version</th>
                    <th style="padding:6px 8px;">Status</th>
                </tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _generate_html(self, scan_data):
        # Separate confirmed vs potential vulnerabilities for components
        comp_vulns = scan_data.get("component_vulnerabilities", [])
        confirmed_comps = [c for c in comp_vulns if any(
            v.get("match_type") == "confirmed" for v in c.get("cves", [])
        )]
        potential_comps = [c for c in comp_vulns if any(
            v.get("match_type") == "potential" for v in c.get("cves", [])
        ) and not any(
            v.get("match_type") == "confirmed" for v in c.get("cves", [])
        )]

        # Separate confirmed vs potential vulnerabilities for modules
        mod_vulns = scan_data.get("module_vulnerabilities", [])
        confirmed_mods = [m for m in mod_vulns if any(
            v.get("match_type") == "confirmed" for v in m.get("cves", [])
        )]
        potential_mods = [m for m in mod_vulns if any(
            v.get("match_type") == "potential" for v in m.get("cves", [])
        ) and not any(
            v.get("match_type") == "confirmed" for v in m.get("cves", [])
        )]

        # Build core vulns HTML
        core_vulns_html = "".join(
            self._build_vuln_html(v)
            for v in scan_data.get("joomla_vulnerabilities", [])
        )

        # Build confirmed component vulns HTML
        confirmed_comps_html = "".join(
            self._build_component_html(c) for c in confirmed_comps
        )

        # Build confirmed module vulns HTML
        confirmed_mods_html = "".join(
            self._build_component_html(m) for m in confirmed_mods
        )

        # Build "Check Manually" section
        n_pot_comps = len(potential_comps)
        n_pot_mods = len(potential_mods)
        check_manually_html = ""
        if potential_comps or potential_mods:
            potential_items = ""
            if potential_comps:
                potential_items += "".join(
                    self._build_component_html(c) for c in potential_comps
                )
            if potential_mods:
                potential_items += "".join(
                    self._build_component_html(m) for m in potential_mods
                )
            check_manually_html = f'''
            <details style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;">
                <summary style="padding:12px 16px;cursor:pointer;font-weight:700;font-size:1em;background:#fafafa;border-radius:6px;">
                    Check Manually for Potential Vuln/Exploitable
                    <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#fff0e6;color:#f76707;margin-left:8px;">{n_pot_comps + n_pot_mods} items</span>
                </summary>
                <div style="padding:12px 16px;">
                    <p style="color:#888;font-style:italic;">The following components/modules were detected with known CVEs reported, but version could not be confirmed — verify manually.</p>
                    {potential_items}
                </div>
            </details>'''

        # Build enumerated components and modules section
        all_components = scan_data.get("components", [])
        all_modules = scan_data.get("modules", [])
        comp_table = self._build_enum_table_html(all_components, "component")
        mod_table = self._build_enum_table_html(all_modules, "module")

        enumerated_html = f'''
            <details style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;">
                <summary style="padding:12px 16px;cursor:pointer;font-weight:700;font-size:1em;background:#fafafa;border-radius:6px;">
                    Enumerated Components and Modules
                    <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#eee;color:#555;margin-left:8px;">{len(all_components)} components, {len(all_modules)} modules</span>
                </summary>
                <div style="padding:12px 16px;">
                    <h4>Components ({len(all_components)})</h4>
                    {comp_table}
                    <h4 style="margin-top:16px;">Modules ({len(all_modules)})</h4>
                    {mod_table}
                </div>
            </details>'''

        # Build backup files HTML
        backup_files = scan_data.get("backup_files", [])
        backup_html = ""
        if backup_files:
            rows = ""
            for bf in backup_files:
                size = self._format_size(bf.get("content_length"))
                ct = bf.get("content_type", "")
                url = bf.get("url", "")
                lm = bf.get("last_modified", "")
                rows += f"""<tr style="border-bottom:1px solid #eee;">
                        <td style="padding:6px 8px;"><strong>{bf.get("filename", "")}</strong></td>
                        <td style="padding:6px 8px;">{size}</td>
                        <td style="padding:6px 8px;word-break:break-all;"><a href="{url}" target="_blank" rel="noopener" style="color:#1a6dcc;text-decoration:none;">{url}</a></td>
                    </tr>"""
            backup_html = f'''
            <details open style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;">
                <summary style="padding:12px 16px;cursor:pointer;font-weight:700;font-size:1em;background:#fafafa;border-radius:6px;">
                    Backup/Sensitive Files Discovered
                    <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#fbe4e4;color:#d63939;margin-left:8px;">{len(backup_files)} files</span>
                </summary>
                <div style="padding:12px 16px;">
                    <div style="background:#fbe4e4;color:#d63939;padding:10px 14px;border-radius:4px;margin-bottom:12px;font-size:.9em;">
                        Exposed backup and sensitive files are a security risk. These should be removed or access-restricted immediately.
                    </div>
                    <div style="overflow-x:auto;">
                    <table style="width:100%;border-collapse:collapse;font-size:.9em;">
                        <thead><tr style="border-bottom:2px solid #e0e0e0;text-align:left;">
                            <th style="padding:6px 8px;">Filename</th>
                            <th style="padding:6px 8px;">Size</th>
                            <th style="padding:6px 8px;">URL</th>
                        </tr></thead>
                        <tbody>{rows}</tbody>
                    </table>
                    </div>
                </div>
            </details>'''

        # Count items for section headers
        joomla_vulns_list = scan_data.get("joomla_vulnerabilities", [])
        n_core = len(joomla_vulns_list)
        n_conf_comps = len(confirmed_comps)
        n_conf_mods = len(confirmed_mods)

        summary = scan_data.get("summary", {})

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JoomlaScanner Report - {scan_data.get("target_url")}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background: #f8f9fa; line-height: 1.5; }}
        a {{ color: #1a6dcc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .wrap {{ max-width: 960px; margin: 0 auto; padding: 16px; }}
        .header {{ background: #1e293b; color: #fff; padding: 20px 16px; margin-bottom: 20px; border-radius: 6px; }}
        .header small {{ color: #94a3b8; display: block; font-size: .85em; margin-bottom: 4px; }}
        .header h1 {{ font-size: 1.4em; font-weight: 700; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; margin-bottom: 20px; }}
        .info-card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px 16px; }}
        .info-card .label {{ font-size: .75em; text-transform: uppercase; color: #888; letter-spacing: .5px; }}
        .info-card .value {{ font-size: 1.1em; font-weight: 600; word-break: break-word; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 10px; margin-bottom: 20px; }}
        .summary-card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 12px; text-align: center; }}
        .summary-card .label {{ font-size: .75em; text-transform: uppercase; color: #888; }}
        .summary-card .num {{ font-size: 1.8em; font-weight: 700; }}
        .section {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 16px; }}
        .section > details {{ border: none; }}
        .section > details > summary {{ padding: 12px 16px; cursor: pointer; font-weight: 700; font-size: 1em; }}
        .section-body {{ padding: 12px 16px; }}
        .footer {{ text-align: right; color: #888; font-size: .85em; margin-top: 16px; }}
    </style>
</head>
<body>
<div class="wrap">
    <div class="header">
        <small>Vulnerability Scan</small>
        <h1>JoomlaScanner Report</h1>
    </div>

    <div class="info-grid">
        <div class="info-card">
            <div class="label">Target URL</div>
            <div class="value">{scan_data.get("target_url")}</div>
        </div>
        <div class="info-card">
            <div class="label">Joomla Version</div>
            <div class="value">{scan_data.get("joomla_version", "Unknown")}</div>
        </div>
        <div class="info-card">
            <div class="label">Detection Method</div>
            <div class="value">{scan_data.get("joomla_detection_method", "N/A")}</div>
        </div>
        <div class="info-card">
            <div class="label">Components Found</div>
            <div class="value">{scan_data.get("total_components", 0)}</div>
        </div>
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="label">Total</div>
            <div class="num">{summary.get("total", 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Critical</div>
            <div class="num" style="color:#d63939;">{summary.get("critical", 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">High</div>
            <div class="num" style="color:#f76707;">{summary.get("high", 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Medium</div>
            <div class="num" style="color:#f59f00;">{summary.get("medium", 0)}</div>
        </div>
        <div class="summary-card">
            <div class="label">Low</div>
            <div class="num" style="color:#2fb344;">{summary.get("low", 0)}</div>
        </div>
    </div>

    {backup_html}

    <details style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;background:#fff;">
        <summary style="padding:12px 16px;cursor:pointer;font-weight:700;">
            Joomla Core Vulnerabilities
            <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#fbe4e4;color:#d63939;margin-left:8px;">{n_core} CVEs</span>
        </summary>
        <div style="padding:12px 16px;">
            {core_vulns_html if n_core > 0 else '<p style="color:#888;">No core vulnerabilities found.</p>'}
        </div>
    </details>

    <details style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;background:#fff;">
        <summary style="padding:12px 16px;cursor:pointer;font-weight:700;">
            Component Vulnerabilities
            <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#fff0e6;color:#f76707;margin-left:8px;">{n_conf_comps} components</span>
        </summary>
        <div style="padding:12px 16px;">
            {confirmed_comps_html if n_conf_comps > 0 else '<p style="color:#888;">No confirmed component vulnerabilities.</p>'}
        </div>
    </details>

    <details style="margin-top:16px;border:1px solid #e0e0e0;border-radius:6px;background:#fff;">
        <summary style="padding:12px 16px;cursor:pointer;font-weight:700;">
            Module Vulnerabilities
            <span style="padding:1px 8px;border-radius:3px;font-size:.8em;background:#e8eaf6;color:#5c6bc0;margin-left:8px;">{n_conf_mods} modules</span>
        </summary>
        <div style="padding:12px 16px;">
            {confirmed_mods_html if n_conf_mods > 0 else '<p style="color:#888;">No confirmed module vulnerabilities.</p>'}
        </div>
    </details>

    {check_manually_html}

    {enumerated_html}

    <div class="footer">
        Scan completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    </div>
</div>
</body>
</html>"""


def generate_report(scan_data, format="console", output=None):
    reporter = Reporter()

    # Always print the console summary
    reporter.print_console_report(scan_data)

    # Export to file when requested
    if format == "json":
        return reporter.generate_json_report(scan_data, output)
    elif format == "html":
        return reporter.generate_html_report(scan_data, output)

    return None


if __name__ == "__main__":
    test_data = {
        "target_url": "https://example.com",
        "joomla_version": "3.9.5",
        "joomla_detection_method": "xml_file",
        "confidence": "high",
        "components": [],
        "joomla_vulnerabilities": [
            {
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "fixed_version": "3.9.6",
                "description": "Test vulnerability",
            }
        ],
        "component_vulnerabilities": [],
        "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0},
        "total_components": 0,
    }

    reporter = Reporter()
    reporter.generate_html_report(test_data, "test_report.html")
    print("Test report generated!")
