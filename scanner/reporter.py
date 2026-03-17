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
            "version": "1.0.0",
            "scan_date": datetime.now().isoformat(),
            "target": scan_data.get("target_url"),
            "joomla": {
                "version": scan_data.get("joomla_version"),
                "detection_method": scan_data.get("joomla_detection_method"),
                "confidence": scan_data.get("confidence", "unknown"),
            },
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

    def _build_vuln_html(self, vuln):
        """Build HTML for a single compact CVE card."""
        severity = (vuln.get("cvss_severity") or "low").lower()
        description = vuln.get("description") or "No description"
        # Truncate long descriptions for the card view
        short_desc = (description[:150] + "...") if len(description) > 150 else description
        fixed = vuln.get("fixed_version")
        fixed_html = f' | Fixed: <strong>{fixed}</strong>' if fixed else ''
        return f'''<div class="vuln-card vuln-card-{severity}">
            <div class="vuln-card-header">
                <span class="vuln-cve">{vuln.get("cve_id")}</span>
                <span class="badge badge-{severity}">{vuln.get("cvss_severity", "N/A")} {vuln.get("cvss_score", "")}</span>
            </div>
            <div class="vuln-card-desc">{short_desc}</div>
            <div class="vuln-card-meta">{vuln.get("published_date", "")}{fixed_html}</div>
        </div>'''

    def _build_component_html(self, comp, show_cves=True):
        """Build HTML for a component/module with its CVEs as compact cards."""
        cves = comp.get("cves", [])
        cves_html = ""
        if show_cves and cves:
            cards = "".join(self._build_vuln_html(v) for v in cves)
            cves_html = f'<div class="vuln-grid">{cards}</div>'

        return f'''
        <div class="component-item">
            <strong>{comp.get("name")}</strong> (version: {comp.get("version", "unknown")})
            <span style="color:#888;font-size:0.85em;margin-left:8px;">{len(cves)} CVE{"s" if len(cves) != 1 else ""}</span>
            {cves_html}
        </div>'''

    def _build_enum_table_html(self, items, item_type="component"):
        """Build an HTML table for enumerated components or modules."""
        if not items:
            return f'<p style="color: #999;">No {item_type}s detected.</p>'

        rows = ""
        for item in items:
            name = item.get("name", "unknown")
            version = item.get("version", "unknown")
            is_core = item.get("is_core", False)
            is_vulnerable = item.get("is_vulnerable", False)
            cve_count = len(item.get("cves", []))

            # Version tag
            if version == "unknown":
                ver_html = f'<span class="tag tag-unknown">unknown</span>'
            else:
                ver_html = version

            # Status tags
            tags = ""
            if is_core:
                tags += '<span class="tag tag-core">CORE</span> '
            if is_vulnerable:
                tags += f'<span class="tag tag-vuln">{cve_count} CVE{"s" if cve_count != 1 else ""}</span>'
            elif not is_vulnerable:
                tags += '<span class="tag tag-clean">No known CVEs</span>'

            rows += f"""
                <tr>
                    <td><strong>{name}</strong></td>
                    <td>{ver_html}</td>
                    <td>{tags}</td>
                </tr>"""

        return f"""
            <table class="enum-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>{rows}
                </tbody>
            </table>"""

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

        # Build core vulns HTML (individual cards, will be wrapped in vuln-grid by template)
        core_vulns_html = "".join(
            self._build_vuln_html(v)
            for v in scan_data.get("joomla_vulnerabilities", [])
        )

        # Build confirmed component vulns HTML
        confirmed_comps_html = "".join(
            self._build_component_html(c)
            for c in confirmed_comps
        )

        # Build confirmed module vulns HTML
        confirmed_mods_html = "".join(
            self._build_component_html(m)
            for m in confirmed_mods
        )

        # Build "Check Manually" section
        n_pot_comps = len(potential_comps)
        n_pot_mods = len(potential_mods)
        check_manually_html = ""
        if potential_comps or potential_mods:
            potential_items = ""
            if potential_comps:
                potential_items += "".join(
                    self._build_component_html(c)
                    for c in potential_comps
                )
            if potential_mods:
                potential_items += "".join(
                    self._build_component_html(m)
                    for m in potential_mods
                )
            check_manually_html = f'''
        <details class="section section-potential" open>
            <summary>Check Manually for Potential Vuln/Exploitable <span class="section-count">{n_pot_comps + n_pot_mods} items</span></summary>
            <div class="section-body">
                <p class="check-manually-note">The following components/modules were detected with known CVEs reported, but version could not be confirmed — verify manually.</p>
                {potential_items}
            </div>
        </details>'''

        # Build collapsible "Enumerated Components and Modules" section
        all_components = scan_data.get("components", [])
        all_modules = scan_data.get("modules", [])
        comp_table = self._build_enum_table_html(all_components, "component")
        mod_table = self._build_enum_table_html(all_modules, "module")

        enumerated_html = f'''
        <details class="section section-enum">
            <summary>Enumerated Components and Modules <span class="section-count">{len(all_components)} components, {len(all_modules)} modules</span></summary>
            <div class="section-body">
                <h3>Components ({len(all_components)})</h3>
                {comp_table}
                <h3>Modules ({len(all_modules)})</h3>
                {mod_table}
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
        * {{ box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px; font-size: 1.5em; }}
        .info-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin: 15px 0; }}
        .info-card {{ background: #f8f9fa; padding: 12px; border-radius: 6px; border-left: 4px solid #1a73e8; }}
        .info-card label {{ font-weight: bold; color: #666; font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.3px; }}
        .info-card value {{ display: block; margin-top: 3px; font-size: 1.05em; color: #333; }}
        .summary-cards {{ display: flex; gap: 10px; margin: 15px 0; flex-wrap: wrap; }}
        .summary-card {{ flex: 1; min-width: 100px; padding: 14px 10px; border-radius: 6px; text-align: center; }}
        .critical {{ background: #ffebee; border: 2px solid #d32f2f; }}
        .high {{ background: #fff3e0; border: 2px solid #f57c00; }}
        .medium {{ background: #fff8e1; border: 2px solid #fbc02d; }}
        .low {{ background: #e8f5e9; border: 2px solid #388e3c; }}
        .total {{ background: #e3f2fd; border: 2px solid #1976d2; }}
        .summary-number {{ font-size: 1.6em; font-weight: bold; }}
        .summary-card > div:last-child {{ font-size: 0.8em; color: #555; }}

        /* Collapsible sections */
        details.section {{ margin-top: 20px; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden; }}
        details.section > summary {{ cursor: pointer; padding: 12px 16px; font-size: 1em; font-weight: bold; user-select: none; display: flex; align-items: center; gap: 8px; }}
        details.section > summary:hover {{ background: #f1f3f5; }}
        details.section > summary::marker {{ font-size: 0.8em; }}
        details.section > .section-body {{ padding: 4px 16px 16px; }}
        .section-core > summary {{ background: #fff5f5; color: #c62828; border-bottom: 2px solid #ef9a9a; }}
        .section-comp > summary {{ background: #fff8e1; color: #e65100; border-bottom: 2px solid #ffe082; }}
        .section-mod > summary {{ background: #e8eaf6; color: #283593; border-bottom: 2px solid #9fa8da; }}
        .section-potential > summary {{ background: #fff3e0; color: #bf360c; border-bottom: 2px solid #ffcc80; }}
        .section-enum > summary {{ background: #f8f9fa; color: #495057; border-bottom: 1px solid #dee2e6; }}
        .section-count {{ font-size: 0.8em; font-weight: normal; color: #888; margin-left: auto; }}

        /* Compact CVE cards in a grid */
        .vuln-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 10px; margin-top: 8px; }}
        .vuln-card {{ border: 1px solid #e0e0e0; border-radius: 4px; padding: 8px 10px; font-size: 0.85em; border-left: 3px solid #dc3545; background: #fff; }}
        .vuln-card-critical {{ border-left-color: #d32f2f; }}
        .vuln-card-high {{ border-left-color: #f57c00; }}
        .vuln-card-medium {{ border-left-color: #fbc02d; }}
        .vuln-card-low {{ border-left-color: #388e3c; }}
        .vuln-card-header {{ display: flex; justify-content: space-between; align-items: center; gap: 6px; margin-bottom: 4px; }}
        .vuln-cve {{ font-weight: bold; font-size: 0.9em; color: #333; }}
        .vuln-card-desc {{ color: #555; font-size: 0.82em; line-height: 1.3; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
        .vuln-card-meta {{ color: #999; font-size: 0.75em; }}
        .badge {{ padding: 2px 8px; border-radius: 3px; font-size: 0.72em; font-weight: bold; white-space: nowrap; }}
        .badge-critical {{ background: #d32f2f; color: white; }}
        .badge-high {{ background: #f57c00; color: white; }}
        .badge-medium {{ background: #fbc02d; color: #333; }}
        .badge-low {{ background: #388e3c; color: white; }}
        .badge-none {{ background: #9e9e9e; color: white; }}

        /* Component items */
        .component-item {{ background: #fafafa; padding: 10px 12px; margin: 6px 0; border-radius: 4px; border-left: 3px solid #1976d2; font-size: 0.9em; }}

        /* Check manually note */
        .check-manually-note {{ color: #666; font-style: italic; margin: 4px 0 10px; font-size: 0.85em; }}

        /* Enum tables */
        .enum-content h3 {{ color: #495057; margin: 14px 0 6px; font-size: 0.95em; border-bottom: 1px solid #dee2e6; padding-bottom: 4px; }}
        .enum-table {{ width: 100%; border-collapse: collapse; margin-bottom: 10px; }}
        .enum-table th {{ background: #e9ecef; text-align: left; padding: 6px 10px; font-size: 0.8em; color: #495057; border-bottom: 2px solid #dee2e6; }}
        .enum-table td {{ padding: 4px 10px; border-bottom: 1px solid #eee; font-size: 0.85em; }}
        .enum-table tr:hover {{ background: #f8f9fa; }}
        .tag {{ display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 0.72em; font-weight: bold; }}
        .tag-core {{ background: #e3f2fd; color: #1565c0; }}
        .tag-vuln {{ background: #ffebee; color: #c62828; }}
        .tag-clean {{ background: #e8f5e9; color: #2e7d32; }}
        .tag-unknown {{ background: #fff8e1; color: #f57f17; }}
        .timestamp {{ color: #999; font-size: 0.8em; text-align: right; margin-top: 20px; }}
        .none-msg {{ color: #888; font-size: 0.85em; padding: 6px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>JoomlaScanner Report</h1>

        <div class="info-grid">
            <div class="info-card">
                <label>Target URL</label>
                <value>{scan_data.get("target_url")}</value>
            </div>
            <div class="info-card">
                <label>Joomla Version</label>
                <value>{scan_data.get("joomla_version", "Unknown")}</value>
            </div>
            <div class="info-card">
                <label>Detection Method</label>
                <value>{scan_data.get("joomla_detection_method", "N/A")}</value>
            </div>
            <div class="info-card">
                <label>Components Found</label>
                <value>{scan_data.get("total_components", 0)}</value>
            </div>
        </div>

        <div class="summary-cards">
            <div class="summary-card total">
                <div class="summary-number">{summary.get("total", 0)}</div>
                <div>Total</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-number">{summary.get("critical", 0)}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-number">{summary.get("high", 0)}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-number">{summary.get("medium", 0)}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="summary-number">{summary.get("low", 0)}</div>
                <div>Low</div>
            </div>
        </div>

        <details class="section section-core" {"open" if n_core > 0 else ""}>
            <summary>Joomla Core Vulnerabilities <span class="section-count">{n_core} CVEs</span></summary>
            <div class="section-body">
                {"<div class='vuln-grid'>" + core_vulns_html + "</div>" if n_core > 0 else '<p class="none-msg">No core vulnerabilities found.</p>'}
            </div>
        </details>

        <details class="section section-comp" {"open" if n_conf_comps > 0 else ""}>
            <summary>Component Vulnerabilities <span class="section-count">{n_conf_comps} components</span></summary>
            <div class="section-body">
                {confirmed_comps_html if n_conf_comps > 0 else '<p class="none-msg">No confirmed component vulnerabilities.</p>'}
            </div>
        </details>

        <details class="section section-mod" {"open" if n_conf_mods > 0 else ""}>
            <summary>Module Vulnerabilities <span class="section-count">{n_conf_mods} modules</span></summary>
            <div class="section-body">
                {confirmed_mods_html if n_conf_mods > 0 else '<p class="none-msg">No confirmed module vulnerabilities.</p>'}
            </div>
        </details>

        {check_manually_html}

        {enumerated_html}

        <div class="timestamp">
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
