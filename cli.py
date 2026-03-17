#!/usr/bin/env python3
import argparse
import json
import sys
import time
import warnings
from pathlib import Path
from urllib.parse import urlparse

warnings.filterwarnings("ignore")

from scanner.db import Database
from scanner.fetcher import CVEFetcher
from scanner.detector import VersionDetector
from scanner.component import ComponentEnumerator, ModuleEnumerator
from scanner.matcher import CVEMatcher
from scanner.reporter import generate_report
from scanner.component_scraper import ComponentScraper


def print_banner():
    banner = r"""
     __        __                       __       __                       __       __  __           __
| | |   >>|<< |  | | |  >>  >>|<< |  | |   |<<     |  >>   >>  |\ /| |   |  | |<< |<< |  | | | | | |   |<<
\</ |<<   |   |><| |\| |  |   |   |><| |<< |>>| << | |  | |  | | < | |   |><| --  |   |><| |\| |\| |<< |>>|
 |  |__   |   |  | | |  <<    |   |  | |__ |  \ |__'  <<   <<  |   | |<< |  | >>| |__ |  | | | | | |__ |  \

    Joomla Vulnerability Scanner v1.0
    ==================================
    """
    print(banner)


def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        return f"https://{url}"
    return url


# =========================================================================
# scan
# =========================================================================

def scan_target(args):
    target = validate_url(args.target)

    print(f"[*] Scanning target: {target}")
    print("-" * 50)

    start_time = time.time()

    db = Database()

    version_result = None
    if not args.components_only:
        print("\n[1/4] Detecting Joomla version...")
        detector = VersionDetector(target, timeout=args.timeout)
        version_result = detector.detect(verbose=True)
        joomla_version = version_result
    else:
        joomla_version = None
        print("\n[1/4] Skipping version detection (--components-only)")

    components = []
    modules = []
    if not args.version_only:
        print("\n[2/4] Enumerating components...")
        enumerator = ComponentEnumerator(target, db=db, timeout=args.timeout, threads=args.threads)
        components = enumerator.enumerate_components(
            verbose=True, quick_scan=not args.full, joomla_version=version_result
        )
        print(f"[+] Found {len(components)} components")

        print("\n[2b/4] Enumerating modules...")
        module_enum = ModuleEnumerator(target, db=db, timeout=args.timeout, threads=args.threads)
        modules = module_enum.enumerate_modules(verbose=True, quick_scan=not args.full)
        print(f"[+] Found {len(modules)} modules")
    else:
        print("\n[2/4] Skipping component/module enumeration (--version-only)")

    vulnerabilities = {"joomla_core": [], "components": [], "modules": []}
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    if not args.version_only:
        print("\n[3/4] Matching vulnerabilities...")
        matcher = CVEMatcher(db)

        if joomla_version:
            vulnerabilities["joomla_core"] = matcher.match_joomla_cves(
                joomla_version, verbose=True
            )

        if components:
            vulnerabilities["components"] = matcher.match_component_cves(
                components, verbose=True
            )

        if modules:
            vulnerabilities["modules"] = matcher.match_module_cves(
                modules, verbose=True
            )

        all_vulns = (
            vulnerabilities["joomla_core"]
            + [{**v, "component": v["name"]} for v in vulnerabilities["components"]]
            + [{**v, "module": v["name"]} for v in vulnerabilities["modules"]]
        )
        summary = matcher.get_vulnerability_summary(all_vulns)

    elapsed = time.time() - start_time

    scan_data = {
        "target_url": target,
        "joomla_version": version_result,
        "joomla_detection_method": getattr(detector, "detection_method", "unknown")
        if not args.components_only
        else None,
        "confidence": getattr(detector, "confidence", "unknown")
        if not args.components_only
        else None,
        "components": components,
        "modules": modules,
        "joomla_vulnerabilities": vulnerabilities["joomla_core"],
        "component_vulnerabilities": vulnerabilities["components"],
        "module_vulnerabilities": vulnerabilities["modules"],
        "summary": summary,
        "total_components": len(components) + len(modules),
        "scan_duration": f"{elapsed:.2f}s",
    }

    print("\n[4/4] Generating report...")
    generate_report(scan_data, format=args.format, output=args.output)

    print(f"\n[+] Scan complete in {elapsed:.2f}s")

    return scan_data


# =========================================================================
# update  —  single command for CVEs + extensions
# =========================================================================

def _update_cves(args):
    """Run the CVE portion of an update."""
    print("[*] Updating CVE database...")

    fetcher = CVEFetcher()

    if args.full:
        print("[*] Full CVE refresh...")
        fetcher.fetch_all_joomla_cves(verbose=True)
    elif args.year:
        if args.range:
            start_year = int(args.year)
            end_year = int(args.range)
            print(f"[*] Fetching CVEs from {start_year} to {end_year}...")
            fetcher.fetch_year_range(start_year, end_year, verbose=True)
        else:
            print(f"[*] Fetching CVEs for year {args.year}...")
            fetcher.fetch_by_year(int(args.year), verbose=True)
    else:
        fetcher.fetch_new_cves(days=7, verbose=True)

    stats = fetcher.get_stats()
    print(f"[+] CVEs:  {stats['core_cves']} core, {stats['component_cves']} component")


def _update_extensions(args):
    """Run the extension (component + module) portion of an update."""
    scraper = ComponentScraper(verbose=True)

    if args.source:
        print(f"[*] Updating extensions from source: {args.source}")
        scraper.merge_source(args.source)
    elif args.quick:
        print("[*] Quick extension update (JED Algolia + GitHub core)...")
        scraper.quick_update()
    else:
        print("[*] Full extension update from all sources...")
        scraper.merge_all_sources()

    comp_count = scraper.export_components_json()
    scraper.export_to_database()
    mod_count = scraper.export_modules_json()
    scraper.export_modules_to_database()

    print(f"[+] Extensions:  {comp_count} components, {mod_count} modules")


def run_update(args):
    """
    `python cli.py update`            — update everything (CVEs + extensions)
    `python cli.py update --cves`     — CVEs only
    `python cli.py update --ext`      — extensions only
    """
    only_cves = args.cves
    only_ext = args.ext

    # No filter flags → update everything
    run_all = not only_cves and not only_ext

    if run_all or only_cves:
        _update_cves(args)

    if run_all or only_ext:
        _update_extensions(args)

    print("\n[+] Update complete!")


# =========================================================================
# stats
# =========================================================================

def show_stats(args):
    db = Database()
    fetcher = CVEFetcher(db)
    stats = fetcher.get_stats()

    print("\nJoomlaScanner Database Statistics")
    print("=" * 40)
    print(f"  Core CVEs:           {stats['core_cves']}")
    print(f"  Component CVEs:      {stats['component_cves']}")
    print(f"  Tracked Components:  {stats['tracked_components']}")

    # Component JSON stats
    json_path = Path(__file__).parent / "data" / "components.json"
    if json_path.exists():
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict) and "metadata" in data:
                cs = data["metadata"]
                print(f"\nComponent Database (components.json):")
                print(f"  Total Components:    {cs.get('total_components', 'N/A')}")
                print(f"  Core Components:     {cs.get('total_core', 'N/A')}")
                print(f"  With Known CVEs:     {cs.get('total_with_cves', 'N/A')}")
                print(f"  VEL Vulnerable:      {cs.get('total_vel_vulnerable', 'N/A')}")
                print(f"  Last Updated:        {cs.get('last_updated', 'N/A')}")
                print(f"  Sources:             {', '.join(cs.get('sources', []))}")
        except:
            pass

    # Module JSON stats
    mod_json_path = Path(__file__).parent / "data" / "modules.json"
    if mod_json_path.exists():
        try:
            with open(mod_json_path, "r") as f:
                mod_data = json.load(f)
            if isinstance(mod_data, dict) and "metadata" in mod_data:
                ms = mod_data["metadata"]
                print(f"\nModule Database (modules.json):")
                print(f"  Total Modules:       {ms.get('total_modules', 'N/A')}")
                print(f"  Core Modules:        {ms.get('total_core', 'N/A')}")
                print(f"  With Known CVEs:     {ms.get('total_with_cves', 'N/A')}")
                print(f"  Last Updated:        {ms.get('last_updated', 'N/A')}")
                print(f"  Sources:             {', '.join(ms.get('sources', []))}")
        except:
            pass


# =========================================================================
# argparse
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="JoomlaScanner - Vulnerability scanner for Joomla CMS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # --- scan ---
    scan_parser = subparsers.add_parser("scan", help="Scan a Joomla website")
    scan_parser.add_argument("target", help="Target URL to scan")
    scan_parser.add_argument(
        "--format", choices=["console", "json", "html"], default="console",
        help="Output format (default: console)",
    )
    scan_parser.add_argument("--output", "-o", help="Output file path")
    scan_parser.add_argument(
        "--timeout", type=int, default=3, help="Request timeout in seconds",
    )
    scan_parser.add_argument(
        "--components-only", action="store_true",
        help="Only enumerate components (skip version detection)",
    )
    scan_parser.add_argument(
        "--version-only", action="store_true",
        help="Only detect Joomla version",
    )
    scan_parser.add_argument(
        "--full", action="store_true",
        help="Full component/module scan (slower but comprehensive)",
    )
    scan_parser.add_argument(
        "--threads", "-t", type=int, default=10,
        help="Number of threads for enumeration (default: 10)",
    )
    scan_parser.set_defaults(func=scan_target)

    # --- update  (CVEs + extensions in one command) ---
    update_parser = subparsers.add_parser(
        "update",
        help="Update databases (CVEs + extensions)",
        description="Update CVE and extension databases. By default updates everything.",
    )
    update_parser.add_argument(
        "--cves", action="store_true",
        help="Only update CVEs",
    )
    update_parser.add_argument(
        "--ext", action="store_true",
        help="Only update extensions (components + modules)",
    )
    update_parser.add_argument(
        "--full", action="store_true",
        help="Full refresh (all CVEs from NVD, all extension sources)",
    )
    update_parser.add_argument(
        "--quick", action="store_true",
        help="Quick extension update (JED Algolia + GitHub core only)",
    )
    update_parser.add_argument(
        "--source", choices=["jed", "github", "nvd", "cve", "vel"],
        help="Update extensions from a specific source only",
    )
    update_parser.add_argument(
        "--year", type=str,
        help="Fetch CVEs for a specific year (e.g. 2024)",
    )
    update_parser.add_argument(
        "--range", type=str,
        help="End year when used with --year (e.g. --year 2018 --range 2024)",
    )
    update_parser.set_defaults(func=run_update)

    # --- stats ---
    stats_parser = subparsers.add_parser("stats", help="Show database statistics")
    stats_parser.set_defaults(func=show_stats)

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()

        print("\n" + "=" * 50)
        print("Examples:")
        print("  python cli.py scan https://example.com")
        print("  python cli.py scan https://example.com --format html -o report.html")
        print("  python cli.py scan https://example.com --full")
        print("  python cli.py update                    # update everything")
        print("  python cli.py update --cves             # CVEs only")
        print("  python cli.py update --ext              # extensions only")
        print("  python cli.py update --ext --quick      # quick extension update")
        print("  python cli.py update --full             # full refresh")
        print("  python cli.py stats")
        print("=" * 50)
        return

    print_banner()

    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
