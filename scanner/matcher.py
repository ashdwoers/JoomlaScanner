import re
from packaging import version
from scanner.db import Database


class CVEMatcher:
    def __init__(self, db=None):
        self.db = db or Database()
        # Build a lookup cache of all component_name values in the CVE DB
        # mapped by their normalized form (lowercase, no underscores after prefix)
        self._name_cache = self._build_name_cache()

    def _build_name_cache(self):
        """Build a mapping from normalized names to actual DB component_names."""
        cache = {}
        rows = self.db.fetch_all(
            "SELECT DISTINCT component_name FROM joomla_component_cves"
        )
        for (name,) in rows:
            # Store exact name
            cache.setdefault(name, set()).add(name)
            # Store normalized form: strip all underscores after prefix
            normalized = self._normalize_name(name)
            cache.setdefault(normalized, set()).add(name)
        return cache

    @staticmethod
    def _normalize_name(name):
        """Normalize a component/module name for fuzzy matching.
        e.g. 'mod_vvisit_counter' -> 'mod_vvisitcounter'
             'mod_vvisitcounter'  -> 'mod_vvisitcounter'
        """
        if not name:
            return name
        # Separate the prefix (com_ or mod_) from the rest
        for prefix in ("com_", "mod_"):
            if name.startswith(prefix):
                rest = name[len(prefix):]
                # Remove all underscores from the rest for normalization
                return prefix + rest.replace("_", "")
        return name.replace("_", "")

    def _lookup_cves(self, name):
        """Look up CVEs for a name, trying exact match first, then normalized."""
        # Try exact match first
        cves = self.db.get_component_cves(name)
        if cves:
            return cves

        # Try normalized lookup via cache
        normalized = self._normalize_name(name)
        db_names = self._name_cache.get(normalized, set())
        for db_name in db_names:
            if db_name != name:
                cves = self.db.get_component_cves(db_name)
                if cves:
                    return cves

        return []

    def match_joomla_cves(self, joomla_version, verbose=True):
        if not joomla_version:
            return []

        if verbose:
            print(f"[*] Matching CVEs for Joomla {joomla_version}...")

        all_cves = self.db.get_core_cves()

        vulnerable_cves = []
        seen_cve_ids = set()

        for cve in all_cves:
            (
                cve_id, description, cvss_score, cvss_severity,
                published, fixed_version, references,
                version_start, version_end, version_end_type,
            ) = cve

            # Skip duplicates (a CVE can have multiple version ranges)
            if cve_id in seen_cve_ids:
                continue

            if self._is_version_affected(
                joomla_version, version_start, version_end,
                version_end_type, fixed_version
            ):
                seen_cve_ids.add(cve_id)
                vulnerable_cves.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "published_date": published,
                    "fixed_version": fixed_version or version_end,
                    "references": references,
                    "target": "joomla_core",
                    "version_start": version_start,
                    "version_end": version_end,
                    "version_end_type": version_end_type,
                })

        if verbose:
            print(f"[+] Found {len(vulnerable_cves)} core vulnerabilities")

        return vulnerable_cves

    def match_component_cves(self, components, verbose=True):
        all_vulnerable = []

        if verbose:
            print(f"[*] Matching CVEs for {len(components)} components...")

        for comp in components:
            comp_name = comp.get("name")
            comp_version = comp.get("version")
            is_core = comp.get("is_core", False)

            # Skip core components (matched separately)
            if is_core:
                continue

            cves = self._lookup_cves(comp_name)

            if not cves:
                continue

            vulnerable_cves = []
            seen_cve_ids = set()

            for cve in cves:
                (
                    cve_id, description, cvss_score, cvss_severity,
                    published, fixed_version, references,
                    version_start, version_end, version_end_type,
                ) = cve

                if cve_id in seen_cve_ids:
                    continue

                # CVE has no version range data at all — report as potential
                has_no_range = not version_start and not version_end and not fixed_version

                # If component version is unknown, still report CVEs that exist
                if not comp_version or comp_version == "unknown":
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": fixed_version or version_end,
                        "references": references,
                        "match_type": "potential",
                        "note": "Version unknown - verify manually",
                    })
                    continue

                # CVE exists but NVD has no version range — can't confirm, report as potential
                if has_no_range:
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": None,
                        "references": references,
                        "match_type": "potential",
                        "note": "No version range in NVD - verify manually",
                    })
                    continue

                if self._is_version_affected(
                    comp_version, version_start, version_end,
                    version_end_type, fixed_version
                ):
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": fixed_version or version_end,
                        "references": references,
                        "match_type": "confirmed",
                        "version_start": version_start,
                        "version_end": version_end,
                        "version_end_type": version_end_type,
                    })

            if vulnerable_cves:
                comp["is_vulnerable"] = True
                comp["cves"] = vulnerable_cves
                all_vulnerable.append(comp)

                if verbose:
                    confirmed = sum(
                        1 for v in vulnerable_cves
                        if v.get("match_type") == "confirmed"
                    )
                    potential = sum(
                        1 for v in vulnerable_cves
                        if v.get("match_type") == "potential"
                    )
                    parts = []
                    if confirmed:
                        parts.append(f"{confirmed} confirmed")
                    if potential:
                        parts.append(f"{potential} potential")
                    print(
                        f"    [!] {comp_name} ({comp_version}): "
                        f"{', '.join(parts)} CVEs"
                    )

        if verbose:
            print(f"[+] Found {len(all_vulnerable)} vulnerable components")

        return all_vulnerable

    def match_module_cves(self, modules, verbose=True):
        if not modules:
            return []

        if verbose:
            print(f"[*] Matching CVEs for {len(modules)} modules...")

        vulnerable_modules = []

        for mod in modules:
            mod_name = mod.get("name")
            mod_version = mod.get("version")

            if not mod_name:
                continue

            cves = self._lookup_cves(mod_name)
            if not cves:
                continue

            vulnerable_cves = []
            seen_cve_ids = set()

            for cve in cves:
                (
                    cve_id, description, cvss_score, cvss_severity,
                    published, fixed_version, references,
                    version_start, version_end, version_end_type,
                ) = cve

                if cve_id in seen_cve_ids:
                    continue

                # CVE has no version range data at all — report as potential
                has_no_range = not version_start and not version_end and not fixed_version

                if not mod_version or mod_version == "unknown":
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": fixed_version or version_end,
                        "references": references,
                        "match_type": "potential",
                        "note": "Version unknown - verify manually",
                    })
                    continue

                # CVE exists but NVD has no version range — can't confirm, report as potential
                if has_no_range:
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": None,
                        "references": references,
                        "match_type": "potential",
                        "note": "No version range in NVD - verify manually",
                    })
                    continue

                if self._is_version_affected(
                    mod_version, version_start, version_end,
                    version_end_type, fixed_version
                ):
                    seen_cve_ids.add(cve_id)
                    vulnerable_cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "cvss_score": cvss_score,
                        "cvss_severity": cvss_severity,
                        "published_date": published,
                        "fixed_version": fixed_version or version_end,
                        "references": references,
                        "match_type": "confirmed",
                    })

            if vulnerable_cves:
                mod["is_vulnerable"] = True
                mod["cves"] = vulnerable_cves
                vulnerable_modules.append(mod)

        if verbose:
            print(f"[+] Found {len(vulnerable_modules)} vulnerable modules")

        return vulnerable_modules

    def _is_version_affected(self, detected_version, version_start,
                              version_end, version_end_type, fixed_version):
        """
        Check if a detected version falls within the vulnerable range.

        Matching logic:
          1. If version_start AND version_end are set (proper range from CPE):
             - detected >= version_start AND
             - detected < version_end (if excluding) OR detected <= version_end (if including)

          2. If only version_end is set (no start):
             - detected <= version_end (if including) OR detected < version_end (if excluding)

          3. If only fixed_version is set (legacy/fallback):
             - detected < fixed_version

          4. If nothing is set, no match.
        """
        detected = self._parse_version(detected_version)
        if not detected:
            return False

        # Case 1 & 2: Version range from CPE
        if version_end:
            v_end = self._parse_version(version_end)
            if not v_end:
                return False

            # Check end bound
            if version_end_type == "excluding":
                end_ok = detected < v_end
            elif version_end_type == "including":
                end_ok = detected <= v_end
            else:
                end_ok = detected < v_end  # default to excluding

            if not end_ok:
                return False

            # Check start bound (if present)
            if version_start:
                v_start = self._parse_version(version_start)
                if v_start and detected < v_start:
                    return False

            return True

        # Case 3: Legacy fixed_version only
        if fixed_version:
            fixed = self._parse_version(fixed_version)
            if fixed:
                return detected < fixed

        return False

    def _parse_version(self, ver):
        """Parse a version string into a comparable Version object."""
        if not ver:
            return None

        # Extract version-like pattern
        match = re.search(r"(\d+(?:\.\d+)*)", str(ver))
        if match:
            try:
                return version.parse(match.group(1))
            except Exception:
                pass

        return None

    def get_vulnerability_summary(self, vulnerabilities):
        summary = {
            "total": len(vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "confirmed": 0,
            "potential": 0,
        }

        for vuln in vulnerabilities:
            severity = (vuln.get("cvss_severity") or "").lower()
            score = vuln.get("cvss_score") or 0
            match_type = vuln.get("match_type", "confirmed")

            if match_type == "confirmed":
                summary["confirmed"] += 1
            else:
                summary["potential"] += 1

            if score >= 9.0 or severity == "critical":
                summary["critical"] += 1
            elif score >= 7.0 or severity == "high":
                summary["high"] += 1
            elif score >= 4.0 or severity == "medium":
                summary["medium"] += 1
            elif score > 0 or severity == "low":
                summary["low"] += 1

        return summary


def match_vulnerabilities(joomla_version, components, verbose=True):
    matcher = CVEMatcher()

    results = {"joomla_core": [], "components": []}

    if joomla_version:
        results["joomla_core"] = matcher.match_joomla_cves(
            joomla_version, verbose=verbose
        )

    if components:
        results["components"] = matcher.match_component_cves(
            components, verbose=verbose
        )

    all_vulns = results["joomla_core"] + [
        {**v, "component": v["name"]} for v in results["components"]
    ]
    results["summary"] = matcher.get_vulnerability_summary(all_vulns)

    return results


if __name__ == "__main__":
    db = Database()
    matcher = CVEMatcher(db)

    print("Testing CVE matching...")
    vulns = matcher.match_joomla_cves("3.9.0", verbose=True)
    print(f"\nFound {len(vulns)} vulnerabilities for Joomla 3.9.0")
    for v in vulns[:5]:
        print(f"  {v['cve_id']}: CVSS {v['cvss_score']} {v['cvss_severity']}")
        print(f"    range: {v.get('version_start')} - {v.get('version_end')} ({v.get('version_end_type')})")
