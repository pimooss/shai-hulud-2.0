#!/usr/bin/env python3
"""
Shai-Hulud Supply Chain Attack Scanner for Windows
Detects vulnerable npm packages from the November 2024-2025 attacks

Based on research from:
- https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
- https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
- https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised

Note: Some checks require the GitHub CLI ('gh') to be installed and authenticated.
"""

import json
import os
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple
import sys
import datetime
import re

# Malicious file hashes (SHA1)
MALICIOUS_HASHES = {
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16": "setup_bun.js",
    "d60ec97eea19fffb4809bc35b91033b52490ca11": "bun_environment.js",
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa": "bun_environment.js (variant)",
}

# Load compromised packages from JSON file
def load_compromised_packages() -> Dict[str, List[str]]:
    """Load compromised packages database from JSON file"""
    script_dir = Path(__file__).parent
    json_path = script_dir / "shai-hulud-packages.json"

    try:
        with open(json_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: Could not find {json_path}")
        return {}
    except json.JSONDecodeError:
        print(f"Warning: Invalid JSON in {json_path}")
        return {}

COMPROMISED_PACKAGES = load_compromised_packages()

# Indicators of Compromise
IOC_PATHS = [
    "~/.bun/bin/bun.exe",  # Malicious Bun installation
    "~/.bun/bin/bun",
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json",
    "data.json",  # Additional exfiltration files from Wiz advisory
    "secrets.json",
    ".env",  # Commonly targeted by the attack
]

IOC_GITHUB_PATTERNS = [
    ".github/workflows/discussion.yaml",
    ".github/workflows/formatter_",  # Followed by random numbers
]


class Color:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'
    
    @staticmethod
    def initialize():
        """Enable ANSI colors on Windows if possible"""
        if sys.platform == 'win32':
            os.system('') # This is a common trick to enable ANSI support in CMD


def print_banner():
    """Print scanner banner"""
    print(f"{Color.CYAN}{Color.BOLD}")
    print("=" * 70)
    print("    SHAI-HULUD SUPPLY CHAIN ATTACK SCANNER")
    print("    Windows NPM Package Vulnerability Detector")
    print("=" * 70)
    print(f"{Color.END}\n")


def find_package_json_files(start_path: str = os.getcwd()) -> List[Path]:
    """Find all package.json files in the filesystem"""
    package_files = []

    # Common locations for npm packages on Windows
    search_paths = [
        start_path,
    ]

    # Global npm packages location
    appdata = os.getenv('APPDATA')
    if appdata:
        search_paths.append(os.path.join(appdata, 'npm', 'node_modules'))

    # Node.js installation directory (might contain global packages)
    program_files = os.getenv('ProgramFiles')
    if program_files:
        search_paths.append(os.path.join(program_files, 'nodejs', 'node_modules'))
    
    # Also check user's home directory for projects
    search_paths.append(os.path.expanduser("~"))
    
    # Remove non-existent paths and duplicates
    unique_paths = []
    for p in search_paths:
        if p and os.path.exists(p):
            try:
                resolved_p = str(Path(p).resolve())
                if resolved_p not in unique_paths:
                    unique_paths.append(resolved_p)
            except OSError:
                continue # Ignore errors from paths we can't resolve
    
    for search_path in unique_paths:
        for root, dirs, files in os.walk(search_path, topdown=True):
            # Skip .git and other hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            if 'package.json' in files:
                p_path = Path(root) / 'package.json'
                if p_path not in package_files:
                    package_files.append(p_path)

    return package_files


def get_installed_npm_packages() -> Dict[str, str]:
    """Get globally installed npm packages"""
    packages = {}

    try:
        # Use shell=True for Windows compatibility to find npm in PATH
        result = subprocess.run(
            ['npm', 'list', '-g', '--json', '--depth=0'],
            capture_output=True,
            text=True,
            timeout=30,
            shell=True
        )

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            if 'dependencies' in data:
                for pkg, info in data['dependencies'].items():
                    packages[pkg] = info.get('version', 'unknown')
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    return packages


def normalize_version(version_str: str) -> str:
    """Normalize version string by removing semver prefixes"""
    # Remove ^, ~, >=, <=, >, <, =, etc.
    clean_version = re.sub(r'^[~^>=<]+', '', version_str.strip())
    # Take the first part if there's a range
    clean_version = clean_version.split(' ')[0]
    return clean_version


def scan_package_json(package_path: Path) -> List[Tuple[str, str, bool]]:
    """Scan a package.json for vulnerable dependencies

    Returns: List of (package_name, version_range, is_exact_match)
    """
    vulnerable = []

    try:
        with open(package_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        all_deps = {}
        for dep_type in ['dependencies', 'devDependencies', 'optionalDependencies']:
            if dep_type in data and isinstance(data[dep_type], dict):
                all_deps.update(data[dep_type])

        for pkg_name, version_range in all_deps.items():
            if pkg_name in COMPROMISED_PACKAGES:
                vulnerable_versions = COMPROMISED_PACKAGES[pkg_name]
                normalized_version = normalize_version(version_range)

                # Check if the normalized version matches any compromised version
                is_exact_match = normalized_version in vulnerable_versions
                vulnerable.append((pkg_name, version_range, is_exact_match))

    except (json.JSONDecodeError, FileNotFoundError, PermissionError, UnicodeDecodeError):
        pass

    return vulnerable


def calculate_sha1(file_path: Path) -> str:
    """Calculate SHA1 hash of a file"""
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha1.update(chunk)
        return sha1.hexdigest()
    except (FileNotFoundError, PermissionError):
        return ""

def scan_for_malicious_files() -> List[Tuple[Path, str]]:
    """Scan for known malicious files by hash"""
    infected_files = []

    # Search in common npm installation directories on Windows
    search_dirs = [
        os.getcwd(),
        os.path.expanduser("~\node_modules"),
    ]
    
    appdata = os.getenv('APPDATA')
    if appdata:
        search_dirs.append(os.path.join(appdata, 'npm', 'node_modules'))

    program_files = os.getenv('ProgramFiles')
    if program_files:
        search_dirs.append(os.path.join(program_files, 'nodejs', 'node_modules'))

    # Remove non-existent paths and duplicates
    unique_paths = []
    for p in search_dirs:
        if p and os.path.exists(p):
            try:
                resolved_p = str(Path(p).resolve())
                if resolved_p not in unique_paths:
                    unique_paths.append(resolved_p)
            except OSError:
                continue

    for search_dir in unique_paths:
        for root, dirs, files in os.walk(search_dir, topdown=True):
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if file in ['setup_bun.js', 'bun_environment.js']:
                    file_path = Path(root) / file
                    file_hash = calculate_sha1(file_path)

                    if file_hash in MALICIOUS_HASHES:
                        infected_files.append((file_path, MALICIOUS_HASHES[file_hash]))

    return infected_files

def check_ioc_files() -> List[Path]:
    """Check for Indicator of Compromise files"""
    found_iocs = []

    # Check in current directory and home directory
    search_locations = [Path.cwd(), Path.home()]
    
    for loc in search_locations:
        for ioc_path in IOC_PATHS:
            # Expand ~ if present
            if ioc_path.startswith('~'):
                 expanded_path = Path(os.path.expanduser(ioc_path))
            else:
                 expanded_path = loc / ioc_path
            
            if expanded_path.exists() and expanded_path not in found_iocs:
                found_iocs.append(expanded_path)

    return found_iocs

def check_github_workflows() -> List[Path]:
    """Check for malicious GitHub workflow files"""
    suspicious_workflows = []

    workflows_dir = Path(".github/workflows")
    if workflows_dir.exists() and workflows_dir.is_dir():
        for extension in ["*.yaml", "*.yml"]:
            for workflow_file in workflows_dir.glob(extension):
                if workflow_file.name == "discussion.yaml" or workflow_file.name.startswith("formatter_"):
                    suspicious_workflows.append(workflow_file)

    return suspicious_workflows

def check_github_runners():
    """Check for malicious GitHub self-hosted runners"""
    try:
        result = subprocess.run(
            ['gh', 'api', 'repos/:owner/:repo/actions/runners'],
            capture_output=True,
            text=True,
            timeout=10,
            shell=True
        )

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            for runner in data.get('runners', []):
                if 'SHA1HULUD' in runner.get('name', '').upper():
                    return [runner['name']]
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        # gh not found or other error
        pass

    return []

def check_attacker_repositories():
    """Check for repositories created by the attacker under user's account"""
    malicious_repos = []

    try:
        # Get user's repositories
        result = subprocess.run(
            ['gh', 'repo', 'list', '--json', 'name,description,createdAt', '--limit', '1000'],
            capture_output=True,
            text=True,
            timeout=30,
            shell=True
        )

        if result.returncode == 0 and result.stdout:
            repos = json.loads(result.stdout)
            for repo in repos:
                desc = repo.get('description', '') or ''
                if 'SHAI-HULUD' in desc.upper() or 'SHA1-HULUD' in desc.upper():
                    malicious_repos.append({
                        'name': repo.get('name'),
                        'description': desc,
                        'created': repo.get('createdAt')
                    })
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired):
        # gh not found or other error
        pass

    return malicious_repos

def export_results_json(results: Dict, output_file: str = "scan-results.json"):
    """Export scan results to JSON file"""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n{Color.GREEN}Results exported to: {output_file}{Color.END}")
    except Exception as e:
        print(f"\n{Color.RED}Failed to export results: {e}{Color.END}")

def main():
    """Main scanner function"""
    import argparse

    parser = argparse.ArgumentParser(description='Shai-Hulud Supply Chain Attack Scanner for Windows')
    parser.add_argument('--json', metavar='FILE', help='Export results to JSON file')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    args = parser.parse_args()
    
    Color.initialize()

    if not args.quiet:
        print_banner()

    # Results dictionary for JSON export
    results = {
        "scan_directory": str(Path.cwd()),
        "scan_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "vulnerable_packages": {},
        "global_vulnerabilities": [],
        "infected_files": [],
        "ioc_files": [],
        "suspicious_workflows": [],
        "malicious_runners": [],
        "attacker_repositories": [],
    }

    print(f"{Color.BOLD}[1/7] Scanning for vulnerable packages in package.json files...{Color.END}")
    vulnerable_packages = {}
    package_files = find_package_json_files()

    for pkg_file in package_files:
        vulns = scan_package_json(pkg_file)
        if vulns:
            vulnerable_packages[pkg_file] = vulns
            results["vulnerable_packages"][str(pkg_file)] = [
                {"package": pkg, "version": ver, "exact_match": match}
                for pkg, ver, match in vulns
            ]

    if vulnerable_packages:
        total_vulns = sum(len(vulns) for vulns in vulnerable_packages.values())
        print(f"{Color.RED}⚠ Found {total_vulns} vulnerable dependencies in {len(vulnerable_packages)} package.json files:{Color.END}")
        for pkg_file, vulns in vulnerable_packages.items():
            print(f"\n  {Color.YELLOW}{pkg_file}{Color.END}")
            for pkg_name, version, is_exact_match in vulns:
                match_indicator = "🎯 EXACT" if is_exact_match else "⚠ POSSIBLE"
                print(f"    {match_indicator} - {Color.RED}{pkg_name}@{version}{Color.END}")
    else:
        print(f"{Color.GREEN}✓ No vulnerable packages found in package.json files{Color.END}")

    print(f"\n{Color.BOLD}[2/7] Checking globally installed npm packages...{Color.END}")
    global_packages = get_installed_npm_packages()
    global_vulns = []

    for pkg_name, version in global_packages.items():
        if pkg_name in COMPROMISED_PACKAGES:
            vulnerable_versions = COMPROMISED_PACKAGES[pkg_name]
            normalized_version = normalize_version(version)
            is_exact_match = normalized_version in vulnerable_versions
            
            # Report if the package name matches, regardless of version, but flag if it's an exact version match
            global_vulns.append((pkg_name, version, is_exact_match))
            results["global_vulnerabilities"].append({
                "package": pkg_name,
                "version": version,
                "exact_match": is_exact_match
            })

    if global_vulns:
        print(f"{Color.RED}⚠ Found {len(global_vulns)} potentially vulnerable global packages:{Color.END}")
        for pkg_name, version, is_exact_match in global_vulns:
            match_indicator = "🎯 CONFIRMED" if is_exact_match else "⚠ CHECK VERSION"
            print(f"  {match_indicator} - {Color.RED}{pkg_name}@{version}{Color.END}")
    else:
        print(f"{Color.GREEN}✓ No vulnerable global packages found{Color.END}")

    print(f"\n{Color.BOLD}[3/7] Scanning for malicious files by hash...{Color.END}")
    infected_files = scan_for_malicious_files()
    results["infected_files"] = [{"path": str(p), "description": d} for p, d in infected_files]

    if infected_files:
        print(f"{Color.RED}🚨 CRITICAL: Found {len(infected_files)} infected files:{Color.END}")
        for file_path, description in infected_files:
            print(f"  - {Color.RED}{file_path}{Color.END} ({description})")
    else:
        print(f"{Color.GREEN}✓ No malicious files detected{Color.END}")

    print(f"\n{Color.BOLD}[4/7] Checking for Indicators of Compromise (IOC files)...{Color.END}")
    ioc_files = check_ioc_files()
    results["ioc_files"] = [str(f) for f in ioc_files]

    if ioc_files:
        print(f"{Color.RED}⚠ Found {len(ioc_files)} IOC files:{Color.END}")
        for ioc_file in ioc_files:
            print(f"  - {Color.RED}{ioc_file}{Color.END}")
    else:
        print(f"{Color.GREEN}✓ No IOC files detected{Color.END}")

    print(f"\n{Color.BOLD}[5/7] Checking for malicious GitHub workflows...{Color.END}")
    suspicious_workflows = check_github_workflows()
    results["suspicious_workflows"] = [str(w) for w in suspicious_workflows]

    if suspicious_workflows:
        print(f"{Color.RED}⚠ Found {len(suspicious_workflows)} suspicious workflow files:{Color.END}")
        for workflow in suspicious_workflows:
            print(f"  - {Color.RED}{workflow}{Color.END}")
    else:
        print(f"{Color.GREEN}✓ No suspicious workflows detected{Color.END}")

    print(f"\n{Color.BOLD}[6/7] Checking for malicious GitHub runners... (requires 'gh' CLI){Color.END}")
    malicious_runners = check_github_runners()
    results["malicious_runners"] = malicious_runners

    if malicious_runners:
        print(f"{Color.RED}🚨 CRITICAL: Found malicious GitHub runners:{Color.END}")
        for runner in malicious_runners:
            print(f"  - {Color.RED}{runner}{Color.END}")
    else:
        print(f"{Color.GREEN}✓ No malicious runners detected{Color.END}")

    print(f"\n{Color.BOLD}[7/7] Checking for attacker-created repositories... (requires 'gh' CLI){Color.END}")
    attacker_repos = check_attacker_repositories()
    results["attacker_repositories"] = attacker_repos

    if attacker_repos:
        print(f"{Color.RED}🚨 CRITICAL: Found {len(attacker_repos)} attacker-created repositories:{Color.END}")
        for repo in attacker_repos:
            print(f"  - {Color.RED}{repo['name']}{Color.END}")
            print(f"    Description: {repo.get('description', 'N/A')}")
            print(f"    Created: {repo.get('created', 'N/A')}")
    else:
        print(f"{Color.GREEN}✓ No attacker repositories detected{Color.END}")

    # Summary
    print(f"\n{Color.BOLD}{Color.CYAN}{'=' * 70}{Color.END}")
    print(f"{Color.BOLD}SCAN SUMMARY{Color.END}")
    print(f"{Color.CYAN}{'=' * 70}{Color.END}\n")

    total_issues = len(vulnerable_packages) + len(global_vulns) + len(infected_files) + len(ioc_files) + len(suspicious_workflows) + len(malicious_runners) + len(attacker_repos)

    if total_issues == 0:
        print(f"{Color.GREEN}{Color.BOLD}✓ No Shai-Hulud indicators found on this system{Color.END}")
    else:
        print(f"{Color.RED}{Color.BOLD}⚠ ATTENTION: {total_issues} potential indicators detected!{Color.END}\n")

        print(f"{Color.BOLD}RECOMMENDED ACTIONS:{Color.END}")
        print("1. Rotate ALL credentials immediately:")
        print("   - GitHub tokens and SSH keys")
        print("   - npm authentication tokens")
        print("   - AWS, GCP, Azure credentials")
        print("   - CI/CD secrets")
        print("\n2. Remove vulnerable packages:")
        print("   - Update to patched versions")
        print("   - Clear npm cache: npm cache clean --force")
        print("\n3. Check for data exfiltration:")
        print("   - Search GitHub for repos with 'Shai-Hulud' in description")
        print("   - Review recent GitHub API activity")
        print("\n4. Remove malicious infrastructure:")
        print("   - Delete suspicious GitHub workflows")
        print("   - Remove self-hosted runners named 'SHA1HULUD'")
        print("   - Delete ~/.bun directory if present")

    print(f"\n{Color.CYAN}{'=' * 70}{Color.END}\n")

    # Export results if requested
    results["total_issues"] = total_issues
    if args.json:
        export_results_json(results, args.json)

    sys.exit(0 if total_issues == 0 else 1)


if __name__ == "__main__":
    main()
