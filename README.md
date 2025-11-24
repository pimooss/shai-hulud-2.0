# Shai-Hulud Supply Chain Attack Scanner

A security scanner for detecting compromised npm packages affected by the Shai-Hulud supply chain attacks (November 21-23, 2025).

## Overview

This scanner detects:
- **492+ compromised npm packages** across major ecosystems (PostHog, Postman, ENS Domains, Zapier, AsyncAPI, Voiceflow, etc.)
- **Malicious files** installed by the attack (setup_bun.js, bun_environment.js)
- **Indicators of Compromise** (IOC files, malicious workflows, self-hosted runners)

**Important:** This scanner is specifically designed for **npm/JavaScript supply chain attacks**. The Shai-Hulud attack targeted npm packages only. Python packages (including those managed by `uv` or in virtual environments) are **not affected** by this specific attack and are not scanned.

It is available for both **macOS** and **Windows**.

## Attack Details

The Shai-Hulud attack is a self-replicating npm worm that:
- Steals AWS, Azure, GCP credentials
- Harvests GitHub tokens and secrets
- Exfiltrates data to attacker-controlled repositories
- Installs backdoored GitHub self-hosted runners
- Propagates to additional packages

**Impact:** 26,000+ GitHub repositories exposed, 132+ million monthly downloads affected

## Installation

Clone or download the scanner repository.

```bash
git clone https://github.com/your-repo/shai-hulud-scanner.git # Replace with actual repository URL
cd shai-hulud-scanner
```

For macOS, the `shair-hulud-scanner-macos.py` script needs executable permissions:
```bash
chmod +x shair-hulud-scanner-macos.py
```
For Windows, no special permissions are needed for `shai-hulud-scanner-windows.py`.

## Usage

### Basic Scan

**For macOS:**

```bash
# Scan current directory and system
./shair-hulud-scanner-macos.py

# Export results to JSON
./shair-hulud-scanner-macos.py --json results.json

# Quiet mode (minimal output)
./shair-hulud-scanner-macos.py --quiet
```

**For Windows:**

```powershell
# Scan current directory and system
python shai-hulud-scanner-windows.py

# Export results to JSON
python shai-hulud-scanner-windows.py --json results.json

# Quiet mode (minimal output)
python shai-hulud-scanner-windows.py --quiet
```

### What It Scans

1. **package.json files** - Checks all package.json files in current directory and common npm locations
2. **Global npm packages** - Scans globally installed packages
3. **Malicious files** - Searches for known malicious files by SHA1 hash
4. **IOC files** - Looks for data exfiltration files (cloud.json, data.json, secrets.json, truffleSecrets.json, etc.)
5. **GitHub workflows** - Detects malicious workflow files
6. **GitHub runners** - Checks for backdoored self-hosted runners (requires `gh` CLI)
7. **Attacker repositories** - Detects repos created by the attack with "Shai-Hulud: The Second Coming" description (requires `gh` CLI)

## Output Explanation

### Match Indicators

- `🎯 EXACT` / `🎯 CONFIRMED` - Package version exactly matches a known compromised version
- `⚠ POSSIBLE` / `⚠ CHECK VERSION` - Package name matches, but version might be safe (verify manually)

### Color Coding

- **RED** - Critical findings (compromised packages, malicious files)
- **YELLOW** - Warnings (file paths, potential issues)
- **GREEN** - All clear (no threats found)

## Compromised Packages

The scanner detects 492+ packages including:

### Major Affected Ecosystems

- **PostHog** (50+ packages): posthog-node, posthog-js, @posthog/*
- **Postman** (20+ packages): @postman/tunnel-agent, @postman/node-keytar
- **ENS Domains** (70+ packages): @ensdomains/ensjs, @ensdomains/address-encoder
- **Zapier** (10+ packages): zapier-platform-cli, @zapier/ai-actions
- **AsyncAPI** (30+ packages): @asyncapi/studio, @asyncapi/cli
- **Voiceflow** (100+ packages): @voiceflow/* ecosystem
- **BrowserBase** (7+ packages): @browserbasehq/stagehand, jan-browser
- **Others**: typeorm-orbit, ethereum-ens, kill-port, shell-exec

See [shai-hulud-packages.json](shai-hulud-packages.json) for complete list.

## If You Find Compromised Packages

### Immediate Actions

1. **Rotate ALL credentials immediately:**
   - GitHub personal access tokens and SSH keys
   - npm authentication tokens
   - AWS, GCP, Azure credentials
   - CI/CD secrets (GitHub Actions, CircleCI, etc.)

2. **Remove vulnerable packages:**
   ```bash
   # Clear npm cache
   npm cache clean --force

   # Update to patched versions
   npm update <package-name>

   # Or remove if not needed
   npm uninstall <package-name>
   ```

3. **Check for data exfiltration:**
   ```bash
   # Search for malicious repos on GitHub
   # Look for repos with "Shai-Hulud: The Second Coming" in description

   # Check your GitHub audit log
   gh api /user/events
   ```

4. **Remove malicious infrastructure:**
   ```bash
   # Delete suspicious workflows
   rm .github/workflows/discussion.yaml
   rm .github/workflows/formatter_*.yml

   # Remove malicious Bun installation
   rm -rf ~/.bun

   # Remove GitHub self-hosted runners named SHA1HULUD
   gh api repos/:owner/:repo/actions/runners
   ```

5. **Scan for IOC files:**
   ```bash
   find . -name "cloud.json" -o -name "truffleSecrets.json" -o -name "environment.json"
   ```

## Technical Details

### Malicious File Hashes (SHA1)

- `d1829b4708126dcc7bea7437c04d1f10eacd4a16` - setup_bun.js
- `d60ec97eea19fffb4809bc35b91033b52490ca11` - bun_environment.js
- `3d7570d14d34b0ba137d502f042b27b0f37a59fa` - bun_environment.js (variant)

### Attack Vector

The malware executes during the `preinstall` lifecycle phase:
1. Downloads and installs Bun runtime via `setup_bun.js`
2. Executes obfuscated `bun_environment.js` (10MB+ with anti-analysis loops)
3. Harvests credentials from local files and environment variables
4. Exfiltrates data to GitHub repositories
5. Registers backdoored self-hosted runners
6. Attempts to propagate to additional packages

### IOC Files

- `cloud.json` - Cloud credentials (AWS, GCP, Azure)
- `contents.json` - Repository contents
- `environment.json` - Environment variables
- `truffleSecrets.json` - Secrets found by TruffleHog

## References

- [Wiz.io: Shai-Hulud 2.0 Ongoing Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack)
- [Aikido: Shai-Hulud Strikes Again](https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains)
- [StepSecurity: Sha1-Hulud The Second Coming](https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised)

## Prevention

- **Pin dependencies** to specific versions in package.json
- **Disable lifecycle scripts** where possible: `npm install --ignore-scripts`
- **Use lockfiles** (package-lock.json, yarn.lock)
- **Enable MFA** on npm and GitHub accounts
- **Audit dependencies** regularly with tools like npm audit, Snyk, or Socket.dev
- **Monitor for unusual activity** in CI/CD logs

## License

This tool is provided as-is for security research and defensive purposes only.
