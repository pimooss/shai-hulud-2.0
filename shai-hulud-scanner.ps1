<#
.SYNOPSIS
    Shai-Hulud Supply Chain Attack Scanner for Windows

.DESCRIPTION
    Detects vulnerable npm packages from the November 2024-2025 attacks

    Based on research from:
    - https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
    - https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
    - https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised

.PARAMETER Json
    Export results to JSON file

.PARAMETER Quiet
    Minimal output mode

.EXAMPLE
    .\shai-hulud-scanner.ps1

.EXAMPLE
    .\shai-hulud-scanner.ps1 -Json results.json
#>

[CmdletBinding()]
param(
    [string]$Json,
    [switch]$Quiet
)

# Malicious file hashes (SHA1)
$MALICIOUS_HASHES = @{
    "d1829b4708126dcc7bea7437c04d1f10eacd4a16" = "setup_bun.js"
    "d60ec97eea19fffb4809bc35b91033b52490ca11" = "bun_environment.js"
    "3d7570d14d34b0ba137d502f042b27b0f37a59fa" = "bun_environment.js (variant)"
}

# IOC file paths
$IOC_PATHS = @(
    "~/.bun/bin/bun.exe"
    "cloud.json"
    "contents.json"
    "environment.json"
    "truffleSecrets.json"
    "data.json"
    "secrets.json"
    ".env"
)

# Load compromised packages database
function Load-CompromisedPackages {
    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    if (-not $scriptDir) { $scriptDir = $PSScriptRoot }
    $jsonPath = Join-Path $scriptDir "shai-hulud-packages.json"

    if (Test-Path $jsonPath) {
        try {
            return Get-Content $jsonPath -Raw | ConvertFrom-Json -AsHashtable
        }
        catch {
            Write-Warning "Could not parse $jsonPath"
            return @{}
        }
    }
    else {
        Write-Warning "Could not find $jsonPath"
        return @{}
    }
}

$COMPROMISED_PACKAGES = Load-CompromisedPackages

# Color output functions
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Success { param([string]$Message) Write-ColorOutput "✓ $Message" "Green" }
function Write-Warning2 { param([string]$Message) Write-ColorOutput "⚠ $Message" "Yellow" }
function Write-Critical { param([string]$Message) Write-ColorOutput "🚨 $Message" "Red" }
function Write-Info { param([string]$Message) Write-ColorOutput $Message "Cyan" }

function Show-Banner {
    if (-not $Quiet) {
        Write-Info ""
        Write-Info ("=" * 70)
        Write-Info "    SHAI-HULUD SUPPLY CHAIN ATTACK SCANNER"
        Write-Info "    Windows NPM Package Vulnerability Detector"
        Write-Info ("=" * 70)
        Write-Info ""
    }
}

function Find-PackageJsonFiles {
    param([string]$StartPath = (Get-Location).Path)

    $packageFiles = @()

    # Common npm locations on Windows
    $searchPaths = @(
        $StartPath,
        "$env:APPDATA\npm",
        "$env:ProgramFiles\nodejs\node_modules",
        "$env:ProgramFiles(x86)\nodejs\node_modules"
    )

    foreach ($searchPath in $searchPaths) {
        if (Test-Path $searchPath) {
            $packageFiles += Get-ChildItem -Path $searchPath -Filter "package.json" -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '[\\/]\.' } |
                Select-Object -ExpandProperty FullName
        }
    }

    return $packageFiles
}

function Get-InstalledNpmPackages {
    $packages = @{}

    try {
        $output = npm list -g --json --depth=0 2>$null | ConvertFrom-Json

        if ($output.dependencies) {
            foreach ($pkg in $output.dependencies.PSObject.Properties) {
                $packages[$pkg.Name] = $pkg.Value.version
            }
        }
    }
    catch {
        # npm not available or error occurred
    }

    return $packages
}

function Get-NormalizedVersion {
    param([string]$Version)

    # Remove semver prefixes (^, ~, >=, etc.)
    $normalized = $Version -replace '^[~^>=<]+', ''
    $normalized = $normalized.Split(' ')[0]

    return $normalized
}

function Test-PackageJson {
    param([string]$Path)

    $vulnerable = @()

    try {
        $data = Get-Content $Path -Raw | ConvertFrom-Json

        $allDeps = @{}

        foreach ($depType in @('dependencies', 'devDependencies', 'optionalDependencies')) {
            if ($data.$depType) {
                foreach ($dep in $data.$depType.PSObject.Properties) {
                    $allDeps[$dep.Name] = $dep.Value
                }
            }
        }

        foreach ($pkg in $allDeps.GetEnumerator()) {
            if ($COMPROMISED_PACKAGES.ContainsKey($pkg.Key)) {
                $vulnerableVersions = $COMPROMISED_PACKAGES[$pkg.Key]
                $normalizedVersion = Get-NormalizedVersion -Version $pkg.Value

                $isExactMatch = $vulnerableVersions -contains $normalizedVersion

                $vulnerable += @{
                    Package = $pkg.Key
                    Version = $pkg.Value
                    ExactMatch = $isExactMatch
                }
            }
        }
    }
    catch {
        # Skip files that can't be parsed
    }

    return $vulnerable
}

function Get-FileSha1 {
    param([string]$Path)

    try {
        $hash = Get-FileHash -Path $Path -Algorithm SHA1
        return $hash.Hash.ToLower()
    }
    catch {
        return ""
    }
}

function Find-MaliciousFiles {
    $infectedFiles = @()

    # Search in common npm directories
    $searchDirs = @(
        "$env:APPDATA\npm",
        "$env:USERPROFILE\node_modules",
        "$env:ProgramFiles\nodejs\node_modules",
        (Get-Location).Path
    )

    foreach ($searchDir in $searchDirs) {
        if (Test-Path $searchDir) {
            $files = Get-ChildItem -Path $searchDir -Include @("setup_bun.js", "bun_environment.js") -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '[\\/]\.' }

            foreach ($file in $files) {
                $hash = Get-FileSha1 -Path $file.FullName

                if ($MALICIOUS_HASHES.ContainsKey($hash)) {
                    $infectedFiles += @{
                        Path = $file.FullName
                        Description = $MALICIOUS_HASHES[$hash]
                    }
                }
            }
        }
    }

    return $infectedFiles
}

function Find-IocFiles {
    $foundIocs = @()

    foreach ($iocPath in $IOC_PATHS) {
        $expandedPath = $ExecutionContext.InvokeCommand.ExpandString($iocPath)

        if (Test-Path $expandedPath) {
            $foundIocs += $expandedPath
        }

        # Check in current directory
        if (Test-Path $iocPath) {
            $foundIocs += (Resolve-Path $iocPath).Path
        }
    }

    return $foundIocs
}

function Find-SuspiciousWorkflows {
    $suspicious = @()
    $workflowsDir = ".github\workflows"

    if (Test-Path $workflowsDir) {
        $workflows = Get-ChildItem -Path $workflowsDir -Include @("*.yaml", "*.yml") -ErrorAction SilentlyContinue

        foreach ($workflow in $workflows) {
            if ($workflow.Name -eq "discussion.yaml" -or
                $workflow.Name -eq "discussion.yml" -or
                $workflow.Name -like "formatter_*") {
                $suspicious += $workflow.FullName
            }
        }
    }

    return $suspicious
}

function Find-MaliciousRunners {
    $malicious = @()

    try {
        $output = gh api repos/:owner/:repo/actions/runners 2>$null | ConvertFrom-Json

        foreach ($runner in $output.runners) {
            if ($runner.name -match "SHA1HULUD") {
                $malicious += $runner.name
            }
        }
    }
    catch {
        # gh CLI not available or not in a repo context
    }

    return $malicious
}

function Find-AttackerRepositories {
    $malicious = @()

    try {
        $repos = gh repo list --json name,description,createdAt --limit 1000 2>$null | ConvertFrom-Json

        foreach ($repo in $repos) {
            if ($repo.description -match "SHAI-HULUD|SHA1-HULUD") {
                $malicious += @{
                    Name = $repo.name
                    Description = $repo.description
                    Created = $repo.createdAt
                }
            }
        }
    }
    catch {
        # gh CLI not available
    }

    return $malicious
}

# Main execution
Show-Banner

# Results object
$results = @{
    scan_timestamp = (Get-Location).Path
    scan_date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    vulnerable_packages = @{}
    global_vulnerabilities = @()
    infected_files = @()
    ioc_files = @()
    suspicious_workflows = @()
    malicious_runners = @()
    attacker_repositories = @()
}

# 1. Scan package.json files
Write-Host "`n[1/7] Scanning for vulnerable packages in package.json files..." -ForegroundColor Cyan -NoNewline
Write-Host ""

$vulnerablePackages = @{}
$packageFiles = Find-PackageJsonFiles

foreach ($pkgFile in $packageFiles) {
    $vulns = Test-PackageJson -Path $pkgFile

    if ($vulns.Count -gt 0) {
        $vulnerablePackages[$pkgFile] = $vulns
        $results.vulnerable_packages[$pkgFile] = $vulns
    }
}

if ($vulnerablePackages.Count -gt 0) {
    $totalVulns = ($vulnerablePackages.Values | Measure-Object -Sum Count).Sum
    Write-Warning2 "Found $totalVulns vulnerable dependencies in $($vulnerablePackages.Count) package.json files:"

    foreach ($pkg in $vulnerablePackages.GetEnumerator()) {
        Write-Host "`n  $($pkg.Key)" -ForegroundColor Yellow
        foreach ($vuln in $pkg.Value) {
            $indicator = if ($vuln.ExactMatch) { "🎯 EXACT" } else { "⚠ POSSIBLE" }
            Write-Host "    $indicator - $($vuln.Package)@$($vuln.Version)" -ForegroundColor Red
        }
    }
}
else {
    Write-Success "No vulnerable packages found in package.json files"
}

# 2. Check global packages
Write-Host "`n[2/7] Checking globally installed npm packages..." -ForegroundColor Cyan
$globalPackages = Get-InstalledNpmPackages
$globalVulns = @()

foreach ($pkg in $globalPackages.GetEnumerator()) {
    if ($COMPROMISED_PACKAGES.ContainsKey($pkg.Key)) {
        $vulnerableVersions = $COMPROMISED_PACKAGES[$pkg.Key]
        $normalizedVersion = Get-NormalizedVersion -Version $pkg.Value

        $isExactMatch = $vulnerableVersions -contains $normalizedVersion

        $vuln = @{
            Package = $pkg.Key
            Version = $pkg.Value
            ExactMatch = $isExactMatch
        }

        $globalVulns += $vuln
        $results.global_vulnerabilities += $vuln
    }
}

if ($globalVulns.Count -gt 0) {
    Write-Warning2 "Found $($globalVulns.Count) potentially vulnerable global packages:"
    foreach ($vuln in $globalVulns) {
        $indicator = if ($vuln.ExactMatch) { "🎯 CONFIRMED" } else { "⚠ CHECK VERSION" }
        Write-Host "  $indicator - $($vuln.Package)@$($vuln.Version)" -ForegroundColor Red
    }
}
else {
    Write-Success "No vulnerable global packages found"
}

# 3. Scan for malicious files
Write-Host "`n[3/7] Scanning for malicious files by hash..." -ForegroundColor Cyan
$infectedFiles = Find-MaliciousFiles
$results.infected_files = $infectedFiles

if ($infectedFiles.Count -gt 0) {
    Write-Critical "Found $($infectedFiles.Count) infected files:"
    foreach ($file in $infectedFiles) {
        Write-Host "  - $($file.Path)" -ForegroundColor Red -NoNewline
        Write-Host " ($($file.Description))"
    }
}
else {
    Write-Success "No malicious files detected"
}

# 4. Check IOC files
Write-Host "`n[4/7] Checking for Indicators of Compromise (IOC files)..." -ForegroundColor Cyan
$iocFiles = Find-IocFiles
$results.ioc_files = $iocFiles

if ($iocFiles.Count -gt 0) {
    Write-Warning2 "Found $($iocFiles.Count) IOC files:"
    foreach ($file in $iocFiles) {
        Write-Host "  - $file" -ForegroundColor Red
    }
}
else {
    Write-Success "No IOC files detected"
}

# 5. Check workflows
Write-Host "`n[5/7] Checking for malicious GitHub workflows..." -ForegroundColor Cyan
$suspiciousWorkflows = Find-SuspiciousWorkflows
$results.suspicious_workflows = $suspiciousWorkflows

if ($suspiciousWorkflows.Count -gt 0) {
    Write-Warning2 "Found $($suspiciousWorkflows.Count) suspicious workflow files:"
    foreach ($workflow in $suspiciousWorkflows) {
        Write-Host "  - $workflow" -ForegroundColor Red
    }
}
else {
    Write-Success "No suspicious workflows detected"
}

# 6. Check runners
Write-Host "`n[6/7] Checking for malicious GitHub runners..." -ForegroundColor Cyan
$maliciousRunners = Find-MaliciousRunners
$results.malicious_runners = $maliciousRunners

if ($maliciousRunners.Count -gt 0) {
    Write-Critical "Found malicious GitHub runners:"
    foreach ($runner in $maliciousRunners) {
        Write-Host "  - $runner" -ForegroundColor Red
    }
}
else {
    Write-Success "No malicious runners detected"
}

# 7. Check repositories
Write-Host "`n[7/7] Checking for attacker-created repositories..." -ForegroundColor Cyan
$attackerRepos = Find-AttackerRepositories
$results.attacker_repositories = $attackerRepos

if ($attackerRepos.Count -gt 0) {
    Write-Critical "Found $($attackerRepos.Count) attacker-created repositories:"
    foreach ($repo in $attackerRepos) {
        Write-Host "  - $($repo.Name)" -ForegroundColor Red
        Write-Host "    Description: $($repo.Description)"
        Write-Host "    Created: $($repo.Created)"
    }
}
else {
    Write-Success "No attacker repositories detected"
}

# Summary
Write-Info "`n$("=" * 70)"
Write-Info "SCAN SUMMARY"
Write-Info ("=" * 70)

$totalIssues = $vulnerablePackages.Count + $globalVulns.Count + $infectedFiles.Count +
               $iocFiles.Count + $suspiciousWorkflows.Count + $maliciousRunners.Count +
               $attackerRepos.Count

$results.total_issues = $totalIssues

if ($totalIssues -eq 0) {
    Write-Host "`n✓ No Shai-Hulud indicators found on this system" -ForegroundColor Green
}
else {
    Write-Host "`n⚠ ATTENTION: $totalIssues potential indicators detected!`n" -ForegroundColor Red

    Write-Host "RECOMMENDED ACTIONS:" -ForegroundColor White
    Write-Host "1. Rotate ALL credentials immediately:"
    Write-Host "   - GitHub tokens and SSH keys"
    Write-Host "   - npm authentication tokens"
    Write-Host "   - AWS, GCP, Azure credentials"
    Write-Host "   - CI/CD secrets"
    Write-Host "`n2. Remove vulnerable packages:"
    Write-Host "   - Update to patched versions"
    Write-Host "   - Clear npm cache: npm cache clean --force"
    Write-Host "`n3. Check for data exfiltration:"
    Write-Host "   - Search GitHub for repos with 'Shai-Hulud' in description"
    Write-Host "   - Review recent GitHub API activity"
    Write-Host "`n4. Remove malicious infrastructure:"
    Write-Host "   - Delete suspicious GitHub workflows"
    Write-Host "   - Remove self-hosted runners named 'SHA1HULUD'"
    Write-Host "   - Delete ~/.bun directory if present"
}

Write-Info "`n$("=" * 70)`n"

# Export JSON if requested
if ($Json) {
    try {
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $Json -Encoding UTF8
        Write-Success "Results exported to: $Json"
    }
    catch {
        Write-Host "Failed to export results: $_" -ForegroundColor Red
    }
}

# Exit with appropriate code
if ($totalIssues -eq 0) {
    exit 0
}
else {
    exit 1
}
