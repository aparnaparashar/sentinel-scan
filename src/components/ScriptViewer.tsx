import { useState } from "react";
import { Copy, Check, Download } from "lucide-react";

const LIGHT_SCAN_SCRIPT = `# ============================================================
# Netra Light Scan - Windows Vulnerability Assessment
# Version: 1.0 | Author: Netra Team
# Run as: powershell -ExecutionPolicy Bypass -File Netra-Light.ps1
# NO installation required. NO persistence left on system.
# ============================================================

$ErrorActionPreference = "Continue"
$report = @{
    ScanType    = "LightScan"
    Timestamp   = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    HostName    = $env:COMPUTERNAME
    OS          = @{}
    Patches     = @{}
    Firewall    = @{}
    Defender    = @{}
    UAC         = @{}
    Services    = @()
    Users       = @{}
    Findings    = @()
}

Write-Host "[*] Netra Light Scan Starting..." -ForegroundColor Cyan

# === 1. OS VERSION & BUILD ===
Write-Host "[*] Collecting OS information..." -ForegroundColor Yellow
$os = Get-CimInstance Win32_OperatingSystem
$report.OS = @{
    Caption     = $os.Caption
    Version     = $os.Version
    BuildNumber = $os.BuildNumber
    Architecture= $os.OSArchitecture
    LastBoot    = $os.LastBootUpTime
    InstallDate = $os.InstallDate
}

# === 2. PATCH & HOTFIX HISTORY ===
Write-Host "[*] Checking installed patches..." -ForegroundColor Yellow
$hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
$report.Patches = @{
    LastUpdate  = ($hotfixes | Select-Object -First 1).InstalledOn
    Count       = $hotfixes.Count
    Recent      = $hotfixes | ForEach-Object { @{ KB = $_.HotFixID; Date = $_.InstalledOn; Type = $_.Description } }
}

# === 3. FIREWALL STATUS ===
Write-Host "[*] Auditing firewall configuration..." -ForegroundColor Yellow
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $report.Firewall = $fwProfiles | ForEach-Object {
        @{ Profile = $_.Name; Enabled = $_.Enabled; DefaultInbound = $_.DefaultInboundAction; DefaultOutbound = $_.DefaultOutboundAction }
    }
    $disabledProfiles = $fwProfiles | Where-Object { -not $_.Enabled }
    if ($disabledProfiles) {
        $report.Findings += @{ Category = "Firewall"; Severity = "HIGH"; Finding = "Firewall disabled on: $($disabledProfiles.Name -join ', ')"; Recommendation = "Enable Windows Firewall on all network profiles" }
    }
} catch { $report.Firewall = @{ Error = $_.Exception.Message } }

# === 4. WINDOWS DEFENDER STATUS ===
Write-Host "[*] Checking Windows Defender..." -ForegroundColor Yellow
try {
    $defender = Get-MpComputerStatus -ErrorAction Stop
    $report.Defender = @{
        RealTimeEnabled     = $defender.RealTimeProtectionEnabled
        AntivirusEnabled    = $defender.AntivirusEnabled
        SignatureDate       = $defender.AntivirusSignatureLastUpdated
        SignatureAge        = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
    }
    if (-not $defender.RealTimeProtectionEnabled) {
        $report.Findings += @{ Category = "Defender"; Severity = "CRITICAL"; Finding = "Windows Defender real-time protection is DISABLED"; Recommendation = "Enable real-time protection immediately" }
    }
    if (((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days -gt 7) {
        $report.Findings += @{ Category = "Defender"; Severity = "HIGH"; Finding = "Antivirus signatures are more than 7 days old"; Recommendation = "Update antivirus signatures immediately" }
    }
} catch { $report.Defender = @{ Error = "Unable to query Defender status" } }

# === 5. UAC CONFIGURATION ===
Write-Host "[*] Checking UAC settings..." -ForegroundColor Yellow
$uacKey = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
$uacEnabled = (Get-ItemProperty $uacKey -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
$consentBehavior = (Get-ItemProperty $uacKey -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$report.UAC = @{ Enabled = $uacEnabled -eq 1; ConsentLevel = $consentBehavior }
if ($uacEnabled -ne 1) {
    $report.Findings += @{ Category = "UAC"; Severity = "CRITICAL"; Finding = "User Account Control (UAC) is DISABLED"; Recommendation = "Enable UAC to prevent privilege escalation" }
}

# === 6. RISKY SERVICES ===
Write-Host "[*] Auditing running services..." -ForegroundColor Yellow
$riskyServiceNames = @("Telnet","SNMP","FTP","RemoteRegistry","Messenger","Alerter","ClipSrv","SharedAccess","upnphost","SSDPSRV","TlntSvr")
$runningServices = Get-Service | Where-Object { $_.Status -eq "Running" }
$report.Services = $runningServices | Select-Object -First 30 | ForEach-Object { @{ Name = $_.Name; DisplayName = $_.DisplayName; Status = $_.Status } }
foreach ($svc in $runningServices) {
    if ($riskyServiceNames -contains $svc.Name) {
        $report.Findings += @{ Category = "Services"; Severity = "MEDIUM"; Finding = "Potentially risky service running: $($svc.DisplayName)"; Recommendation = "Disable $($svc.Name) if not required" }
    }
}

# === 7. LOCAL ADMIN ACCOUNTS ===
Write-Host "[*] Checking user privileges..." -ForegroundColor Yellow
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    $report.Users = @{ AdminCount = $admins.Count; Admins = $admins | ForEach-Object { @{ Name = $_.Name; PrincipalSource = $_.PrincipalSource } } }
    if ($admins.Count -gt 3) {
        $report.Findings += @{ Category = "Users"; Severity = "MEDIUM"; Finding = "$($admins.Count) accounts in local Administrators group"; Recommendation = "Review and reduce admin accounts to minimum required" }
    }
} catch { $report.Users = @{ Error = $_.Exception.Message } }

# === OUTPUT REPORT ===
Write-Host "[+] Scan complete. Findings: $($report.Findings.Count)" -ForegroundColor Green
$json = $report | ConvertTo-Json -Depth 10
$outputPath = Join-Path $env:TEMP "Netra-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$json | Out-File -FilePath $outputPath -Encoding UTF8
$json | Out-File -FilePath $outputPath -Encoding UTF8
Write-Host "[+] Report saved: $outputPath" -ForegroundColor Cyan
Write-Host "[+] Upload this file to Netra portal for CVE analysis." -ForegroundColor Green
$json`;

const DEEP_SCAN_SCRIPT = `# ============================================================
# Netra Deep Scan - Remote Windows Vulnerability Assessment
# Requires: Admin credentials + WinRM enabled on target
# Usage: .\Netra-Deep.ps1 -TargetIP 192.168.1.100 -Credential (Get-Credential)
# ============================================================

param(
    [Parameter(Mandatory=$true)][string]$TargetIP,
    [Parameter(Mandatory=$true)][System.Management.Automation.PSCredential]$Credential
)

Write-Host "[*] Netra Deep Scan starting on $TargetIP ..." -ForegroundColor Cyan

# Test WinRM connectivity
if (-not (Test-WSMan -ComputerName $TargetIP -Credential $Credential -Authentication Negotiate -ErrorAction SilentlyContinue)) {
    Write-Error "WinRM not reachable on $TargetIP. Ensure WinRM is enabled: winrm quickconfig"
    exit 1
}

$session = New-PSSession -ComputerName $TargetIP -Credential $Credential -Authentication Negotiate

$deepReport = Invoke-Command -Session $session -ScriptBlock {
    $r = @{ TargetIP = $using:TargetIP; Timestamp = (Get-Date -Format "o"); OpenPorts = @(); NetworkConfig = @{}; RiskyShares = @(); Findings = @() }

    # Open TCP Ports (common risky ports)
    $riskyPorts = @(21,22,23,25,53,80,135,137,139,443,445,1433,1521,3306,3389,5985,5986,8080,8443)
    $openPorts = @()
    foreach ($port in $riskyPorts) {
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.Connect("127.0.0.1", $port)
            $openPorts += @{ Port = $port; State = "OPEN" }
            $tcp.Close()
        } catch { }
    }
    $r.OpenPorts = $openPorts

    # Flag dangerous open ports
    if ($openPorts.Port -contains 23) { $r.Findings += @{ Severity = "CRITICAL"; Finding = "Telnet (port 23) is OPEN"; Recommendation = "Disable Telnet immediately - use SSH" } }
    if ($openPorts.Port -contains 3389) { $r.Findings += @{ Severity = "HIGH"; Finding = "RDP (port 3389) exposed"; Recommendation = "Restrict RDP access to VPN or specific IPs only" } }
    if ($openPorts.Port -contains 445) { $r.Findings += @{ Severity = "HIGH"; Finding = "SMB (port 445) exposed - EternalBlue risk"; Recommendation = "Ensure MS17-010 patch applied, restrict SMB to internal only" } }

    # Network adapter config
    $r.NetworkConfig = Get-NetIPConfiguration | ForEach-Object { @{ Interface = $_.InterfaceAlias; IPv4 = $_.IPv4Address.IPAddress; Gateway = $_.IPv4DefaultGateway.NextHop } }

    # SMB Shares (potential data exposure)
    $shares = Get-SmbShare | Where-Object { $_.Name -notmatch "^\w+\$$" }
    $r.RiskyShares = $shares | ForEach-Object { @{ Name = $_.Name; Path = $_.Path; Description = $_.Description } }
    if ($shares.Count -gt 0) { $r.Findings += @{ Severity = "MEDIUM"; Finding = "$($shares.Count) non-default SMB shares detected"; Recommendation = "Review share permissions and remove unnecessary shares" } }

    # SMBv1 check (EternalBlue vector)
    $smb1 = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
    if ($smb1.EnableSMB1Protocol) { $r.Findings += @{ Severity = "CRITICAL"; Finding = "SMBv1 is ENABLED (EternalBlue / WannaCry vulnerability)"; Recommendation = "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false" } }

    # NLA for RDP
    $rdpKey = "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
    $nla = (Get-ItemProperty $rdpKey -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    if ($nla -eq 0) { $r.Findings += @{ Severity = "HIGH"; Finding = "RDP Network Level Authentication (NLA) is DISABLED"; Recommendation = "Enable NLA for RDP to prevent pre-auth attacks" } }

    return $r
}

Remove-PSSession $session
$outputPath = Join-Path $env:TEMP "Netra-Deep-$($TargetIP.Replace('.','_'))-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$deepReport | ConvertTo-Json -Depth 10 | Out-File $outputPath -Encoding UTF8
Write-Host "[+] Deep scan complete. Report: $outputPath" -ForegroundColor Green
`;

interface ScriptViewerProps {
  mode: "light" | "deep";
}

export default function ScriptViewer({ mode }: ScriptViewerProps) {
  const [copied, setCopied] = useState(false);
  const script = mode === "light" ? LIGHT_SCAN_SCRIPT : DEEP_SCAN_SCRIPT;
  const filename = mode === "light" ? "Netra-Light.ps1" : "Netra-Deep.ps1";

  const handleCopy = () => {
    navigator.clipboard.writeText(script);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([script], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <div className="bg-surface-2 border-b border-border px-4 py-2.5 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-threat-critical" />
            <span className="w-3 h-3 rounded-full bg-threat-medium" />
            <span className="w-3 h-3 rounded-full bg-threat-low" />
          </div>
          <span className="font-mono text-sm text-muted-foreground">{filename}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors border border-border hover:border-cyber-cyan/40 rounded px-2.5 py-1.5"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-threat-low" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? "Copied!" : "Copy"}
          </button>
          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 font-mono text-xs text-cyber-cyan border border-cyber-cyan/40 hover:bg-cyber-cyan/10 rounded px-2.5 py-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download .ps1
          </button>
        </div>
      </div>
      <div className="bg-surface-1 max-h-80 overflow-y-auto">
        <pre className="p-4 text-xs font-mono text-foreground/80 leading-relaxed whitespace-pre-wrap">
          <code>{script}</code>
        </pre>
      </div>
    </div>
  );
}
