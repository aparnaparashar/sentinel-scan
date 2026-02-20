import { useState } from "react";
import { FileDown, Search, AlertTriangle, Shield, CheckCircle } from "lucide-react";
import VulnerabilityCard from "@/components/VulnerabilityCard";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

const SAMPLE_REPORT = {
  reportId: "BC-192-168-1-100-20241215",
  target: "192.168.1.100",
  hostname: "CORP-WORKSTATION-07",
  os: "Windows 10 Pro · Build 19045 · x64",
  scanType: "Deep Scan",
  timestamp: "2024-12-15T14:32:00Z",
  scanDuration: "4m 17s",
  riskScore: 78,
  summary: { critical: 2, high: 3, medium: 2, low: 1, total: 8 },
  vulnerabilities: [
    {
      cve: "CVE-2017-0144",
      title: "EternalBlue — SMBv1 Remote Code Execution",
      severity: "critical" as const,
      description: "SMBv1 is enabled on the target host. This protocol has a critical remote code execution vulnerability exploited by WannaCry and NotPetya ransomware. An unauthenticated attacker can execute arbitrary code remotely on vulnerable Windows systems via port 445.",
      affected: "SMBv1 · Port 445 · All Windows versions pre-MS17-010",
      patch: "Apply KB4012212 (MS17-010). Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
      cvssScore: 9.8,
    },
    {
      cve: "CVE-2019-0708",
      title: "BlueKeep — RDP Pre-Auth Remote Code Execution",
      severity: "critical" as const,
      description: "RDP port 3389 is exposed without Network Level Authentication (NLA). BlueKeep allows unauthenticated remote attackers to execute arbitrary code via a specially crafted request to the Remote Desktop Service. Wormable — no user interaction required.",
      affected: "RDP · Port 3389 · Windows 7, Server 2008 R2",
      patch: "Enable NLA for RDP. Apply KB4499175. Restrict RDP access to VPN/trusted IPs only.",
      cvssScore: 9.8,
    },
    {
      cve: "CVE-2021-34527",
      title: "PrintNightmare — Print Spooler Privilege Escalation",
      severity: "high" as const,
      description: "The Windows Print Spooler service is running and allows remote exploitation for privilege escalation and remote code execution. An authenticated attacker can gain SYSTEM privileges by installing a malicious printer driver.",
      affected: "Print Spooler service · All Windows versions",
      patch: "Apply KB5004945. Disable Print Spooler if not required: Stop-Service -Name Spooler -Force",
      cvssScore: 8.8,
    },
    {
      cve: "CVE-2020-1472",
      title: "Zerologon — Netlogon Privilege Escalation",
      severity: "high" as const,
      description: "A cryptographic flaw in the Netlogon Remote Protocol allows an unauthenticated attacker to establish a secure channel and take over an Active Directory domain controller by setting the machine account password to empty.",
      affected: "Netlogon service · Domain Controllers",
      patch: "Apply KB4557222. Ensure August 2020 or later cumulative updates are installed.",
      cvssScore: 10.0,
    },
    {
      cve: "CVE-2022-26925",
      title: "LSA Authentication Spoofing",
      severity: "high" as const,
      description: "An unauthenticated attacker can force domain controllers to authenticate to the attacker using NTLM via the Local Security Authority. Combined with NTLM relay, this can lead to privilege escalation.",
      affected: "LSASS · Windows Active Directory environments",
      patch: "Apply May 2022 Patch Tuesday updates. Enable Extended Protection for Authentication (EPA).",
      cvssScore: 8.1,
    },
    {
      cve: "CVE-2023-MISC-001",
      title: "Firewall Public Profile Disabled",
      severity: "medium" as const,
      description: "The Windows Firewall public network profile is disabled, leaving the host fully exposed on untrusted networks. All inbound connection restrictions on the public profile are bypassed.",
      affected: "Windows Firewall · Public network profile",
      patch: "Enable firewall: Set-NetFirewallProfile -Profile Public -Enabled True",
      cvssScore: 6.5,
    },
    {
      cve: "CVE-2023-MISC-002",
      title: "Telnet Service Running (Port 23)",
      severity: "medium" as const,
      description: "Telnet transmits all data including credentials in plaintext. Running Telnet exposes the system to credential sniffing and man-in-the-middle attacks on any network segment.",
      affected: "Telnet service · Port 23",
      patch: "Disable Telnet: Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled. Use SSH instead.",
      cvssScore: 6.2,
    },
    {
      cve: "CVE-2023-MISC-003",
      title: "Excessive Local Administrator Accounts",
      severity: "low" as const,
      description: "5 accounts are members of the local Administrators group. Excessive admin privileges increase the blast radius of any successful attack and violate the principle of least privilege.",
      affected: "Local Administrators group · All users listed",
      patch: "Remove unnecessary admin accounts. Implement LAPS for local admin password management.",
      cvssScore: 4.3,
    },
  ],
};

function RiskGauge({ score }: { score: number }) {
  const color = score >= 80 ? "text-threat-critical" : score >= 60 ? "text-threat-high" : score >= 40 ? "text-threat-medium" : "text-threat-low";
  const label = score >= 80 ? "CRITICAL RISK" : score >= 60 ? "HIGH RISK" : score >= 40 ? "MEDIUM RISK" : "LOW RISK";

  return (
    <div className="text-center">
      <div className={`font-orbitron text-6xl font-black ${color} text-glow-red`}>{score}</div>
      <div className={`font-mono text-sm uppercase tracking-widest mt-1 ${color}`}>{label}</div>
      <div className="text-muted-foreground font-mono text-xs mt-1">/ 100 Risk Score</div>
    </div>
  );
}

export default function ReportPage() {
  const [ipInput, setIpInput] = useState("");
  const [loaded, setLoaded] = useState(true); // show sample by default
  const report = SAMPLE_REPORT;

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.reportId}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-background bg-grid">
      <Navbar />

      <div className="max-w-6xl mx-auto px-6 pt-24 pb-16">
        {/* Report lookup */}
        <div className="border border-border bg-surface-2 rounded-xl p-6 mb-10">
          <h2 className="font-orbitron text-lg font-bold text-foreground mb-4">Retrieve Report by IP</h2>
          <div className="flex gap-3">
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="Enter target IP (e.g. 192.168.1.100)"
              className="flex-1 bg-surface-1 border border-border text-foreground font-mono text-sm px-4 py-2.5 rounded focus:outline-none focus:border-cyber-cyan/60 placeholder:text-muted-foreground"
            />
            <button
              onClick={() => setLoaded(true)}
              className="flex items-center gap-2 bg-gradient-primary text-primary-foreground font-rajdhani font-bold px-5 py-2.5 rounded hover:opacity-90 transition-all"
            >
              <Search className="w-4 h-4" />
              Retrieve
            </button>
          </div>
          <p className="text-xs font-mono text-muted-foreground mt-2">
            Reports are stored temporarily (24h). No permanent data retained. Demo report shown below.
          </p>
        </div>

        {loaded && (
          <>
            {/* Report header */}
            <div className="grid md:grid-cols-3 gap-6 mb-8">
              <div className="md:col-span-2 border border-border bg-surface-2 rounded-xl p-6">
                <div className="flex items-center gap-2 mb-5">
                  <Shield className="w-5 h-5 text-cyber-red" />
                  <span className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Vulnerability Report</span>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    ["Report ID", report.reportId],
                    ["Target IP", report.target],
                    ["Hostname", report.hostname],
                    ["OS", report.os],
                    ["Scan Type", report.scanType],
                    ["Scan Duration", report.scanDuration],
                    ["Timestamp", new Date(report.timestamp).toLocaleString()],
                    ["Total Findings", report.summary.total.toString()],
                  ].map(([label, value]) => (
                    <div key={label}>
                      <div className="font-mono text-xs text-muted-foreground uppercase tracking-wider mb-0.5">{label}</div>
                      <div className="font-rajdhani text-sm text-foreground font-medium">{value}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="border border-border bg-surface-2 rounded-xl p-6 flex flex-col items-center justify-center">
                <RiskGauge score={report.riskScore} />
                <div className="grid grid-cols-4 gap-2 mt-6 w-full">
                  {[
                    { label: "CRIT", count: report.summary.critical, color: "text-threat-critical" },
                    { label: "HIGH", count: report.summary.high, color: "text-threat-high" },
                    { label: "MED", count: report.summary.medium, color: "text-threat-medium" },
                    { label: "LOW", count: report.summary.low, color: "text-threat-low" },
                  ].map(({ label, count, color }) => (
                    <div key={label} className="text-center">
                      <div className={`font-orbitron text-xl font-bold ${color}`}>{count}</div>
                      <div className="font-mono text-xs text-muted-foreground">{label}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Download */}
            <div className="flex gap-3 mb-8">
              <button
                onClick={handleDownloadJSON}
                className="flex items-center gap-2 border border-cyber-cyan/40 text-cyber-cyan hover:bg-cyber-cyan/10 font-mono text-sm px-4 py-2.5 rounded transition-colors"
              >
                <FileDown className="w-4 h-4" />
                Download JSON Report
              </button>
              <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
                <CheckCircle className="w-3.5 h-3.5 text-threat-low" />
                AV-safe · No executables · Raw JSON only
              </div>
            </div>

            {/* Vulnerabilities */}
            <div>
              <h2 className="font-orbitron text-xl font-bold text-foreground mb-6 flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-cyber-red" />
                VULNERABILITY FINDINGS
                <span className="font-mono text-sm text-muted-foreground font-normal">({report.vulnerabilities.length} total)</span>
              </h2>
              <div className="space-y-4">
                {report.vulnerabilities.map((vuln) => (
                  <VulnerabilityCard key={vuln.cve} {...vuln} />
                ))}
              </div>
            </div>

            {/* Remediation summary */}
            <div className="mt-10 border border-cyber-cyan/30 bg-cyber-cyan/5 rounded-xl p-6">
              <h3 className="font-orbitron text-base font-bold text-cyber-cyan mb-4">REMEDIATION PRIORITY PLAN</h3>
              <div className="space-y-3">
                {[
                  { priority: "IMMEDIATE", color: "text-threat-critical", items: ["Patch MS17-010 (KB4012212) to close EternalBlue", "Enable NLA for RDP and restrict to VPN only", "Disable SMBv1 immediately"] },
                  { priority: "WITHIN 24H", color: "text-threat-high", items: ["Apply PrintNightmare patch KB5004945", "Install August 2020 Zerologon patch", "Update LSA EPA configuration"] },
                  { priority: "THIS WEEK", color: "text-threat-medium", items: ["Re-enable Windows Firewall on all profiles", "Disable Telnet service, migrate to SSH"] },
                  { priority: "PLANNED", color: "text-threat-low", items: ["Review and reduce local admin accounts", "Implement LAPS for privileged access management"] },
                ].map(({ priority, color, items }) => (
                  <div key={priority} className="grid md:grid-cols-4 gap-3 items-start">
                    <div className={`font-mono text-xs font-bold uppercase ${color} pt-0.5`}>{priority}</div>
                    <div className="md:col-span-3">
                      <ul className="space-y-1">
                        {items.map((item) => (
                          <li key={item} className="text-sm font-rajdhani text-muted-foreground flex gap-2">
                            <span className={color}>›</span>
                            {item}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      <Footer />
    </div>
  );
}
