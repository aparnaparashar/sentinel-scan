import { useState, useEffect, useRef } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, CheckCircle, XCircle, Loader2, ChevronRight } from "lucide-react";
import Navbar from "@/components/Navbar";

interface ScanStep {
  id: string;
  label: string;
  status: "pending" | "running" | "done" | "error";
  detail?: string;
}

const lightSteps: ScanStep[] = [
  { id: "os", label: "Collecting OS version & build info", status: "pending" },
  { id: "patches", label: "Auditing installed patches & hotfixes", status: "pending" },
  { id: "firewall", label: "Checking firewall profiles", status: "pending" },
  { id: "defender", label: "Verifying Windows Defender status", status: "pending" },
  { id: "uac", label: "Inspecting UAC configuration", status: "pending" },
  { id: "services", label: "Enumerating running services", status: "pending" },
  { id: "users", label: "Auditing local admin accounts", status: "pending" },
  { id: "cve", label: "Matching findings against CVE database", status: "pending" },
  { id: "report", label: "Generating vulnerability report", status: "pending" },
];

const deepSteps: ScanStep[] = [
  { id: "winrm", label: "Establishing WinRM remote session", status: "pending" },
  { id: "ports", label: "Scanning risky TCP ports", status: "pending" },
  { id: "smb", label: "Auditing SMB configuration (SMBv1 / EternalBlue)", status: "pending" },
  { id: "rdp", label: "Checking RDP & NLA settings", status: "pending" },
  { id: "shares", label: "Enumerating SMB shares", status: "pending" },
  { id: "network", label: "Network interface & routing audit", status: "pending" },
  { id: "lateral", label: "Assessing lateral movement vectors", status: "pending" },
  { id: "cve", label: "CVE mapping & CVSS scoring", status: "pending" },
  { id: "report", label: "Building detailed vulnerability report", status: "pending" },
];

const mockDetails: Record<string, string> = {
  os: "Windows 11 Pro · Build 22621 · x64",
  patches: "Last update: 45 days ago · 3 missing KB patches",
  firewall: "⚠ Public profile disabled",
  defender: "✓ Real-time protection active · Signatures 2d old",
  uac: "✓ UAC enabled · Level: Notify on changes",
  services: "⚠ Telnet service running on port 23",
  users: "⚠ 5 local administrator accounts found",
  cve: "8 CVE matches found · 2 CRITICAL, 3 HIGH",
  report: "Report ID: BC-192-168-1-100-20241215",
  winrm: "✓ Connected to 192.168.1.100 via HTTPS",
  ports: "⚠ Open: 23 (Telnet), 445 (SMB), 3389 (RDP)",
  smb: "⚠ SMBv1 ENABLED — EternalBlue risk detected",
  rdp: "⚠ NLA disabled — pre-auth attack surface exposed",
  shares: "2 non-default SMB shares found",
  network: "Single NIC · Default gateway reachable",
  lateral: "⚠ Pass-the-hash risk via SMBv1 + open 445",
};

export default function ScanPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const mode = (searchParams.get("mode") || "light") as "light" | "deep";
  const ip = searchParams.get("ip") || "local";
  const [steps, setSteps] = useState<ScanStep[]>(mode === "light" ? lightSteps : deepSteps);
  const [currentIdx, setCurrentIdx] = useState(0);
  const [done, setDone] = useState(false);
  const [log, setLog] = useState<string[]>(["[Netra] Initializing scan engine...", `[Netra] Mode: ${mode.toUpperCase()} | Target: ${ip}`]);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (currentIdx >= steps.length) {
      setDone(true);
      return;
    }

    setSteps((prev) =>
      prev.map((s, i) => (i === currentIdx ? { ...s, status: "running" } : s))
    );

    const delay = 800 + Math.random() * 600;
    const timer = setTimeout(() => {
      setSteps((prev) =>
        prev.map((s, i) =>
          i === currentIdx ? { ...s, status: "done", detail: mockDetails[s.id] } : s
        )
      );
      setLog((prev) => [...prev, `[+] ${mockDetails[steps[currentIdx].id] || "Step completed"}`]);
      setCurrentIdx((i) => i + 1);
    }, delay);

    return () => clearTimeout(timer);
  }, [currentIdx]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [log]);

  const progress = Math.round((steps.filter((s) => s.status === "done").length / steps.length) * 100);

  return (
    <div className="min-h-screen bg-background bg-grid">
      <Navbar />

      <div className="max-w-5xl mx-auto px-6 pt-24 pb-16">
        {/* Header */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-10 h-10 bg-surface-2 border border-border rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyber-red" />
          </div>
          <div>
            <div className="font-mono text-xs text-muted-foreground uppercase tracking-widest">
              {mode === "light" ? "Light Scan" : "Deep Scan"} · {ip}
            </div>
            <h1 className="font-orbitron text-2xl font-bold text-foreground">
              {done ? "SCAN COMPLETE" : "SCANNING..."}
            </h1>
          </div>
          {done && (
            <span className="ml-auto font-mono text-xs text-threat-low border border-threat-low/30 bg-threat-low/10 px-3 py-1.5 rounded uppercase">
              ✓ Done
            </span>
          )}
        </div>

        {/* Progress bar */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-2">
            <span className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Scan Progress</span>
            <span className="font-orbitron text-lg font-bold text-cyber-cyan">{progress}%</span>
          </div>
          <div className="h-2 bg-surface-3 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-cyan rounded-full transition-all duration-500 shadow-glow-cyan"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-6">
          {/* Steps */}
          <div className="space-y-2">
            <h2 className="font-mono text-xs text-muted-foreground uppercase tracking-widest mb-4">Scan Steps</h2>
            {steps.map((step) => (
              <div
                key={step.id}
                className={`border rounded-lg px-4 py-3 transition-all ${
                  step.status === "running"
                    ? "border-cyber-cyan/50 bg-cyber-cyan/5 shadow-glow-cyan"
                    : step.status === "done"
                    ? "border-threat-low/30 bg-threat-low/5"
                    : "border-border bg-surface-2"
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="shrink-0">
                    {step.status === "pending" && <div className="w-4 h-4 rounded-full border border-border" />}
                    {step.status === "running" && <Loader2 className="w-4 h-4 text-cyber-cyan animate-spin" />}
                    {step.status === "done" && <CheckCircle className="w-4 h-4 text-threat-low" />}
                    {step.status === "error" && <XCircle className="w-4 h-4 text-threat-critical" />}
                  </div>
                  <div className="min-w-0">
                    <div className={`font-rajdhani text-sm font-medium ${
                      step.status === "running" ? "text-cyber-cyan" :
                      step.status === "done" ? "text-foreground" : "text-muted-foreground"
                    }`}>
                      {step.label}
                    </div>
                    {step.detail && (
                      <div className="font-mono text-xs text-muted-foreground mt-0.5 truncate">{step.detail}</div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Terminal log */}
          <div>
            <h2 className="font-mono text-xs text-muted-foreground uppercase tracking-widest mb-4">Terminal Output</h2>
            <div
              ref={logRef}
              className="h-80 overflow-y-auto bg-surface-1 border border-border rounded-lg p-4 scroll-smooth"
            >
              {log.map((line, i) => (
                <div key={i} className={`font-mono text-xs mb-1 ${
                  line.startsWith("[+]") ? "text-threat-low" :
                  line.startsWith("[!]") ? "text-threat-high" :
                  line.startsWith("[Netra]") ? "text-cyber-cyan" : "text-muted-foreground"
                }`}>
                  {line}
                </div>
              ))}
              {!done && <div className="font-mono text-xs text-cyber-cyan terminal-cursor" />}
            </div>

            {done && (
              <div className="mt-4 space-y-3 animate-fade-up">
                <button
                  onClick={() => navigate("/report")}
                  className="w-full flex items-center justify-center gap-2 bg-gradient-primary text-primary-foreground font-rajdhani font-bold text-base py-3 rounded-lg hover:opacity-90 transition-all shadow-glow-red"
                >
                  View Full Vulnerability Report
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
