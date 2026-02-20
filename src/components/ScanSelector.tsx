import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Zap, Activity, AlertTriangle, Download, ChevronRight, Wifi } from "lucide-react";
import ScriptViewer from "./ScriptViewer";

type ScanMode = "light" | "deep" | null;

export default function ScanSelector() {
  const [mode, setMode] = useState<ScanMode>(null);
  const [deepIP, setDeepIP] = useState("");
  const navigate = useNavigate();

  const handleStartScan = () => {
    if (mode) navigate(`/scan?mode=${mode}&ip=${deepIP || "local"}`);
  };

  return (
    <section className="py-20 px-6 bg-grid" id="scan">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 font-mono text-xs text-cyber-red border border-cyber-red/30 bg-cyber-red/5 px-4 py-2 rounded mb-6 uppercase tracking-widest">
            <span className="w-2 h-2 bg-cyber-red rounded-full animate-pulse" />
            Select Scan Mode
          </div>
          <h2 className="font-orbitron text-3xl md:text-4xl font-bold text-foreground">
            INITIATE <span className="text-glow-red text-cyber-red">VULNERABILITY</span> SCAN
          </h2>
        </div>

        <div className="grid md:grid-cols-2 gap-6 mb-8">
          {/* Light Scan */}
          <button
            onClick={() => setMode("light")}
            className={`text-left border rounded-xl p-6 transition-all duration-300 ${
              mode === "light"
                ? "border-cyber-red bg-cyber-red/10 shadow-glow-red"
                : "border-border bg-surface-2 hover:border-cyber-red/40 hover:bg-cyber-red/5"
            }`}
          >
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${mode === "light" ? "bg-cyber-red text-primary-foreground" : "bg-surface-3 text-cyber-red"}`}>
                <Zap className="w-6 h-6" />
              </div>
              <div>
                <div className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Mode 01</div>
                <h3 className="font-rajdhani font-bold text-xl text-foreground">Light Scan</h3>
              </div>
              {mode === "light" && <ChevronRight className="ml-auto text-cyber-red w-5 h-5" />}
            </div>
            <p className="text-muted-foreground font-rajdhani text-sm mb-4 leading-relaxed">
              Run a PowerShell script locally on the target Windows machine. No admin privileges required.
              Detects OS misconfigurations, missing patches, and firewall/AV issues.
            </p>
            <ul className="space-y-1.5">
              {["No admin rights needed", "Runs locally on host", "Outputs JSON report", "AV/EDR safe", "~2 min runtime"].map((f) => (
                <li key={f} className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                  <span className="text-threat-low">✓</span> {f}
                </li>
              ))}
            </ul>
          </button>

          {/* Deep Scan */}
          <button
            onClick={() => setMode("deep")}
            className={`text-left border rounded-xl p-6 transition-all duration-300 ${
              mode === "deep"
                ? "border-cyber-cyan bg-cyber-cyan/10 shadow-glow-cyan"
                : "border-border bg-surface-2 hover:border-cyber-cyan/40 hover:bg-cyber-cyan/5"
            }`}
          >
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${mode === "deep" ? "bg-cyber-cyan text-secondary-foreground" : "bg-surface-3 text-cyber-cyan"}`}>
                <Wifi className="w-6 h-6" />
              </div>
              <div>
                <div className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Mode 02</div>
                <h3 className="font-rajdhani font-bold text-xl text-foreground">Deep Scan</h3>
              </div>
              {mode === "deep" && <ChevronRight className="ml-auto text-cyber-cyan w-5 h-5" />}
            </div>
            <p className="text-muted-foreground font-rajdhani text-sm mb-4 leading-relaxed">
              Remote scan via WinRM/Remote PowerShell. Performs network-level analysis, open port detection,
              SMB audit, and lateral movement risk assessment.
            </p>
            <ul className="space-y-1.5">
              {["Admin credentials required", "WinRM must be enabled", "Network-level scanning", "Port & service detection", "SMBv1/NLA/RDP audits"].map((f) => (
                <li key={f} className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
                  <span className="text-cyber-cyan">✓</span> {f}
                </li>
              ))}
            </ul>
          </button>
        </div>

        {/* Deep scan IP input */}
        {mode === "deep" && (
          <div className="border border-cyber-cyan/30 bg-cyber-cyan/5 rounded-lg p-4 mb-6 animate-fade-up">
            <label className="block font-mono text-xs text-cyber-cyan uppercase tracking-widest mb-2">Target IP Address</label>
            <input
              type="text"
              value={deepIP}
              onChange={(e) => setDeepIP(e.target.value)}
              placeholder="192.168.1.100"
              className="w-full bg-surface-1 border border-border text-foreground font-mono text-sm px-4 py-2.5 rounded focus:outline-none focus:border-cyber-cyan/60 placeholder:text-muted-foreground"
            />
            <p className="text-xs text-muted-foreground font-mono mt-2">
              ⚠ WinRM must be enabled: <code className="text-cyber-cyan">winrm quickconfig</code>
            </p>
          </div>
        )}

        {/* Action buttons */}
        {mode && (
          <div className="flex flex-col sm:flex-row gap-4 mb-10 animate-fade-up">
            <button
              onClick={handleStartScan}
              className="flex-1 flex items-center justify-center gap-2 bg-gradient-primary text-primary-foreground font-rajdhani font-bold text-lg py-4 rounded-lg hover:opacity-90 transition-all shadow-glow-red"
            >
              <Activity className="w-5 h-5" />
              Launch Scan
            </button>
          </div>
        )}

        {/* Script download */}
        {mode && (
          <div className="animate-fade-up">
            <div className="flex items-center gap-2 mb-4">
              <Download className="w-4 h-4 text-cyber-cyan" />
              <h3 className="font-rajdhani font-semibold text-foreground text-lg">PowerShell Script</h3>
              <span className="font-mono text-xs text-muted-foreground border border-border px-2 py-0.5 rounded">
                {mode === "light" ? "Netra-Light.ps1" : "Netra-Deep.ps1"}
              </span>
            </div>
            <ScriptViewer mode={mode} />
          </div>
        )}
      </div>
    </section>
  );
}
