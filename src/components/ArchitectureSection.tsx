import { useState } from "react";
import { ChevronDown, ChevronUp, Server, Network, Shield, Database, Code, Globe } from "lucide-react";

interface ArchNode {
  icon: React.ElementType;
  title: string;
  color: string;
  items: string[];
}

const architecture: ArchNode[] = [
  {
    icon: Server,
    title: "Target Windows Host",
    color: "text-cyber-red",
    items: ["Windows 10/11, Server 2016/2019/2022", "PowerShell 5.1+ required", "WinRM enabled for Deep Scan", "No agent or software installed"],
  },
  {
    icon: Code,
    title: "Light Scan Engine",
    color: "text-threat-high",
    items: ["Native PowerShell script", "OS version & patch detection", "Firewall/Defender/UAC checks", "Service enumeration & config audit", "Outputs structured JSON"],
  },
  {
    icon: Network,
    title: "Deep Scan Engine",
    color: "text-threat-medium",
    items: ["Remote PowerShell via WinRM", "Open port & service scanning", "Network misconfiguration checks", "Lateral movement risk detection", "Admin credentials required"],
  },
  {
    icon: Database,
    title: "Flask Backend",
    color: "text-cyber-cyan",
    items: ["Receives & parses scan JSON", "CVE matching via NVD API", "CVSS score assignment", "Severity classification", "Remediation step generation"],
  },
  {
    icon: Globe,
    title: "CVE Intelligence",
    color: "text-threat-low",
    items: ["NVD NIST database integration", "Open-source exploit DBs", "Real-time CVE lookup", "CVSS v3 scoring", "Historical patch data"],
  },
  {
    icon: Shield,
    title: "Report & Delivery",
    color: "text-cyber-cyan",
    items: ["IP-based unique report ID", "PDF & JSON export", "Temporary storage (privacy-first)", "No permanent user data", "Secure retrieval endpoint"],
  },
];

export default function ArchitectureSection() {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <section className="py-20 px-6 bg-grid relative">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-14">
          <div className="inline-flex items-center gap-2 font-mono text-xs text-cyber-cyan border border-cyber-cyan/30 bg-cyber-cyan/5 px-4 py-2 rounded mb-6 uppercase tracking-widest">
            <span className="w-2 h-2 bg-cyber-cyan rounded-full animate-pulse" />
            System Architecture
          </div>
          <h2 className="font-orbitron text-3xl md:text-4xl font-bold text-foreground mb-4">
            HOW <span className="text-glow-red text-cyber-red">BADCOPS</span> WORKS
          </h2>
          <p className="text-muted-foreground font-rajdhani text-lg max-w-2xl mx-auto">
            A layered, agent-less architecture designed for real-world Windows environments — no installation, no persistence, no footprint.
          </p>
        </div>

        {/* Architecture flow diagram */}
        <div className="relative mb-10">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {architecture.map((node, i) => {
              const Icon = node.icon;
              const isOpen = expanded === i;
              return (
                <button
                  key={i}
                  onClick={() => setExpanded(isOpen ? null : i)}
                  className="text-left border border-border bg-surface-2 hover:border-cyber-red/40 rounded-lg p-5 transition-all duration-300 hover:shadow-glow-red group"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`w-10 h-10 rounded border border-current/20 flex items-center justify-center ${node.color} bg-current/5`}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="font-mono text-xs text-muted-foreground">LAYER {String(i + 1).padStart(2, "0")}</div>
                        <div className={`font-rajdhani font-semibold text-base ${node.color}`}>{node.title}</div>
                      </div>
                    </div>
                    {isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                  </div>

                  {isOpen && (
                    <ul className="mt-3 space-y-2 border-t border-border pt-3">
                      {node.items.map((item, j) => (
                        <li key={j} className="flex items-start gap-2 text-sm font-rajdhani text-muted-foreground">
                          <span className={`${node.color} mt-0.5 shrink-0`}>›</span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Flow arrows */}
        <div className="flex items-center justify-center gap-2 flex-wrap">
          {["Target Host", "PowerShell", "WinRM / JSON", "Flask API", "CVE Engine", "Report"].map((step, i, arr) => (
            <div key={i} className="flex items-center gap-2">
              <span className="font-mono text-xs text-muted-foreground border border-border bg-surface-3 px-3 py-1.5 rounded">
                {step}
              </span>
              {i < arr.length - 1 && <span className="text-cyber-cyan text-lg">→</span>}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
