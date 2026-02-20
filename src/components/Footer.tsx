import { Shield, Github, AlertTriangle } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-border bg-surface-1 py-10 px-6">
      <div className="max-w-7xl mx-auto grid md:grid-cols-3 gap-8">
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-cyber-red" />
            <span className="font-orbitron text-base font-bold">BAD<span className="text-cyber-red">COPS</span></span>
          </div>
          <p className="text-muted-foreground font-rajdhani text-sm leading-relaxed max-w-xs">
            Agent-less Windows vulnerability scanner built for real-world environments. SIH-grade security tooling.
          </p>
        </div>

        <div>
          <h4 className="font-mono text-xs text-muted-foreground uppercase tracking-widest mb-3">Scan Capabilities</h4>
          <ul className="space-y-1.5 text-sm font-rajdhani text-muted-foreground">
            {["OS & Patch Audit", "Firewall / Defender Check", "UAC & User Privilege Scan", "Open Port Detection", "SMB / WinRM Assessment", "CVE Mapping & CVSS Scoring"].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <span className="text-cyber-red text-xs">›</span>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div>
          <h4 className="font-mono text-xs text-muted-foreground uppercase tracking-widest mb-3">Legal & Safety</h4>
          <div className="border border-threat-medium/30 bg-threat-medium/5 rounded p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-threat-medium shrink-0 mt-0.5" />
              <p className="text-xs font-mono text-muted-foreground leading-relaxed">
                BadCops is designed for <strong className="text-foreground">authorized security assessments only</strong>. 
                Scanning systems without explicit permission is illegal. Use responsibly.
              </p>
            </div>
          </div>
          <p className="text-xs font-mono text-muted-foreground mt-4 opacity-60">
            © 2024 BadCops Project · Smart India Hackathon
          </p>
        </div>
      </div>
    </footer>
  );
}
