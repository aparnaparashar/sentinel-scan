import heroBanner from "@/assets/hero-banner.jpg";
import { Link } from "react-router-dom";
import { Shield, ChevronDown, Zap, Wifi, AlertTriangle } from "lucide-react";
import StatsBar from "@/components/StatsBar";
import ScanSelector from "@/components/ScanSelector";
import ArchitectureSection from "@/components/ArchitectureSection";
import Navbar from "@/components/Navbar";
import Footer from "@/components/Footer";

const threatBadges = [
  { label: "CVE-2017-0144", name: "EternalBlue", sev: "CRITICAL" },
  { label: "CVE-2021-34527", name: "PrintNightmare", sev: "CRITICAL" },
  { label: "CVE-2020-0796", name: "SMBGhost", sev: "CRITICAL" },
  { label: "CVE-2019-0708", name: "BlueKeep", sev: "CRITICAL" },
  { label: "CVE-2022-26925", name: "LSA Spoofing", sev: "HIGH" },
];

export default function Index() {
  return (
    <div id="top" className="min-h-screen bg-background">
      <Navbar />

      {/* ===== HERO ===== */}
      <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden">
        {/* Background image */}
        <div
          className="absolute inset-0 bg-cover bg-center"
          style={{ backgroundImage: `url(${heroBanner})` }}
        />
        {/* Dark overlay + grid */}
        <div className="absolute inset-0 bg-background/75 bg-grid" />
        {/* Red gradient from bottom */}
        <div className="absolute bottom-0 left-0 right-0 h-40 bg-gradient-to-t from-background to-transparent" />

        {/* Floating CVE badges */}
        <div className="absolute top-24 left-6 hidden lg:flex flex-col gap-2 opacity-60">
          {threatBadges.slice(0, 3).map((b) => (
            <div key={b.label} className="font-mono text-xs border border-threat-critical/30 bg-threat-critical/10 text-threat-critical px-3 py-1.5 rounded">
              <span className="opacity-60">{b.label}</span> · {b.name}
            </div>
          ))}
        </div>
        <div className="absolute top-24 right-6 hidden lg:flex flex-col gap-2 opacity-60">
          {threatBadges.slice(3).map((b) => (
            <div key={b.label} className="font-mono text-xs border border-threat-critical/30 bg-threat-critical/10 text-threat-critical px-3 py-1.5 rounded">
              <span className="opacity-60">{b.label}</span> · {b.name}
            </div>
          ))}
        </div>

        {/* Hero content */}
        <div className="relative z-10 text-center px-6 max-w-5xl mx-auto pt-16">
          <div className="inline-flex items-center gap-2 font-mono text-xs text-cyber-cyan border border-cyber-cyan/30 bg-cyber-cyan/5 px-4 py-2 rounded mb-8 uppercase tracking-widest animate-fade-up">
            <span className="w-2 h-2 bg-cyber-cyan rounded-full animate-pulse" />
            Smart India Hackathon · Cybersecurity Track
          </div>

          <h1 className="font-orbitron text-5xl md:text-7xl lg:text-8xl font-black mb-4 tracking-tight animate-fade-up" style={{ animationDelay: "0.1s", opacity: 0 }}>
            <span className="text-glow-red text-cyber-red">NET</span>
            <span className="text-foreground">RA</span>
          </h1>

          <p className="font-orbitron text-sm md:text-base text-cyber-cyan tracking-widest mb-6 uppercase animate-fade-up" style={{ animationDelay: "0.2s", opacity: 0 }}>
            Agent-less · Windows · Vulnerability Scanner
          </p>

          <p className="font-rajdhani text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-up" style={{ animationDelay: "0.3s", opacity: 0 }}>
            Scan Windows systems for vulnerabilities using <strong className="text-foreground">native PowerShell</strong> - 
            no agent, no installation, no footprint. CVE-mapped reports in minutes.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center animate-fade-up" style={{ animationDelay: "0.4s", opacity: 0 }}>
            <a
              href="#scan"
              className="inline-flex items-center justify-center gap-2 bg-gradient-primary text-primary-foreground font-rajdhani font-bold text-lg px-8 py-4 rounded-lg hover:opacity-90 transition-all shadow-glow-red"
            >
              <Zap className="w-5 h-5" />
              Start Light Scan
            </a>
            <a
              href="#scan"
              className="inline-flex items-center justify-center gap-2 border border-cyber-cyan/50 text-cyber-cyan font-rajdhani font-bold text-lg px-8 py-4 rounded-lg hover:bg-cyber-cyan/10 transition-all"
            >
              <Wifi className="w-5 h-5" />
              Deep Scan
            </a>
          </div>

          <div className="mt-6 flex items-center justify-center gap-2 text-xs font-mono text-muted-foreground">
            <Shield className="w-3.5 h-3.5 text-threat-low" />
            No agent installed · No data stored permanently · AV/EDR compatible
          </div>
        </div>

        <a href="#stats" className="absolute bottom-8 left-1/2 -translate-x-1/2 text-muted-foreground animate-bounce">
          <ChevronDown className="w-6 h-6" />
        </a>
      </section>

      {/* ===== STATS ===== */}
      <div id="stats">
        <StatsBar />
      </div>

      {/* ===== THREAT BANNER ===== */}
      <section className="bg-surface-1 border-y border-border py-10 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center gap-3 mb-6">
            <AlertTriangle className="w-5 h-5 text-cyber-red" />
            <h2 className="font-orbitron text-base font-bold text-foreground tracking-wider">DETECTABLE VULNERABILITIES</h2>
            <span className="font-mono text-xs text-muted-foreground">— CVEs Netra can identify</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {[
              { cve: "CVE-2017-0144", name: "EternalBlue (MS17-010)", type: "SMBv1 Remote Code Execution", sev: "critical" },
              { cve: "CVE-2021-34527", name: "PrintNightmare", type: "Windows Print Spooler Privilege Escalation", sev: "critical" },
              { cve: "CVE-2020-0796", name: "SMBGhost", type: "SMBv3.1.1 Remote Code Execution", sev: "critical" },
              { cve: "CVE-2019-0708", name: "BlueKeep", type: "RDP Pre-Auth Remote Code Execution", sev: "critical" },
              { cve: "CVE-2022-26925", name: "LSA Spoofing", type: "NTLM Authentication Vulnerability", sev: "high" },
              { cve: "CVE-2021-36934", name: "HiveNightmare", type: "SAM Database Privilege Escalation", sev: "high" },
              { cve: "CVE-2020-1472", name: "Zerologon", type: "Netlogon Privilege Escalation", sev: "critical" },
              { cve: "CVE-2021-1675", name: "PrintNightmare LPE", type: "Local Privilege Escalation Vector", sev: "high" },
              { cve: "CVE-2023-23397", name: "Outlook NTLM Leak", type: "Zero-click credential theft", sev: "critical" },
            ].map(({ cve, name, type, sev }) => (
              <div
                key={cve}
                className={`border rounded-lg p-4 ${
                  sev === "critical"
                    ? "border-threat-critical/30 bg-threat-critical/5"
                    : "border-threat-high/30 bg-threat-high/5"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs text-muted-foreground">{cve}</span>
                  <span className={`font-mono text-xs font-bold uppercase ${sev === "critical" ? "text-threat-critical" : "text-threat-high"}`}>
                    {sev}
                  </span>
                </div>
                <div className="font-rajdhani font-semibold text-foreground text-sm">{name}</div>
                <div className="font-rajdhani text-xs text-muted-foreground mt-0.5">{type}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ===== ARCHITECTURE ===== */}
      <div id="architecture">
        <ArchitectureSection />
      </div>

      {/* ===== SCAN SELECTOR ===== */}
      <ScanSelector />

      <Footer />
    </div>
  );
}
