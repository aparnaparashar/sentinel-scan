import { Link } from "react-router-dom";
import { Shield } from "lucide-react";

export default function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between h-16">
        <Link to="/" className="flex items-center gap-3">
          <div className="w-8 h-8 bg-cyber-red rounded flex items-center justify-center shadow-glow-red">
            <Shield className="w-4 h-4 text-primary-foreground" />
          </div>
          <span className="font-orbitron text-lg font-bold text-foreground tracking-widest">
            BAD<span className="text-cyber-red">COPS</span>
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-6">
          {[
            { label: "Architecture", href: "/#architecture" },
            { label: "Scan", href: "/#scan" },
            { label: "Report", href: "/report" },
          ].map(({ label, href }) => (
            <Link
              key={label}
              to={href}
              className="font-mono text-xs text-muted-foreground hover:text-foreground uppercase tracking-widest transition-colors"
            >
              {label}
            </Link>
          ))}
        </div>

        <Link
          to="/#scan"
          className="font-mono text-xs text-cyber-red border border-cyber-red/50 hover:bg-cyber-red/10 px-4 py-2 rounded transition-colors uppercase tracking-widest"
        >
          Scan Now
        </Link>
      </div>
    </nav>
  );
}
