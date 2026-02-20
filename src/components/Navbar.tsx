import { Link, useLocation } from "react-router-dom";
import { Shield, LogIn, LogOut, UserPlus, User } from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";

export default function Navbar() {
  const { user, signOut } = useAuth();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const location = useLocation();

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border bg-background/90 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-8 h-8 bg-cyber-red rounded flex items-center justify-center shadow-glow-red">
              <Shield className="w-4 h-4 text-primary-foreground" />
            </div>
            <span className="font-orbitron text-lg font-bold text-foreground tracking-widest">
              <span className="text-[#e22f35]">NET</span>
              <span className="text-white">RA</span>
            </span>
          </Link>

        <div className="hidden md:flex items-center gap-6">
          {[
            { label: "Home", id: "top" },
            { label: "Architecture", id: "architecture" },
            { label: "Scan", id: "scan" },
            { label: "Report", href: "/report" },
          ].map(({ label, id, href }) => {
            if (id) {
              // If on home page, scroll to section; otherwise navigate to home with hash
              return location.pathname === "/" ? (
                <button
                  key={label}
                  onClick={() => {
                    if (id === "top") window.scrollTo({ top: 0, behavior: "smooth" });
                    else {
                      const el = document.getElementById(id);
                      if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
                    }
                  }}
                  className="font-mono text-xs text-muted-foreground hover:text-foreground uppercase tracking-widest transition-colors bg-transparent border-0"
                >
                  {label}
                </button>
              ) : (
                <Link
                  key={label}
                  to={id === "top" ? "/" : `/#${id}`}
                  className="font-mono text-xs text-muted-foreground hover:text-foreground uppercase tracking-widest transition-colors"
                >
                  {label}
                </Link>
              );
            }

            return (
              <Link
                key={label}
                to={href as string}
                className="font-mono text-xs text-muted-foreground hover:text-foreground uppercase tracking-widest transition-colors"
              >
                {label}
              </Link>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          {user ? (
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="flex items-center gap-2 font-mono text-xs text-foreground border border-border hover:border-cyber-red/50 bg-surface-2 hover:bg-surface-3 px-3 py-2 rounded transition-all"
              >
                <User className="w-3.5 h-3.5 text-cyber-red" />
                <span className="hidden sm:inline max-w-[120px] truncate">{user.name}</span>
              </button>
              {dropdownOpen && (
                <div className="absolute right-0 top-11 w-48 bg-surface-1 border border-border rounded-lg shadow-xl overflow-hidden z-50">
                  <div className="px-4 py-3 border-b border-border">
                    <p className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Signed in as</p>
                    <p className="font-rajdhani text-sm text-foreground font-semibold truncate mt-0.5">{user.email}</p>
                  </div>
                  <button
                    onClick={() => { signOut(); setDropdownOpen(false); }}
                    className="w-full flex items-center gap-2 px-4 py-3 font-mono text-xs text-threat-critical hover:bg-threat-critical/10 transition-colors uppercase tracking-widest"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <>
              <Link
                to="/signin"
                className="font-mono text-xs text-muted-foreground hover:text-foreground border border-border hover:border-cyber-red/40 px-3 py-2 rounded transition-all uppercase tracking-widest flex items-center gap-1.5"
              >
                <LogIn className="w-3 h-3" />
                Sign In
              </Link>
              <Link
                to="/signup"
                className="font-mono text-xs text-cyber-red border border-cyber-red/50 hover:bg-cyber-red/10 px-3 py-2 rounded transition-colors uppercase tracking-widest flex items-center gap-1.5"
              >
                <UserPlus className="w-3 h-3" />
                Sign Up
              </Link>
            </>
          )}
        </div>
      </div>

      {/* Close dropdown on outside click */}
      {dropdownOpen && (
        <div className="fixed inset-0 z-40" onClick={() => setDropdownOpen(false)} />
      )}
    </nav>
  );
}

