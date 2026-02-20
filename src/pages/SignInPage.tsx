import { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Eye, EyeOff, Loader2, LogIn } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

export default function SignInPage() {
  const { signIn } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    const result = await signIn(email, password);
    setLoading(false);
    if (result.error) {
      setError(result.error);
    } else {
      navigate("/");
    }
  };

  return (
    <div className="min-h-screen bg-background bg-grid flex items-center justify-center px-4">
      {/* Back link */}
      <Link to="/" className="absolute top-6 left-6 flex items-center gap-2 font-mono text-xs text-muted-foreground hover:text-foreground transition-colors uppercase tracking-widest">
        <span>←</span> Back to Home
      </Link>

      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-6">
            <div className="w-10 h-10 bg-cyber-red rounded flex items-center justify-center shadow-glow-red">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="font-orbitron text-2xl font-black tracking-widest">
              BAD<span className="text-cyber-red">COPS</span>
            </span>
          </div>
          <h1 className="font-orbitron text-xl font-bold text-foreground mb-1">SIGN IN</h1>
          <p className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Access your vulnerability dashboard</p>
        </div>

        {/* Form card */}
        <div className="border border-border bg-surface-1 rounded-xl p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Email */}
            <div>
              <label className="block font-mono text-xs text-muted-foreground uppercase tracking-widest mb-2">
                Email Address
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@badcops.io"
                className="w-full bg-surface-2 border border-border text-foreground font-mono text-sm px-4 py-3 rounded-lg focus:outline-none focus:border-cyber-red/60 focus:shadow-glow-red placeholder:text-muted-foreground transition-all"
              />
            </div>

            {/* Password */}
            <div>
              <label className="block font-mono text-xs text-muted-foreground uppercase tracking-widest mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPass ? "text" : "password"}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-surface-2 border border-border text-foreground font-mono text-sm px-4 py-3 pr-12 rounded-lg focus:outline-none focus:border-cyber-red/60 focus:shadow-glow-red placeholder:text-muted-foreground transition-all"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  {showPass ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="border border-threat-critical/30 bg-threat-critical/10 text-threat-critical font-mono text-xs px-4 py-3 rounded-lg">
                ⚠ {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-primary text-primary-foreground font-rajdhani font-bold text-base py-3 rounded-lg hover:opacity-90 transition-all shadow-glow-red disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Authenticating...</>
              ) : (
                <><LogIn className="w-4 h-4" /> Sign In</>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="flex items-center gap-4 my-6">
            <div className="flex-1 h-px bg-border" />
            <span className="font-mono text-xs text-muted-foreground">OR</span>
            <div className="flex-1 h-px bg-border" />
          </div>

          <p className="text-center font-mono text-xs text-muted-foreground">
            No account?{" "}
            <Link to="/signup" className="text-cyber-red hover:text-cyber-red/80 transition-colors underline underline-offset-2">
              Create one
            </Link>
          </p>
        </div>

        <p className="text-center font-mono text-xs text-muted-foreground mt-6 opacity-50">
          Authorized operators only · BadCops v1.0
        </p>
      </div>
    </div>
  );
}
