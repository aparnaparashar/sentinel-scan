import { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Eye, EyeOff, Loader2, UserPlus } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";

export default function SignUpPage() {
  const { signUp } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setLoading(true);
    const result = await signUp(email, password, name);
    setLoading(false);
    if (result.error) {
      setError(result.error);
    } else {
      navigate("/");
    }
  };

  const strength = password.length === 0 ? 0 : password.length < 6 ? 1 : password.length < 10 ? 2 : 3;
  const strengthLabel = ["", "Weak", "Medium", "Strong"][strength];
  const strengthColor = ["", "text-threat-critical", "text-threat-high", "text-threat-low"][strength];
  const strengthBar = ["", "w-1/3 bg-threat-critical", "w-2/3 bg-threat-high", "w-full bg-threat-low"][strength];

  return (
    <div className="min-h-screen bg-background bg-grid flex items-center justify-center px-4 py-12">
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
              <span className="text-[#e22f35]">NET</span>
              <span className="text-white">RA</span>
            </span>
          </div>
          <h1 className="font-orbitron text-xl font-bold text-foreground mb-1">CREATE ACCOUNT</h1>
          <p className="font-mono text-xs text-muted-foreground uppercase tracking-widest">Join the Netra security network</p>
        </div>

        {/* Form card */}
        <div className="border border-border bg-surface-1 rounded-xl p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Name */}
            <div>
              <label className="block font-mono text-xs text-muted-foreground uppercase tracking-widest mb-2">
                Full Name
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Security Operator"
                className="w-full bg-surface-2 border border-border text-foreground font-mono text-sm px-4 py-3 rounded-lg focus:outline-none focus:border-cyber-red/60 focus:shadow-glow-red placeholder:text-muted-foreground transition-all"
              />
            </div>

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
                placeholder="operator@netra.io"
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
                  placeholder="Min. 6 characters"
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
              {/* Strength bar */}
              {password.length > 0 && (
                <div className="mt-2">
                  <div className="h-1 bg-surface-3 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-300 ${strengthBar}`} />
                  </div>
                  <p className={`font-mono text-xs mt-1 ${strengthColor}`}>{strengthLabel} password</p>
                </div>
              )}
            </div>

            {/* Confirm password */}
            <div>
              <label className="block font-mono text-xs text-muted-foreground uppercase tracking-widest mb-2">
                Confirm Password
              </label>
              <input
                type={showPass ? "text" : "password"}
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                placeholder="Re-enter password"
                className={`w-full bg-surface-2 border text-foreground font-mono text-sm px-4 py-3 rounded-lg focus:outline-none focus:shadow-glow-red placeholder:text-muted-foreground transition-all ${
                  confirm && confirm !== password
                    ? "border-threat-critical/60"
                    : "border-border focus:border-cyber-red/60"
                }`}
              />
              {confirm && confirm !== password && (
                <p className="font-mono text-xs text-threat-critical mt-1">Passwords do not match</p>
              )}
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
                <><Loader2 className="w-4 h-4 animate-spin" /> Creating Account...</>
              ) : (
                <><UserPlus className="w-4 h-4" /> Create Account</>
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
            Already have an account?{" "}
            <Link to="/signin" className="text-cyber-red hover:text-cyber-red/80 transition-colors underline underline-offset-2">
              Sign In
            </Link>
          </p>
        </div>

        <p className="text-center font-mono text-xs text-muted-foreground mt-6 opacity-50">
          By signing up you agree to use Netra for authorized assessments only.
        </p>
      </div>
    </div>
  );
}
