import { Shield, Wifi, FileDown, AlertTriangle, Activity, Lock } from "lucide-react";

interface Stat {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
}

const stats: Stat[] = [
  { label: "CVEs Tracked", value: "200K+", icon: AlertTriangle, color: "text-cyber-red" },
  { label: "Agent-less", value: "100%", icon: Shield, color: "text-cyber-cyan" },
  { label: "Scan Modes", value: "2", icon: Activity, color: "text-cyber-red" },
  { label: "AV/EDR Safe", value: "YES", icon: Lock, color: "text-cyber-cyan" },
];

export default function StatsBar() {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-border">
      {stats.map(({ label, value, icon: Icon, color }) => (
        <div
          key={label}
          className="bg-surface-1 flex flex-col items-center justify-center py-6 px-4 text-center"
        >
          <Icon className={`w-5 h-5 mb-2 ${color}`} />
          <span className={`font-orbitron text-2xl font-bold ${color}`}>{value}</span>
          <span className="text-muted-foreground text-sm font-rajdhani mt-1 tracking-wider uppercase">{label}</span>
        </div>
      ))}
    </div>
  );
}
