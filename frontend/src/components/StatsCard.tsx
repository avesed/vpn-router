import { ReactNode } from "react";

interface StatsCardProps {
  title: string;
  value: ReactNode;
  description?: string;
  icon?: React.ComponentType<{ className?: string }>;
  trend?: "up" | "down" | "neutral";
  status?: "success" | "warning" | "error" | "info";
}

export default function StatsCard({ title, value, description, icon: Icon, trend, status = "info" }: StatsCardProps) {
  const statusColors = {
    success: "from-emerald-500/10 to-emerald-500/5 border-emerald-500/20",
    warning: "from-amber-500/10 to-amber-500/5 border-amber-500/20",
    error: "from-rose-500/10 to-rose-500/5 border-rose-500/20",
    info: "from-blue-500/10 to-blue-500/5 border-blue-500/20"
  };

  const statusIconColors = {
    success: "text-emerald-400",
    warning: "text-amber-400",
    error: "text-rose-400",
    info: "text-blue-400"
  };

  const trendIcons = {
    up: "↗",
    down: "↘",
    neutral: "→"
  };

  return (
    <div className={`rounded-2xl border bg-gradient-to-br ${statusColors[status]} p-5 shadow-lg shadow-black/20 transition-all hover:shadow-xl hover:shadow-black/30 hover:scale-[1.02]`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs uppercase tracking-widest text-slate-400">{title}</p>
          <div className="mt-3 flex items-baseline gap-2">
            <div className="text-3xl font-bold text-white">{value}</div>
            {trend && (
              <span className={`text-lg ${trend === 'up' ? 'text-emerald-400' : trend === 'down' ? 'text-rose-400' : 'text-slate-400'}`}>
                {trendIcons[trend]}
              </span>
            )}
          </div>
          {description && <p className="mt-2 text-sm text-slate-400">{description}</p>}
        </div>
        {Icon && (
          <div className={`rounded-xl bg-white/5 p-3 ${statusIconColors[status]}`}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
    </div>
  );
}
