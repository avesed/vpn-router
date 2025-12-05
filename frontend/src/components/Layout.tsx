import { PropsWithChildren, useState } from "react";
import { Link } from "react-router-dom";
import {
  ChartBarIcon,
  CogIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  AdjustmentsHorizontalIcon,
  RectangleStackIcon,
  ChevronDownIcon,
  ArrowRightStartOnRectangleIcon,
  ArrowLeftEndOnRectangleIcon,
  WrenchScrewdriverIcon,
  UsersIcon,
  ServerIcon,
  CloudArrowUpIcon
} from "@heroicons/react/24/outline";

interface NavItem {
  label: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

interface NavGroup {
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
}

const standaloneItems: NavItem[] = [
  { label: "仪表盘", path: "/", icon: ChartBarIcon, description: "实时监控" }
];

const navGroups: NavGroup[] = [
  {
    label: "入口管理",
    icon: ArrowLeftEndOnRectangleIcon,
    items: [
      { label: "客户端配置", path: "/ingress", icon: UsersIcon, description: "WireGuard 客户端" }
    ]
  },
  {
    label: "出口管理",
    icon: ArrowRightStartOnRectangleIcon,
    items: [
      { label: "出口线路", path: "/egress", icon: ServerIcon, description: "PIA 和自定义出口" },
      { label: "路由规则", path: "/rules", icon: AdjustmentsHorizontalIcon, description: "流量分流配置" },
      { label: "规则库", path: "/domain-catalog", icon: RectangleStackIcon, description: "域名和IP分流" }
    ]
  },
  {
    label: "系统设置",
    icon: WrenchScrewdriverIcon,
    items: [
      { label: "PIA 登录", path: "/pia", icon: LockClosedIcon, description: "凭证管理" },
      { label: "端点配置", path: "/endpoints", icon: CogIcon, description: "WireGuard 参数" },
      { label: "备份恢复", path: "/backup", icon: CloudArrowUpIcon, description: "配置导入导出" }
    ]
  }
];

interface LayoutProps extends PropsWithChildren {
  currentPath: string;
}

export default function Layout({ children, currentPath }: LayoutProps) {
  // Initialize expanded groups based on current path
  const getInitialExpanded = () => {
    const expanded: Set<string> = new Set();
    navGroups.forEach((group) => {
      if (group.items.some((item) => currentPath === item.path || (item.path !== "/" && currentPath.startsWith(item.path)))) {
        expanded.add(group.label);
      }
    });
    // Default expand first group if nothing is active
    if (expanded.size === 0 && navGroups.length > 0) {
      expanded.add(navGroups[0].label);
    }
    return expanded;
  };

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(getInitialExpanded);

  const toggleGroup = (label: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(label)) {
        next.delete(label);
      } else {
        next.add(label);
      }
      return next;
    });
  };

  const isItemActive = (item: NavItem) => {
    return currentPath === item.path || (item.path !== "/" && currentPath.startsWith(item.path));
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      {/* Decorative background elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 -left-4 w-96 h-96 bg-brand/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 -right-4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative flex max-w-7xl mx-auto gap-6 px-6 py-8">
        <aside className="w-72 flex-shrink-0 h-fit sticky top-8">
          <div className="rounded-3xl bg-gradient-to-br from-slate-900/90 to-slate-900/70 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/40">
            {/* Logo Section */}
            <div className="mb-8 pb-6 border-b border-white/5">
              <div className="flex items-center gap-3">
                <div className="rounded-2xl bg-gradient-to-br from-brand to-blue-600 p-2.5 shadow-lg shadow-brand/20">
                  <ShieldCheckIcon className="h-7 w-7 text-white" />
                </div>
                <div>
                  <p className="text-xs uppercase tracking-widest text-slate-400 font-semibold">Smart VPN</p>
                  <h1 className="text-xl font-bold text-white">网关控制台</h1>
                </div>
              </div>
            </div>

            {/* Navigation */}
            <nav className="space-y-1">
              {/* Standalone items */}
              {standaloneItems.map((item) => {
                const active = isItemActive(item);
                const Icon = item.icon;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    className={`group flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm font-medium transition-all duration-200 ${
                      active
                        ? "bg-gradient-to-r from-brand to-blue-600 text-white shadow-lg shadow-brand/25"
                        : "text-slate-400 hover:text-white hover:bg-white/5"
                    }`}
                  >
                    <div className={`rounded-lg p-1.5 transition-colors ${
                      active ? "bg-white/20" : "bg-white/5 group-hover:bg-white/10"
                    }`}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <span className="font-semibold">{item.label}</span>
                  </Link>
                );
              })}

              {/* Grouped items */}
              {navGroups.map((group) => {
                const GroupIcon = group.icon;
                const isExpanded = expandedGroups.has(group.label);
                const hasActiveItem = group.items.some(isItemActive);

                return (
                  <div key={group.label} className="pt-2">
                    {/* Group Header */}
                    <button
                      onClick={() => toggleGroup(group.label)}
                      className={`w-full flex items-center gap-3 rounded-xl px-4 py-2.5 text-sm font-medium transition-all duration-200 ${
                        hasActiveItem
                          ? "text-white bg-white/5"
                          : "text-slate-400 hover:text-white hover:bg-white/5"
                      }`}
                    >
                      <div className={`rounded-lg p-1.5 transition-colors ${
                        hasActiveItem ? "bg-brand/20" : "bg-white/5"
                      }`}>
                        <GroupIcon className="h-4 w-4" />
                      </div>
                      <span className="flex-1 text-left font-semibold">{group.label}</span>
                      <ChevronDownIcon
                        className={`h-4 w-4 transition-transform duration-200 ${
                          isExpanded ? "rotate-180" : ""
                        }`}
                      />
                    </button>

                    {/* Group Items */}
                    <div
                      className={`overflow-hidden transition-all duration-200 ${
                        isExpanded ? "max-h-96 opacity-100" : "max-h-0 opacity-0"
                      }`}
                    >
                      <div className="ml-4 mt-1 space-y-0.5 border-l border-white/10 pl-4">
                        {group.items.map((item) => {
                          const active = isItemActive(item);
                          const Icon = item.icon;
                          return (
                            <Link
                              key={item.path}
                              to={item.path}
                              className={`group flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-all duration-200 ${
                                active
                                  ? "bg-brand/20 text-white"
                                  : "text-slate-400 hover:text-white hover:bg-white/5"
                              }`}
                            >
                              <Icon className={`h-4 w-4 ${active ? "text-brand" : ""}`} />
                              <div className="flex-1">
                                <div className="font-medium">{item.label}</div>
                                <div className={`text-xs ${active ? "text-slate-300" : "text-slate-500"}`}>
                                  {item.description}
                                </div>
                              </div>
                            </Link>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}
            </nav>

            {/* Footer Info */}
            <div className="mt-8 pt-6 border-t border-white/5">
              <div className="rounded-xl bg-white/5 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-semibold text-slate-300">系统在线</span>
                </div>
                <p className="text-xs text-slate-500">基于 sing-box</p>
              </div>
            </div>
          </div>
        </aside>

        <main className="flex-1 min-h-[calc(100vh-4rem)]">
          <div className="rounded-3xl bg-slate-900/60 backdrop-blur-xl border border-white/10 px-8 py-10 shadow-2xl shadow-black/40">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
