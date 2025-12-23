import { PropsWithChildren, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  ChartBarIcon,
  LockClosedIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  AdjustmentsHorizontalIcon,
  RectangleStackIcon,
  ChevronDownIcon,
  ArrowRightStartOnRectangleIcon,
  ArrowLeftEndOnRectangleIcon,
  ArrowRightOnRectangleIcon,
  WrenchScrewdriverIcon,
  UsersIcon,
  ServerIcon,
  CloudArrowUpIcon,
  EllipsisHorizontalIcon,
  XMarkIcon
} from "@heroicons/react/24/outline";
import LanguageSwitcher from "./LanguageSwitcher";
import { useAuth } from "../contexts/AuthContext";

interface NavItem {
  labelKey: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  descriptionKey: string;
}

interface NavGroup {
  labelKey: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
}

const standaloneItems: NavItem[] = [
  { labelKey: "nav.dashboard", path: "/", icon: ChartBarIcon, descriptionKey: "nav.dashboardDesc" }
];

const navGroups: NavGroup[] = [
  {
    labelKey: "nav.ingress",
    icon: ArrowLeftEndOnRectangleIcon,
    items: [
      { labelKey: "nav.ingressClient", path: "/ingress", icon: UsersIcon, descriptionKey: "nav.ingressClientDesc" },
      { labelKey: "nav.v2rayIngress", path: "/ingress-v2ray", icon: ServerIcon, descriptionKey: "nav.v2rayIngressDesc" }
    ]
  },
  {
    labelKey: "nav.egress",
    icon: ArrowRightStartOnRectangleIcon,
    items: [
      { labelKey: "nav.egressLines", path: "/egress", icon: ServerIcon, descriptionKey: "nav.egressLinesDesc" },
      { labelKey: "nav.routeRules", path: "/rules", icon: AdjustmentsHorizontalIcon, descriptionKey: "nav.routeRulesDesc" },
      { labelKey: "nav.ruleCatalog", path: "/domain-catalog", icon: RectangleStackIcon, descriptionKey: "nav.ruleCatalogDesc" },
      { labelKey: "nav.adblock", path: "/adblock", icon: ShieldExclamationIcon, descriptionKey: "nav.adblockDesc" }
    ]
  },
  {
    labelKey: "nav.system",
    icon: WrenchScrewdriverIcon,
    items: [
      { labelKey: "nav.piaLogin", path: "/pia", icon: LockClosedIcon, descriptionKey: "nav.piaLoginDesc" },
      { labelKey: "nav.backup", path: "/backup", icon: CloudArrowUpIcon, descriptionKey: "nav.backupDesc" }
    ]
  }
];

// Mobile bottom navigation items
interface BottomNavItem {
  labelKey: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}

const bottomNavItems: BottomNavItem[] = [
  { labelKey: "nav.dashboard", path: "/", icon: ChartBarIcon },
  { labelKey: "nav.egress", path: "/egress", icon: ArrowRightStartOnRectangleIcon },
  { labelKey: "nav.routeRules", path: "/rules", icon: AdjustmentsHorizontalIcon }
];

// Ingress submenu items
const ingressMenuItems: BottomNavItem[] = [
  { labelKey: "nav.ingressClient", path: "/ingress", icon: UsersIcon },
  { labelKey: "nav.v2rayIngress", path: "/ingress-v2ray", icon: ServerIcon }
];

// "More" menu items
const moreMenuItems: BottomNavItem[] = [
  { labelKey: "nav.ruleCatalog", path: "/domain-catalog", icon: RectangleStackIcon },
  { labelKey: "nav.adblock", path: "/adblock", icon: ShieldExclamationIcon },
  { labelKey: "nav.piaLogin", path: "/pia", icon: LockClosedIcon },
  { labelKey: "nav.backup", path: "/backup", icon: CloudArrowUpIcon }
];

interface LayoutProps extends PropsWithChildren {
  currentPath: string;
}

export default function Layout({ children, currentPath }: LayoutProps) {
  const { t } = useTranslation();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [showMoreMenu, setShowMoreMenu] = useState(false);
  const [showIngressMenu, setShowIngressMenu] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  // Initialize expanded groups based on current path
  const getInitialExpanded = () => {
    const expanded: Set<string> = new Set();
    navGroups.forEach((group) => {
      if (group.items.some((item) => {
        if (currentPath === item.path) return true;
        if (item.path === "/") return false;
        return currentPath.startsWith(item.path + "/");
      })) {
        expanded.add(group.labelKey);
      }
    });
    // Default expand first group if nothing is active
    if (expanded.size === 0 && navGroups.length > 0) {
      expanded.add(navGroups[0].labelKey);
    }
    return expanded;
  };

  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(getInitialExpanded);

  const toggleGroup = (labelKey: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(labelKey)) {
        next.delete(labelKey);
      } else {
        next.add(labelKey);
      }
      return next;
    });
  };

  const isItemActive = (item: NavItem | BottomNavItem) => {
    if (currentPath === item.path) return true;
    if (item.path === "/") return false;
    // Add trailing slash to prevent /ingress matching /ingress-v2ray
    return currentPath.startsWith(item.path + "/");
  };

  // Check if any item in ingress menu is active
  const isIngressMenuActive = ingressMenuItems.some(item => isItemActive(item));

  // Check if any item in "more" menu is active
  const isMoreMenuActive = moreMenuItems.some(item => isItemActive(item));

  const handleIngressMenuItemClick = (path: string) => {
    setShowIngressMenu(false);
    navigate(path);
  };

  const handleMoreMenuItemClick = (path: string) => {
    setShowMoreMenu(false);
    navigate(path);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      {/* Decorative background elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 left-0 w-96 h-96 bg-brand/5 rounded-full blur-3xl -translate-x-4" />
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl translate-x-4" />
      </div>

      <div className="relative flex max-w-7xl mx-auto gap-6 px-2 md:px-6 py-2 md:py-8 w-full">
        {/* Desktop Sidebar - Hidden on mobile */}
        <aside className="hidden md:block w-72 flex-shrink-0 h-fit sticky top-8">
          <div className="rounded-3xl bg-gradient-to-br from-slate-900/90 to-slate-900/70 backdrop-blur-xl border border-white/10 p-6 shadow-2xl shadow-black/40">
            {/* Logo Section */}
            <div className="mb-8 pb-6 border-b border-white/5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="rounded-2xl bg-gradient-to-br from-brand to-blue-600 p-2.5 shadow-lg shadow-brand/20">
                    <ShieldCheckIcon className="h-7 w-7 text-white" />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-widest text-slate-400 font-semibold">{t('nav.brand')}</p>
                    <h1 className="text-xl font-bold text-white">{t('nav.title')}</h1>
                  </div>
                </div>
                <LanguageSwitcher />
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
                    <span className="font-semibold">{t(item.labelKey)}</span>
                  </Link>
                );
              })}

              {/* Grouped items */}
              {navGroups.map((group) => {
                const GroupIcon = group.icon;
                const isExpanded = expandedGroups.has(group.labelKey);
                const hasActiveItem = group.items.some(isItemActive);

                return (
                  <div key={group.labelKey} className="pt-2">
                    {/* Group Header */}
                    <button
                      onClick={() => toggleGroup(group.labelKey)}
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
                      <span className="flex-1 text-left font-semibold">{t(group.labelKey)}</span>
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
                                <div className="font-medium">{t(item.labelKey)}</div>
                                <div className={`text-xs ${active ? "text-slate-300" : "text-slate-500"}`}>
                                  {t(item.descriptionKey)}
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
              <div className="rounded-xl bg-white/5 p-3 mb-3">
                <div className="flex items-center gap-2 mb-1">
                  <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-xs font-semibold text-slate-300">{t('nav.systemOnline')}</span>
                </div>
                <p className="text-xs text-slate-500">{t('nav.poweredBy')}</p>
              </div>

              {/* Logout Button */}
              <button
                onClick={handleLogout}
                className="w-full flex items-center gap-2 rounded-xl px-4 py-2.5 text-sm font-medium text-slate-400 hover:text-white hover:bg-white/5 transition-all duration-200"
              >
                <ArrowRightOnRectangleIcon className="h-4 w-4" />
                <span>{t('auth.logout')}</span>
              </button>
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 min-w-0 max-w-full min-h-[calc(100vh-4rem)] pb-20 md:pb-0">
          {/* Mobile Header */}
          <div className="md:hidden mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="rounded-xl bg-gradient-to-br from-brand to-blue-600 p-2 shadow-lg shadow-brand/20">
                <ShieldCheckIcon className="h-5 w-5 text-white" />
              </div>
              <div>
                <h1 className="text-sm font-bold text-white">{t('nav.title')}</h1>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <LanguageSwitcher />
              <button
                onClick={handleLogout}
                className="rounded-lg p-2 text-slate-400 hover:text-white hover:bg-white/5 transition-colors"
                title={t('auth.logout')}
              >
                <ArrowRightOnRectangleIcon className="h-5 w-5" />
              </button>
            </div>
          </div>

          <div className="rounded-xl md:rounded-3xl bg-slate-900/60 backdrop-blur-xl border border-white/10 px-3 py-4 md:px-8 md:py-10 shadow-2xl shadow-black/40 max-w-full">
            {children}
          </div>
        </main>
      </div>

      {/* Mobile Bottom Navigation */}
      <nav className="fixed bottom-0 left-0 right-0 z-50 md:hidden bg-slate-900/95 backdrop-blur-xl border-t border-white/10 safe-area-bottom">
        <div className="flex justify-around items-center h-16 px-1">
          {/* Dashboard */}
          <Link
            to="/"
            onClick={() => {
              setShowIngressMenu(false);
              setShowMoreMenu(false);
            }}
            className={`flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200 ${
              currentPath === "/"
                ? "text-brand bg-brand/10"
                : "text-slate-400 active:bg-white/5"
            }`}
          >
            <ChartBarIcon className="h-6 w-6 mb-0.5" />
            <span className="text-[10px] font-medium truncate max-w-[56px]">{t('nav.dashboard')}</span>
          </Link>

          {/* Ingress button with submenu */}
          <button
            onClick={() => {
              setShowIngressMenu(!showIngressMenu);
              setShowMoreMenu(false);
            }}
            className={`flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200 ${
              isIngressMenuActive || showIngressMenu
                ? "text-brand bg-brand/10"
                : "text-slate-400 active:bg-white/5"
            }`}
          >
            <ArrowLeftEndOnRectangleIcon className="h-6 w-6 mb-0.5" />
            <span className="text-[10px] font-medium">{t('nav.ingress')}</span>
          </button>

          {/* Other nav items */}
          {bottomNavItems.slice(1).map((item) => {
            const active = isItemActive(item);
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => {
                  setShowIngressMenu(false);
                  setShowMoreMenu(false);
                }}
                className={`flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200 ${
                  active
                    ? "text-brand bg-brand/10"
                    : "text-slate-400 active:bg-white/5"
                }`}
              >
                <Icon className="h-6 w-6 mb-0.5" />
                <span className="text-[10px] font-medium truncate max-w-[56px]">{t(item.labelKey)}</span>
              </Link>
            );
          })}

          {/* More button */}
          <button
            onClick={() => {
              setShowMoreMenu(!showMoreMenu);
              setShowIngressMenu(false);
            }}
            className={`flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200 ${
              isMoreMenuActive || showMoreMenu
                ? "text-brand bg-brand/10"
                : "text-slate-400 active:bg-white/5"
            }`}
          >
            {showMoreMenu ? (
              <XMarkIcon className="h-6 w-6 mb-0.5" />
            ) : (
              <EllipsisHorizontalIcon className="h-6 w-6 mb-0.5" />
            )}
            <span className="text-[10px] font-medium">{t('nav.more')}</span>
          </button>
        </div>
      </nav>

      {/* Ingress Menu Popup */}
      {showIngressMenu && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/50 md:hidden"
            onClick={() => setShowIngressMenu(false)}
          />
          {/* Menu Panel */}
          <div className="fixed bottom-[72px] left-3 right-3 z-50 md:hidden bg-slate-800/95 backdrop-blur-xl rounded-2xl border border-white/10 shadow-2xl p-3 animate-slide-up safe-area-bottom">
            <div className="grid grid-cols-2 gap-2">
              {ingressMenuItems.map((item) => {
                const active = isItemActive(item);
                const Icon = item.icon;
                return (
                  <button
                    key={item.path}
                    onClick={() => handleIngressMenuItemClick(item.path)}
                    className={`flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl transition-colors duration-200 ${
                      active
                        ? "bg-brand/20 text-brand"
                        : "text-slate-300 hover:bg-white/5 active:bg-white/10"
                    }`}
                  >
                    <Icon className="h-6 w-6" />
                    <span className="text-xs font-medium text-center leading-tight">{t(item.labelKey)}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* More Menu Popup */}
      {showMoreMenu && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/50 md:hidden"
            onClick={() => setShowMoreMenu(false)}
          />
          {/* Menu Panel */}
          <div className="fixed bottom-[72px] left-3 right-3 z-50 md:hidden bg-slate-800/95 backdrop-blur-xl rounded-2xl border border-white/10 shadow-2xl p-3 animate-slide-up safe-area-bottom">
            <div className="grid grid-cols-3 gap-2">
              {moreMenuItems.map((item) => {
                const active = isItemActive(item);
                const Icon = item.icon;
                return (
                  <button
                    key={item.path}
                    onClick={() => handleMoreMenuItemClick(item.path)}
                    className={`flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl transition-colors duration-200 ${
                      active
                        ? "bg-brand/20 text-brand"
                        : "text-slate-300 hover:bg-white/5 active:bg-white/10"
                    }`}
                  >
                    <Icon className="h-6 w-6" />
                    <span className="text-xs font-medium text-center leading-tight">{t(item.labelKey)}</span>
                  </button>
                );
              })}
              {/* Logout in more menu */}
              <button
                onClick={() => {
                  setShowMoreMenu(false);
                  handleLogout();
                }}
                className="flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl text-rose-400 hover:bg-rose-500/10 active:bg-rose-500/20 transition-colors duration-200"
              >
                <ArrowRightOnRectangleIcon className="h-6 w-6" />
                <span className="text-xs font-medium text-center leading-tight">{t('auth.logout')}</span>
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
