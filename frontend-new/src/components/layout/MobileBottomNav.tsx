import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  LayoutDashboard,
  Server,
  Sliders,
  ArrowLeftToLine,
  MoreHorizontal,
  X,
  Users,
  ServerCog,
  Link2,
  Map,
  Layers,
  ShieldAlert,
  Key,
  CloudUpload,
  LogOut,
  Scale,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/providers/AuthProvider";

interface NavItem {
  labelKey: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}

// Main bottom nav items
const mainNavItems: NavItem[] = [
  { labelKey: "nav.dashboard", path: "/", icon: LayoutDashboard },
  { labelKey: "nav.egressLines", path: "/egress", icon: Server },
  { labelKey: "nav.routeRules", path: "/rules", icon: Sliders },
];

// Ingress submenu items
const ingressMenuItems: NavItem[] = [
  { labelKey: "nav.ingressClient", path: "/ingress", icon: Users },
  { labelKey: "nav.v2rayIngress", path: "/ingress-v2ray", icon: Server },
  { labelKey: "nav.peerNodes", path: "/peers", icon: ServerCog },
  { labelKey: "nav.nodeChains", path: "/chains", icon: Link2 },
  { labelKey: "nav.topology", path: "/topology", icon: Map },
];

// "More" menu items
const moreMenuItems: NavItem[] = [
  { labelKey: "nav.loadBalance", path: "/groups", icon: Scale },
  { labelKey: "nav.ruleCatalog", path: "/domain-catalog", icon: Layers },
  { labelKey: "nav.adblock", path: "/adblock", icon: ShieldAlert },
  { labelKey: "nav.piaLogin", path: "/pia", icon: Key },
  { labelKey: "nav.backup", path: "/backup", icon: CloudUpload },
];

function isPathActive(currentPath: string, itemPath: string): boolean {
  if (currentPath === itemPath) return true;
  if (itemPath === "/") return false;
  return currentPath.startsWith(itemPath + "/");
}

export function MobileBottomNav() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const currentPath = location.pathname;

  const [showIngressMenu, setShowIngressMenu] = useState(false);
  const [showMoreMenu, setShowMoreMenu] = useState(false);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const closeMenus = () => {
    setShowIngressMenu(false);
    setShowMoreMenu(false);
  };

  const handleMenuItemClick = (path: string) => {
    closeMenus();
    navigate(path);
  };

  // Check if any item in ingress menu is active
  const isIngressMenuActive = ingressMenuItems.some(item => isPathActive(currentPath, item.path));

  // Check if any item in "more" menu is active
  const isMoreMenuActive = moreMenuItems.some(item => isPathActive(currentPath, item.path));

  return (
    <>
      {/* Bottom Navigation Bar */}
      <nav className="fixed bottom-0 left-0 right-0 z-50 md:hidden bg-background/95 backdrop-blur-xl border-t">
        <div className="flex justify-around items-center h-16 px-1 safe-area-bottom">
          {/* Dashboard */}
          <Link
            to="/"
            onClick={closeMenus}
            className={cn(
              "flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200",
              currentPath === "/"
                ? "text-primary bg-primary/10"
                : "text-muted-foreground active:bg-muted"
            )}
          >
            <LayoutDashboard className="h-6 w-6 mb-0.5" />
            <span className="text-[10px] font-medium truncate max-w-[56px]">
              {t("nav.dashboard")}
            </span>
          </Link>

          {/* Ingress button with submenu */}
          <button
            onClick={() => {
              setShowIngressMenu(!showIngressMenu);
              setShowMoreMenu(false);
            }}
            className={cn(
              "flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200",
              isIngressMenuActive || showIngressMenu
                ? "text-primary bg-primary/10"
                : "text-muted-foreground active:bg-muted"
            )}
          >
            <ArrowLeftToLine className="h-6 w-6 mb-0.5" />
            <span className="text-[10px] font-medium">{t("nav.ingress")}</span>
          </button>

          {/* Other nav items */}
          {mainNavItems.slice(1).map((item) => {
            const active = isPathActive(currentPath, item.path);
            const Icon = item.icon;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={closeMenus}
                className={cn(
                  "flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200",
                  active
                    ? "text-primary bg-primary/10"
                    : "text-muted-foreground active:bg-muted"
                )}
              >
                <Icon className="h-6 w-6 mb-0.5" />
                <span className="text-[10px] font-medium truncate max-w-[56px]">
                  {t(item.labelKey)}
                </span>
              </Link>
            );
          })}

          {/* More button */}
          <button
            onClick={() => {
              setShowMoreMenu(!showMoreMenu);
              setShowIngressMenu(false);
            }}
            className={cn(
              "flex flex-col items-center justify-center px-2 py-1.5 min-w-[56px] rounded-xl transition-colors duration-200",
              isMoreMenuActive || showMoreMenu
                ? "text-primary bg-primary/10"
                : "text-muted-foreground active:bg-muted"
            )}
          >
            {showMoreMenu ? (
              <X className="h-6 w-6 mb-0.5" />
            ) : (
              <MoreHorizontal className="h-6 w-6 mb-0.5" />
            )}
            <span className="text-[10px] font-medium">{t("nav.more", { defaultValue: "More" })}</span>
          </button>
        </div>
      </nav>

      {/* Ingress Menu Popup */}
      {showIngressMenu && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-40 bg-black/50 md:hidden"
            onClick={closeMenus}
          />
          {/* Menu Panel */}
          <div className="fixed bottom-[72px] left-3 right-3 z-50 md:hidden bg-card backdrop-blur-xl rounded-2xl border shadow-2xl p-3 animate-in slide-in-from-bottom-2 duration-200">
            <div className="grid grid-cols-2 gap-2">
              {ingressMenuItems.map((item) => {
                const active = isPathActive(currentPath, item.path);
                const Icon = item.icon;
                return (
                  <button
                    key={item.path}
                    onClick={() => handleMenuItemClick(item.path)}
                    className={cn(
                      "flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl transition-colors duration-200",
                      active
                        ? "bg-primary/20 text-primary"
                        : "text-foreground hover:bg-muted active:bg-muted"
                    )}
                  >
                    <Icon className="h-6 w-6" />
                    <span className="text-xs font-medium text-center leading-tight">
                      {t(item.labelKey)}
                    </span>
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
            onClick={closeMenus}
          />
          {/* Menu Panel */}
          <div className="fixed bottom-[72px] left-3 right-3 z-50 md:hidden bg-card backdrop-blur-xl rounded-2xl border shadow-2xl p-3 animate-in slide-in-from-bottom-2 duration-200">
            <div className="grid grid-cols-3 gap-2">
              {moreMenuItems.map((item) => {
                const active = isPathActive(currentPath, item.path);
                const Icon = item.icon;
                return (
                  <button
                    key={item.path}
                    onClick={() => handleMenuItemClick(item.path)}
                    className={cn(
                      "flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl transition-colors duration-200",
                      active
                        ? "bg-primary/20 text-primary"
                        : "text-foreground hover:bg-muted active:bg-muted"
                    )}
                  >
                    <Icon className="h-6 w-6" />
                    <span className="text-xs font-medium text-center leading-tight">
                      {t(item.labelKey)}
                    </span>
                  </button>
                );
              })}
              {/* Logout in more menu */}
              <button
                onClick={() => {
                  closeMenus();
                  handleLogout();
                }}
                className="flex flex-col items-center justify-center gap-1.5 px-2 py-3 rounded-xl text-destructive hover:bg-destructive/10 active:bg-destructive/20 transition-colors duration-200"
              >
                <LogOut className="h-6 w-6" />
                <span className="text-xs font-medium text-center leading-tight">
                  {t("auth.logout")}
                </span>
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}
