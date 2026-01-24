import { useLocation, useNavigate, Outlet, Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  LayoutDashboard,
  Users,
  Server,
  ServerCog,
  Link2,
  Map,
  LogOut,
  ArrowLeftToLine,
  ArrowRightFromLine,
  Settings,
  ShieldCheck,
  CloudUpload,
  ShieldAlert,
  Sliders,
  Layers,
  Key,
  ChevronDown,
  Search,
  Languages,
  Scale,
  Shield,
} from "lucide-react";
import { MobileBottomNav } from "./MobileBottomNav";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarInset,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/providers/AuthProvider";
import { useCommandPalette } from "@/components/command-palette/CommandPaletteProvider";

interface NavItem {
  labelKey: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavGroup {
  labelKey: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItem[];
}

const standaloneItems: NavItem[] = [
  { labelKey: "nav.dashboard", path: "/", icon: LayoutDashboard },
];

const navGroups: NavGroup[] = [
  {
    labelKey: "nav.ingress",
    icon: ArrowLeftToLine,
    items: [
      { labelKey: "nav.ingressClient", path: "/ingress", icon: Users },
      { labelKey: "nav.v2rayIngress", path: "/ingress-v2ray", icon: Server },
      { labelKey: "nav.ssIngress", path: "/ingress-shadowsocks", icon: Shield },
      { labelKey: "nav.peerNodes", path: "/peers", icon: ServerCog },
      { labelKey: "nav.nodeChains", path: "/chains", icon: Link2 },
      { labelKey: "nav.topology", path: "/topology", icon: Map },
    ],
  },
  {
    labelKey: "nav.egress",
    icon: ArrowRightFromLine,
    items: [
      { labelKey: "nav.egressLines", path: "/egress", icon: Server },
      { labelKey: "nav.loadBalance", path: "/groups", icon: Scale },
      { labelKey: "nav.routeRules", path: "/rules", icon: Sliders },
      { labelKey: "nav.ruleCatalog", path: "/domain-catalog", icon: Layers },
      { labelKey: "nav.adblock", path: "/adblock", icon: ShieldAlert },
    ],
  },
  {
    labelKey: "nav.system",
    icon: Settings,
    items: [
      { labelKey: "nav.piaLogin", path: "/pia", icon: Key },
      { labelKey: "nav.backup", path: "/backup", icon: CloudUpload },
    ],
  },
];

function isPathActive(currentPath: string, itemPath: string): boolean {
  if (currentPath === itemPath) return true;
  if (itemPath === "/") return false;
  return currentPath.startsWith(itemPath + "/");
}

function AppSidebar() {
  const { t } = useTranslation();
  const location = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const currentPath = location.pathname;

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to="/">
                <div className="flex aspect-square size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                  <ShieldCheck className="size-4" />
                </div>
                <div className="flex flex-col gap-0.5 leading-none">
                  <span className="text-xs text-muted-foreground">
                    {t("nav.brand")}
                  </span>
                  <span className="font-semibold">{t("nav.title")}</span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              {standaloneItems.map((item) => {
                const Icon = item.icon;
                const active = isPathActive(currentPath, item.path);
                return (
                  <SidebarMenuItem key={item.path}>
                    <SidebarMenuButton asChild isActive={active}>
                      <Link to={item.path}>
                        <Icon className="size-4" />
                        <span>{t(item.labelKey)}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        {navGroups.map((group) => {
          const GroupIcon = group.icon;
          const hasActiveItem = group.items.some((item) =>
            isPathActive(currentPath, item.path)
          );

          return (
            <Collapsible
              key={group.labelKey}
              defaultOpen={hasActiveItem}
              className="group/collapsible"
            >
              <SidebarGroup>
                <SidebarGroupLabel asChild>
                  <CollapsibleTrigger className="flex w-full items-center">
                    <GroupIcon className="mr-2 size-4" />
                    {t(group.labelKey)}
                    <ChevronDown className="ml-auto size-4 transition-transform group-data-[state=open]/collapsible:rotate-180" />
                  </CollapsibleTrigger>
                </SidebarGroupLabel>
                <CollapsibleContent>
                  <SidebarGroupContent>
                    <SidebarMenu>
                      {group.items.map((item) => {
                        const Icon = item.icon;
                        const active = isPathActive(currentPath, item.path);
                        return (
                          <SidebarMenuItem key={item.path}>
                            <SidebarMenuButton asChild isActive={active}>
                              <Link to={item.path}>
                                <Icon className="size-4" />
                                <span>{t(item.labelKey)}</span>
                              </Link>
                            </SidebarMenuButton>
                          </SidebarMenuItem>
                        );
                      })}
                    </SidebarMenu>
                  </SidebarGroupContent>
                </CollapsibleContent>
              </SidebarGroup>
            </Collapsible>
          );
        })}
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton onClick={handleLogout}>
              <LogOut className="size-4" />
              <span>{t("auth.logout")}</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  );
}

export function AppLayout() {
  const { setOpen } = useCommandPalette();
  const { i18n, t } = useTranslation();

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4 justify-between">
          <div className="flex items-center gap-2">
            <SidebarTrigger className="-ml-1 hidden md:flex" />
            <Separator orientation="vertical" className="mr-2 h-4 hidden md:block" />
            {/* Mobile header - show brand on mobile */}
            <div className="flex md:hidden items-center gap-2">
              <div className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheck className="size-4" />
              </div>
              <span className="font-semibold">{t("nav.title")}</span>
            </div>
            {/* Desktop - show system status */}
            <div className="hidden md:flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-sm text-muted-foreground">{t("nav.systemOnline")}</span>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <Button 
              variant="outline" 
              size="sm" 
              className="w-full max-w-[200px] justify-start text-muted-foreground hidden md:flex"
              onClick={() => setOpen(true)}
            >
              <Search className="mr-2 h-4 w-4" />
              <span>{t("common.search")}...</span>
              <kbd className="pointer-events-none ml-auto inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground opacity-100">
                <span className="text-xs">⌘</span>K
              </kbd>
            </Button>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon">
                  <Languages className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => i18n.changeLanguage("en")}>
                  {t("language.en")}
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => i18n.changeLanguage("zh")}>
                  {t("language.zh")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6 pb-20 md:pb-6">
          <Outlet />
        </main>
      </SidebarInset>
      {/* Mobile bottom navigation */}
      <MobileBottomNav />
    </SidebarProvider>
  );
}
