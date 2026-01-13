import React, { Suspense, lazy } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { QueryProvider } from "@/providers/QueryProvider";
import { AuthProvider, useAuth } from "@/providers/AuthProvider";
import { ThemeProvider } from "@/providers/ThemeProvider";
import { AppLayout } from "@/components/layout/AppLayout";
import { Toaster } from "@/components/ui/sonner";
import { CommandPaletteProvider } from "@/components/command-palette/CommandPaletteProvider";
import { CommandPalette } from "@/components/command-palette/CommandPalette";
import "@/i18n";
import "./index.css";
import { Loader2 } from "lucide-react";

// Lazy load pages
const LoginPage = lazy(() => import("@/pages/LoginPage").then(module => ({ default: module.LoginPage })));
const DashboardPage = lazy(() => import("@/pages/DashboardPage").then(module => ({ default: module.DashboardPage })));
const PeersPage = lazy(() => import("@/pages/PeersPage").then(module => ({ default: module.PeersPage })));
const EgressPage = lazy(() => import("@/pages/EgressPage"));
const ChainsPage = lazy(() => import("@/pages/ChainsPage"));
const RulesPage = lazy(() => import("@/pages/RulesPage"));
const IngressPage = lazy(() => import("@/pages/IngressPage"));
const V2RayIngressPage = lazy(() => import("@/pages/V2RayIngressPage"));
const AdBlockPage = lazy(() => import("@/pages/AdBlockPage"));
const PIAPage = lazy(() => import("@/pages/PIAPage"));
const BackupPage = lazy(() => import("@/pages/BackupPage"));
const TopologyPage = lazy(() => import("@/pages/TopologyPage"));
const DomainCatalogPage = lazy(() => import("@/pages/DomainCatalogPage"));

// Loading fallback
function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full min-h-[50vh]">
      <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
    </div>
  );
}

// Protected route wrapper
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-pulse text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function AppRoutes() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <AppLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="ingress" element={<IngressPage />} />
          <Route path="ingress-v2ray" element={<V2RayIngressPage />} />
          <Route path="peers" element={<PeersPage />} />
          <Route path="chains" element={<ChainsPage />} />
          <Route path="topology" element={<TopologyPage />} />
          <Route path="egress" element={<EgressPage />} />
          <Route path="rules" element={<RulesPage />} />
          <Route path="domain-catalog" element={<DomainCatalogPage />} />
          <Route path="adblock" element={<AdBlockPage />} />
          <Route path="pia" element={<PIAPage />} />
          <Route path="backup" element={<BackupPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}

function App() {
  return (
    <ThemeProvider defaultTheme="dark">
      <QueryProvider>
        <BrowserRouter>
          <AuthProvider>
            <CommandPaletteProvider>
              <AppRoutes />
              <CommandPalette />
              <Toaster />
            </CommandPaletteProvider>
          </AuthProvider>
        </BrowserRouter>
      </QueryProvider>
    </ThemeProvider>
  );
}

export default App;
