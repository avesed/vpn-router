import React, { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter, Navigate } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import App from "./App";
import "./index.css";
import "./i18n";

// Lazy load all page components for code splitting
const Dashboard = lazy(() => import("./pages/Dashboard"));
const PiaLogin = lazy(() => import("./pages/PiaLogin"));
const EgressManager = lazy(() => import("./pages/EgressManager"));
const RouteRules = lazy(() => import("./pages/RouteRules"));
const DomainCatalog = lazy(() => import("./pages/DomainCatalog"));
const IpCatalog = lazy(() => import("./pages/IpCatalog"));
const IngressManager = lazy(() => import("./pages/IngressManager"));
const V2RayIngressManager = lazy(() => import("./pages/V2RayIngressManager"));
const PeerManager = lazy(() => import("./pages/PeerManager"));
const ChainManager = lazy(() => import("./pages/ChainManager"));
const TopologyView = lazy(() => import("./pages/TopologyView"));
const BackupRestore = lazy(() => import("./pages/BackupRestore"));
const AdBlock = lazy(() => import("./pages/AdBlock"));
const Login = lazy(() => import("./pages/Login"));
const Setup = lazy(() => import("./pages/Setup"));

// Loading fallback component
const PageLoader = () => (
  <div className="flex items-center justify-center min-h-screen">
    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
  </div>
);

const router = createBrowserRouter([
  // Public routes
  { path: "/login", element: <Suspense fallback={<PageLoader />}><Login /></Suspense> },
  { path: "/setup", element: <Suspense fallback={<PageLoader />}><Setup /></Suspense> },

  // Protected routes
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <App />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Suspense fallback={<PageLoader />}><Dashboard /></Suspense> },
      { path: "ingress", element: <Suspense fallback={<PageLoader />}><IngressManager /></Suspense> },
      { path: "ingress-v2ray", element: <Suspense fallback={<PageLoader />}><V2RayIngressManager /></Suspense> },
      { path: "peers", element: <Suspense fallback={<PageLoader />}><PeerManager /></Suspense> },
      { path: "chains", element: <Suspense fallback={<PageLoader />}><ChainManager /></Suspense> },
      { path: "topology", element: <Suspense fallback={<PageLoader />}><TopologyView /></Suspense> },
      { path: "egress", element: <Suspense fallback={<PageLoader />}><EgressManager /></Suspense> },
      { path: "profiles", element: <Navigate to="/egress" replace /> },
      { path: "rules", element: <Suspense fallback={<PageLoader />}><RouteRules /></Suspense> },
      { path: "domain-catalog", element: <Suspense fallback={<PageLoader />}><DomainCatalog /></Suspense> },
      { path: "ip-catalog", element: <Suspense fallback={<PageLoader />}><IpCatalog /></Suspense> },
      { path: "adblock", element: <Suspense fallback={<PageLoader />}><AdBlock /></Suspense> },
      { path: "pia", element: <Suspense fallback={<PageLoader />}><PiaLogin /></Suspense> },
      { path: "backup", element: <Suspense fallback={<PageLoader />}><BackupRestore /></Suspense> }
    ]
  }
]);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </React.StrictMode>
);
