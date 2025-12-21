import React from "react";
import ReactDOM from "react-dom/client";
import { RouterProvider, createBrowserRouter, Navigate } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import App from "./App";
import Dashboard from "./pages/Dashboard";
import Endpoints from "./pages/Endpoints";
import PiaLogin from "./pages/PiaLogin";
import EgressManager from "./pages/EgressManager";
import RouteRules from "./pages/RouteRules";
import DomainCatalog from "./pages/DomainCatalog";
import IpCatalog from "./pages/IpCatalog";
import IngressManager from "./pages/IngressManager";
import V2RayIngressManager from "./pages/V2RayIngressManager";
import BackupRestore from "./pages/BackupRestore";
import AdBlock from "./pages/AdBlock";
import Login from "./pages/Login";
import Setup from "./pages/Setup";
import "./index.css";
import "./i18n";

const router = createBrowserRouter([
  // Public routes
  { path: "/login", element: <Login /> },
  { path: "/setup", element: <Setup /> },

  // Protected routes
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <App />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Dashboard /> },
      { path: "ingress", element: <IngressManager /> },
      { path: "ingress-v2ray", element: <V2RayIngressManager /> },
      { path: "egress", element: <EgressManager /> },
      { path: "profiles", element: <Navigate to="/egress" replace /> },
      { path: "rules", element: <RouteRules /> },
      { path: "domain-catalog", element: <DomainCatalog /> },
      { path: "ip-catalog", element: <IpCatalog /> },
      { path: "adblock", element: <AdBlock /> },
      { path: "endpoints", element: <Endpoints /> },
      { path: "pia", element: <PiaLogin /> },
      { path: "backup", element: <BackupRestore /> }
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
