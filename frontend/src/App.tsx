import { Outlet, useLocation } from "react-router-dom";
import Layout from "./components/Layout";

export default function App() {
  const location = useLocation();
  return (
    <Layout currentPath={location.pathname}>
      <Outlet />
    </Layout>
  );
}
