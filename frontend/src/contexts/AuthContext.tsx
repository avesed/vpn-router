import { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface AuthState {
  isAuthenticated: boolean;
  isSetup: boolean;
  isLoading: boolean;
  token: string | null;
}

interface AuthContextType extends AuthState {
  login: (password: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const TOKEN_KEY = "vpn_gateway_token";
const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isSetup: true,
    isLoading: true,
    token: null,
  });

  useEffect(() => {
    checkAuthStatus();
  }, []);

  useEffect(() => {
    if (!state.token) return;

    // H2: 每 30 分钟刷新一次 token (从 12 小时缩短)
    const interval = setInterval(() => {
      refreshToken().catch(console.error);
    }, 30 * 60 * 1000);

    return () => clearInterval(interval);
  }, [state.token]);

  async function checkAuthStatus() {
    try {
      const response = await fetch(`${API_BASE}/auth/status`);
      const data = await response.json();

      const storedToken = localStorage.getItem(TOKEN_KEY);
      if (storedToken && data.is_setup) {
        const meResponse = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${storedToken}` },
        });

        if (meResponse.ok) {
          setState({
            isAuthenticated: true,
            isSetup: true,
            isLoading: false,
            token: storedToken,
          });
          return;
        } else {
          localStorage.removeItem(TOKEN_KEY);
        }
      }

      setState({
        isAuthenticated: false,
        isSetup: data.is_setup,
        isLoading: false,
        token: null,
      });
    } catch (error) {
      console.error("Auth status check failed:", error);
      // API 不可用时，假设未设置（显示设置页更安全）
      setState({
        isAuthenticated: false,
        isSetup: false,
        isLoading: false,
        token: null,
      });
    }
  }

  async function login(password: string) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json();
      // L16 修复: 记录认证失败（不记录密码）
      console.error(`Login failed: ${response.status}`, error.detail || "Unknown error");
      throw new Error(error.detail || "Login failed");
    }

    const data = await response.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setState({
      isAuthenticated: true,
      isSetup: true,
      isLoading: false,
      token: data.access_token,
    });
  }

  async function setup(password: string) {
    const response = await fetch(`${API_BASE}/auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json();
      // L16 修复: 记录设置失败
      console.error(`Setup failed: ${response.status}`, error.detail || "Unknown error");
      throw new Error(error.detail || "Setup failed");
    }

    const data = await response.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setState({
      isAuthenticated: true,
      isSetup: true,
      isLoading: false,
      token: data.access_token,
    });
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    setState({
      isAuthenticated: false,
      isSetup: true,
      isLoading: false,
      token: null,
    });
  }

  async function refreshToken() {
    if (!state.token) return;

    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { Authorization: `Bearer ${state.token}` },
    });

    if (response.ok) {
      const data = await response.json();
      localStorage.setItem(TOKEN_KEY, data.access_token);
      setState((prev) => ({ ...prev, token: data.access_token }));
    } else {
      // L16 修复: 记录 token 刷新失败
      console.warn(`Token refresh failed: ${response.status}, logging out`);
      logout();
    }
  }

  return (
    <AuthContext.Provider value={{ ...state, login, setup, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
