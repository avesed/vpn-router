import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";

const TOKEN_KEY = "vpn_gateway_token";
const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

interface User {
  username: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isSetup: boolean;
  login: (password: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isSetup, setIsSetup] = useState(true);
  const [isLoading, setIsLoading] = useState(true);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setIsSetup(true);
  }, []);

  const refreshToken = useCallback(async () => {
    if (!token) return;

    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      logout();
      return;
    }

    const data = await response.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setToken(data.access_token);
  }, [token, logout]);

  const checkAuthStatus = useCallback(async () => {
    setIsLoading(true);
    try {
      const statusResponse = await fetch(`${API_BASE}/auth/status`);
      if (!statusResponse.ok) {
        throw new Error("Failed to fetch auth status");
      }
      const statusData = await statusResponse.json();
      const setup = Boolean(statusData.is_setup);
      setIsSetup(setup);

      const storedToken = localStorage.getItem(TOKEN_KEY);
      if (storedToken && setup && JWT_PATTERN.test(storedToken)) {
        const meResponse = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${storedToken}` },
        });

        if (meResponse.ok) {
          const meData = await meResponse.json();
          setToken(storedToken);
          setUser({ username: meData.username || "admin" });
          return;
        }

        localStorage.removeItem(TOKEN_KEY);
      } else if (storedToken) {
        localStorage.removeItem(TOKEN_KEY);
      }

      setToken(null);
      setUser(null);
    } catch {
      setIsSetup(false);
      setToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  useEffect(() => {
    if (!token) return;

    const interval = setInterval(() => {
      refreshToken().catch(() => logout());
    }, 30 * 60 * 1000);

    return () => clearInterval(interval);
  }, [token, refreshToken, logout]);

  const login = useCallback(async (password: string) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || "Login failed");
    }

    const data = await response.json();
    const newToken = data.access_token;

    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setUser({ username: "admin" });
    setIsSetup(true);
  }, []);

  const setup = useCallback(async (password: string) => {
    const response = await fetch(`${API_BASE}/auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || "Setup failed");
    }

    const data = await response.json();
    const newToken = data.access_token;

    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setUser({ username: "admin" });
    setIsSetup(true);
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token,
    isLoading,
    isSetup,
    login,
    setup,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
