import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import { api } from "@/api/client";
import type { RegisterResponse } from "@/types";

const TOKEN_KEY = "vpn_gateway_token";
const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

export interface User {
  id: number;
  username: string;
  role: "admin" | "user" | "pending";
  email?: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isSetup: boolean;
  isAdmin: boolean;
  isPending: boolean;
  pendingUser: User | null;
  pendingCredentials: { username: string; password: string } | null;
  allowRegistration: boolean;
  registrationDefaultRole: "user" | "pending";
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  register: (username: string, password: string, email?: string) => Promise<RegisterResponse>;
  clearPending: () => void;
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

  // Pending user state
  const [isPending, setIsPending] = useState(false);
  const [pendingUser, setPendingUser] = useState<User | null>(null);
  const [pendingCredentials, setPendingCredentials] = useState<{ username: string; password: string } | null>(null);

  // Registration settings
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [registrationDefaultRole, setRegistrationDefaultRole] = useState<"user" | "pending">("pending");

  const clearPending = useCallback(() => {
    setIsPending(false);
    setPendingUser(null);
    setPendingCredentials(null);
  }, []);

  const logout = useCallback(async () => {
    // Call logout endpoint to revoke token
    if (token) {
      try {
        await fetch(`${API_BASE}/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Ignore errors during logout
      }
    }
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
    setIsSetup(true);
    clearPending();
  }, [token, clearPending]);

  const refreshToken = useCallback(async () => {
    if (!token) return;

    const response = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      await logout();
      return;
    }

    const data = await response.json();
    localStorage.setItem(TOKEN_KEY, data.access_token);
    setToken(data.access_token);
  }, [token, logout]);

  const fetchUserInfo = useCallback(async (authToken: string): Promise<User | null> => {
    try {
      const response = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });

      if (!response.ok) {
        return null;
      }

      const data = await response.json();
      return {
        id: data.user_id,
        username: data.username,
        role: data.role || "admin",
        email: data.email,
      };
    } catch {
      return null;
    }
  }, []);

  const refreshUser = useCallback(async () => {
    if (!token) return;
    const userInfo = await fetchUserInfo(token);
    if (userInfo) {
      setUser(userInfo);
    }
  }, [token, fetchUserInfo]);

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

      // Update registration settings from auth status
      setAllowRegistration(Boolean(statusData.allow_registration));
      setRegistrationDefaultRole(statusData.registration_default_role || "pending");

      const storedToken = localStorage.getItem(TOKEN_KEY);
      if (storedToken && setup && JWT_PATTERN.test(storedToken)) {
        const userInfo = await fetchUserInfo(storedToken);

        if (userInfo) {
          setToken(storedToken);
          setUser(userInfo);
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
  }, [fetchUserInfo]);

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

  const login = useCallback(async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || "Login failed");
    }

    const data = await response.json();

    // Check if response indicates pending status
    if (data.status === "pending") {
      setIsPending(true);
      setPendingUser(data.user || { id: 0, username, role: "pending" as const, enabled: true });
      setPendingCredentials({ username, password });
      // isAuthenticated is derived from token, no explicit setter needed
      return;
    }

    const newToken = data.access_token;

    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);

    // Fetch full user info
    const userInfo = await fetchUserInfo(newToken);
    if (userInfo) {
      setUser(userInfo);
    } else {
      // Fallback to basic user info from login response
      setUser({
        id: data.user_id || 1,
        username: data.username || username,
        role: data.role || "admin",
      });
    }
    setIsSetup(true);
  }, [fetchUserInfo]);

  const setup = useCallback(async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/auth/setup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.detail || "Setup failed");
    }

    const data = await response.json();
    const newToken = data.access_token;

    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setUser({
      id: 1,
      username: username,
      role: "admin",
    });
    setIsSetup(true);
  }, []);

  const register = useCallback(async (username: string, password: string, email?: string): Promise<RegisterResponse> => {
    const data = await api.register({ username, password, email });

    if (data.status === "pending") {
      setIsPending(true);
      setPendingUser({ id: 0, username, role: "pending", enabled: true } as User);
      setPendingCredentials({ username, password });
      return data;
    }

    // Direct user - auto login
    if (data.access_token) {
      localStorage.setItem(TOKEN_KEY, data.access_token);
      setToken(data.access_token);
      setUser(data.user || { id: 0, username, role: "user", enabled: true } as User);
      // isAuthenticated is derived from token, automatically set by setToken
    }

    return data;
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token,
    isLoading,
    isSetup,
    isAdmin: user?.role === "admin",
    isPending,
    pendingUser,
    pendingCredentials,
    allowRegistration,
    registrationDefaultRole,
    login,
    setup,
    logout,
    refreshUser,
    register,
    clearPending,
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
