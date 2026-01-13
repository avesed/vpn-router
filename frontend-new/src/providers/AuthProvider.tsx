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

interface User {
  username: string;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

interface AuthProviderProps {
  children: ReactNode;
}

export function AuthProvider({ children }: AuthProviderProps) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Check for existing token on mount
  useEffect(() => {
    const storedToken = localStorage.getItem(TOKEN_KEY);
    if (storedToken) {
      // Validate token format (JWT: header.payload.signature)
      const jwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
      if (jwtPattern.test(storedToken)) {
        setToken(storedToken);
        // Decode username from JWT payload
        try {
          const payload = JSON.parse(atob(storedToken.split(".")[1]));
          setUser({ username: payload.sub || "admin" });
        } catch {
          // Invalid token, clear it
          localStorage.removeItem(TOKEN_KEY);
        }
      } else {
        // Invalid format, clear it
        localStorage.removeItem(TOKEN_KEY);
      }
    }
    setIsLoading(false);
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(error || "Login failed");
    }

    const data = await response.json();
    const newToken = data.access_token;

    localStorage.setItem(TOKEN_KEY, newToken);
    setToken(newToken);
    setUser({ username });
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(TOKEN_KEY);
    setToken(null);
    setUser(null);
  }, []);

  const value: AuthContextType = {
    user,
    token,
    isAuthenticated: !!token,
    isLoading,
    login,
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
