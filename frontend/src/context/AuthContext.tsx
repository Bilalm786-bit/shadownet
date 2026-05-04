import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authAPI } from '../api/client';

interface User { id: string; username: string; email: string; role: string; full_name?: string; }
interface AuthCtx {
  user: User | null; token: string | null; loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  register: (data: { email: string; username: string; password: string; full_name?: string }) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthCtx>({} as AuthCtx);
export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('shadownet_token'));
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (token) {
      authAPI.me().then(r => { setUser(r.data); setLoading(false); })
        .catch(() => { localStorage.removeItem('shadownet_token'); setToken(null); setLoading(false); });
    } else { setLoading(false); }
  }, [token]);

  const login = async (username: string, password: string) => {
    const res = await authAPI.login(username, password);
    localStorage.setItem('shadownet_token', res.data.access_token);
    setToken(res.data.access_token);
  };

  const register = async (data: { email: string; username: string; password: string; full_name?: string }) => {
    await authAPI.register(data);
  };

  const logout = () => {
    localStorage.removeItem('shadownet_token');
    localStorage.removeItem('shadownet_user');
    setToken(null); setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
