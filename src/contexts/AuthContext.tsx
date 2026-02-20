import { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface User {
  id: string;
  email: string;
  name: string;
  createdAt: string;
}

interface AuthContextType {
  user: User | null;
  signIn: (email: string, password: string) => Promise<{ error?: string }>;
  signUp: (email: string, password: string, name: string) => Promise<{ error?: string }>;
  signOut: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

const STORAGE_KEY = "netra_users";
const SESSION_KEY = "netra_session";

function getUsers(): Record<string, { password: string; name: string; createdAt: string }> {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const session = localStorage.getItem(SESSION_KEY);
    if (session) {
      try {
        setUser(JSON.parse(session));
      } catch {
        localStorage.removeItem(SESSION_KEY);
      }
    }
    setIsLoading(false);
  }, []);

  const signUp = async (email: string, password: string, name: string): Promise<{ error?: string }> => {
    await new Promise((r) => setTimeout(r, 600)); // simulate async
    const users = getUsers();
    const key = email.toLowerCase().trim();
    if (users[key]) return { error: "An account with this email already exists." };
    if (password.length < 6) return { error: "Password must be at least 6 characters." };

    const newUser: User = {
      id: crypto.randomUUID(),
      email: key,
      name: name.trim(),
      createdAt: new Date().toISOString(),
    };
    users[key] = { password, name: name.trim(), createdAt: newUser.createdAt };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(users));
    localStorage.setItem(SESSION_KEY, JSON.stringify(newUser));
    setUser(newUser);
    return {};
  };

  const signIn = async (email: string, password: string): Promise<{ error?: string }> => {
    await new Promise((r) => setTimeout(r, 600));
    const users = getUsers();
    const key = email.toLowerCase().trim();
    const record = users[key];
    if (!record) return { error: "No account found with this email." };
    if (record.password !== password) return { error: "Incorrect password." };

    const loggedIn: User = { id: crypto.randomUUID(), email: key, name: record.name, createdAt: record.createdAt };
    localStorage.setItem(SESSION_KEY, JSON.stringify(loggedIn));
    setUser(loggedIn);
    return {};
  };

  const signOut = () => {
    localStorage.removeItem(SESSION_KEY);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, signIn, signUp, signOut, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
