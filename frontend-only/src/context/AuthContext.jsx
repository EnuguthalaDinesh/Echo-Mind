import React, { createContext, useContext, useState, useEffect } from "react";

// Create Auth Context
const AuthContext = createContext();

// Helper: safely get stored user from localStorage
const getStoredUser = () => {
  try {
    const stored = localStorage.getItem("user");
    // Ensure we retrieve and parse the role if available
    const parsedUser = stored ? JSON.parse(stored) : null;
    return parsedUser;
  } catch (err) {
    console.warn("Error parsing user from localStorage:", err);
    return null;
  }
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(getStoredUser());
  const [loading, setLoading] = useState(false);
  const [ws, setWs] = useState(null);

  // Save user to localStorage whenever it changes
  useEffect(() => {
    if (user) {
      localStorage.setItem("user", JSON.stringify(user));
    } else {
      localStorage.removeItem("user");
    }
  }, [user]);

  // Initialize WebSocket when user is logged in
  useEffect(() => {
    if (!user || !user.access_token) return;

    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${protocol}://localhost:8000/ws?token=${user.access_token}`);

    socket.onopen = () => console.log("✅ WebSocket connected");
    socket.onclose = () => console.log("❌ WebSocket closed");
    socket.onerror = (err) => console.error("WebSocket error:", err);
    socket.onmessage = (msg) => console.log("WebSocket message:", msg.data);

    setWs(socket);

    return () => {
      socket.close();
    };
  }, [user]);

  // --- Auth Functions ---
  const register = async (name, email, password) => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Registration failed");

      // Optional: fetch user info after registration (or use data.role if your register returns it)
      const userInfo = { id: data.customer_id, name, email, role: data.role || 'user' };
      setUser(userInfo);
      setLoading(false);
      return userInfo;
    } catch (err) {
      setLoading(false);
      throw err;
    }
  };

  const login = async (email, password) => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Login failed");

      // We assume the backend /login now returns {..., role: 'agent'|'admin'|'user'}
      const loggedInUser = {
        name: data.name,
        email: data.email,
        role: data.role || 'user', // <--- CAPTURING THE ROLE
        access_token: data.access_token,
        refresh_token: data.refresh_token,
      };

      // Since your original code had a separate /me fetch, I'll keep the logic simple
      // and assume all necessary fields (like role) are available directly in the /login response.
      // If /login only returns tokens, you would need the /me call below:
      /*
      const userInfoRes = await fetch("http://localhost:8000/me", {
        headers: { Authorization: `Bearer ${data.access_token}` },
      });
      const userInfo = await userInfoRes.json();
      const loggedInUser = { ...userInfo, access_token: data.access_token, refresh_token: data.refresh_token };
      */
      
      setUser(loggedInUser);
      setLoading(false);
      // Return the object containing the role for the Login component to use.
      return loggedInUser; 
    } catch (err) {
      setLoading(false);
      throw err;
    }
  };

  const logout = () => {
    setUser(null);
    setWs(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, register, login, logout, ws }}>
      {children}
    </AuthContext.Provider>
  );
};

// Hook for consuming AuthContext
export const useAuth = () => useContext(AuthContext);