// src/context/AuthContext.jsx

import React, { createContext, useState, useContext } from "react";
import axios from "axios";

// Create context
const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);           // Stores full user: { email, name, role, ... }
  const [accessToken, setAccessToken] = useState(""); // Optionally store access token

  // Login function - expects backend to return { access_token, role, ... }
  const login = async (email, password) => {
    const res = await axios.post("/login", { email, password });
    if (res.data && res.data.access_token) {
      setAccessToken(res.data.access_token);
      const userObj = {
        email: res.data.email,
        name: res.data.name,
        role: res.data.role,
        accessToken: res.data.access_token
      };
      setUser(userObj);
      // Optionally: localStorage.setItem("user", JSON.stringify(userObj));
      return userObj; // So LoginPage gets { ...user, role }
    }
    throw new Error("Invalid login response");
  };

  // Logout function
  const logout = () => {
    setUser(null);
    setAccessToken("");
    // Optionally: localStorage.removeItem("user");
  };

  // You can enhance this with registration, token refresh, etc.

  return (
    <AuthContext.Provider value={{ user, login, logout, accessToken }}>
      {children}
    </AuthContext.Provider>
  );
};

// Hook to use auth everywhere in the app
export const useAuth = () => useContext(AuthContext);

export default AuthContext;
