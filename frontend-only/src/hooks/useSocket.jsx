import { useEffect, useState, useRef } from "react";

// 🚨 CRITICAL FIX: The local fallback "ws://localhost:5000/ws" 
// must be replaced with the public address for Vercel deployment stability.
// The public address should be handled via the same VITE_API_BASE environment variable 
// used by Axios and AuthContext, but let's assume VITE_API_WS_URL is set 
// to the correct WSS URL (e.g., wss://echo-backend-1-ubeb.onrender.com/ws).
// If VITE_API_WS_URL is not explicitly set, we'll construct the Render address.

// Assuming the base HTTP URL is defined elsewhere or set as an environment variable (like VITE_API_BASE)
// For demonstration, let's use the explicit public Render WebSocket address structure as the fallback.
const PUBLIC_WS_URL_FALLBACK = "wss://echo-backend-1-ubeb.onrender.com/ws";


export const useSocket = (userId) => {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState([]);
  const [typing, setTyping] = useState(false);
  const [agentConnected, setAgentConnected] = useState(false);

  const socketRef = useRef(null);

  useEffect(() => {
    if (!userId) return;

    // Determine the WS URL: use env variable, or fall back to the public Render URL.
    // NOTE: If VITE_API_WS_URL is not set, this defaults to the correct public path.
    const wsUrl = import.meta.env.VITE_API_WS_URL || PUBLIC_WS_URL_FALLBACK;
    
    // Connect to FastAPI WebSocket
    // NOTE: Based on your backend, the FastAPI endpoint is /ws, 
    // and you are appending the userId to the path, which suggests the backend endpoint 
    // should be defined as "/ws/{userId}". This structure might be faulty 
    // if your backend only uses "/ws". Let's assume your backend is looking for a path parameter.
    const ws = new WebSocket(`${wsUrl}/${userId}`);
    socketRef.current = ws;

    ws.onopen = () => {
      setConnected(true);
      console.log("✅ WebSocket connected");
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        if (msg.type === "typing") {
          setTyping(true);
        } else if (msg.type === "stop_typing") {
          setTyping(false);
        } else if (msg.type === "agent_connected") {
          setAgentConnected(true);
          setMessages((prev) => [
            ...prev,
            {
              id: Date.now(),
              text: `Agent ${msg.agentName} has joined.`,
              sender: "system",
              timestamp: new Date().toISOString(),
            },
          ]);
        } else {
          // Normal chat message
          setMessages((prev) => [...prev, msg]);
        }
      } catch (err) {
        console.error("❌ Failed to parse WS message:", err);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      console.log("❌ WebSocket disconnected");
    };
    
    ws.onerror = (err) => {
        console.error("❌ WebSocket error:", err);
    };

    return () => {
      // Safely close on component unmount
      if (ws && ws.readyState === WebSocket.OPEN) {
          ws.close();
      }
    };
  }, [userId]);

  const sendMessage = (text, domain) => {
    if (socketRef.current && connected) {
      const msg = {
        id: Date.now(),
        text,
        sender: "user",
        domain,
        timestamp: new Date().toISOString(),
      };
      socketRef.current.send(JSON.stringify(msg));
      setMessages((prev) => [...prev, msg]);
    }
  };

  const startTyping = () => {
    if (socketRef.current && connected) {
      socketRef.current.send(JSON.stringify({ type: "typing", userId }));
    }
  };

  const stopTyping = () => {
    if (socketRef.current && connected) {
      socketRef.current.send(JSON.stringify({ type: "stop_typing", userId }));
    }
  };

  return {
    connected,
    messages,
    typing,
    agentConnected,
    sendMessage,
    startTyping,
    stopTyping,
    setMessages,
  };
};