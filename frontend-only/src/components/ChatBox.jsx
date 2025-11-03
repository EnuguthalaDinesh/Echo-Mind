import { useState } from "react";
import { sendChat } from "../api/chatbot";
import { useAuth } from "../context/AuthContext";

export default function ChatBox() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const { user } = useAuth();

  const handleSend = async () => {
    if (!input.trim()) return;
    const sessionId = crypto.randomUUID();
    const customerProfile = {
      customer_id: user?.id || "guest",
      previous_interactions: [],
      purchase_history: [],
      preference_settings: {},
      sentiment_history: [],
      active_case_id: null,
    };
    const res = await sendChat({
      user_query: input,
      session_id: sessionId,
      customer_profile: customerProfile,
      conversation_history: messages.map((m) => ({
        role: m.role,
        content: m.content,
        timestamp: new Date().toISOString(),
      })),
      domain: "general",
    });
    setMessages((prev) => [
      ...prev,
      { role: "customer", content: input },
      { role: "bot", content: res.data.bot_response },
    ]);
    setInput("");
  };

  return (
    <div style={{ maxWidth: 720, margin: "2rem auto" }}>
      <div style={{ border: "1px solid #ddd", minHeight: 240, padding: 16, borderRadius: 12 }}>
        {messages.map((m, idx) => (
          <p key={idx}><b>{m.role}:</b> {m.content}</p>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
        <input style={{ flex: 1 }} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Type your message..." />
        <button onClick={handleSend}>Send</button>
      </div>
    </div>
  );
}