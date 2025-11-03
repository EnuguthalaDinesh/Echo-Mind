import React, { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import Topbar from "../ui/Topbar";
import Sidebar from "../ui/Sidebar";
import MessageList from "../ui/MessageList";
import ChatInput from "../ui/ChatInput";
import FAQDrawer from "../ui/FAQDrawer";
import TypingIndicator from "../ui/TypingIndicator";
import { sendChat } from "../services/api";

export default function Chat() {
  const { domain } = useParams();
  const [openFAQ, setOpenFAQ] = useState(false);
  const [conversations, setConversations] = useState([
    { id: "conv-1", title: "New conversation", domain },
  ]);
  const [activeId, setActiveId] = useState("conv-1");
  const [messagesByConv, setMessagesByConv] = useState({ "conv-1": [] });
  const [isTyping, setIsTyping] = useState(false);
  const scrollerRef = useRef(null);

  const messages = messagesByConv[activeId] || [];

  const addMessage = (msg) => {
    setMessagesByConv((prev) => ({
      ...prev,
      [activeId]: [...(prev[activeId] || []), msg],
    }));
  };

  const handleSend = async (text) => {
    if (!text.trim()) return;
    addMessage({ id: crypto.randomUUID(), role: "user", text });
    setIsTyping(true);
    try {
      const reply = await sendChat({ domain, message: text });
      addMessage({ id: crypto.randomUUID(), role: "assistant", text: reply });
    } catch (e) {
      addMessage({ id: crypto.randomUUID(), role: "assistant", text: "Sorry, I had trouble answering. Please try again." });
    } finally {
      setIsTyping(false);
      setTimeout(() => {
        scrollerRef.current?.scrollTo({ top: scrollerRef.current.scrollHeight, behavior: "smooth" });
      }, 50);
    }
  };

  const createConversation = () => {
    const id = `conv-${crypto.randomUUID().slice(0, 8)}`;
    setConversations((c) => [{ id, title: "New conversation", domain }, ...c]);
    setMessagesByConv((m) => ({ ...m, [id]: [] }));
    setActiveId(id);
  };

  useEffect(() => { document.title = `Chat • ${domain}`; }, [domain]);

  return (
    <div className="h-screen flex">
      <Sidebar
        conversations={conversations}
        activeId={activeId}
        setActiveId={setActiveId}
        createConversation={createConversation}
      />
      <div className="flex-1 flex flex-col">
        <Topbar domain={domain} onOpenFAQ={() => setOpenFAQ(true)} />
        <div className="flex-1 overflow-y-auto" ref={scrollerRef}>
          <MessageList messages={messages} />
          {isTyping && <TypingIndicator />}
        </div>
        <ChatInput onSend={handleSend} />
      </div>
      <FAQDrawer open={openFAQ} onClose={() => setOpenFAQ(false)} />
    </div>
  );
}
