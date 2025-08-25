import React, { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import Topbar from "../ui/Topbar";
import Sidebar from "../ui/Sidebar";
import MessageList from "../ui/MessageList";
import ChatInput from "../ui/ChatInput";
import FAQDrawer from "../ui/FAQDrawer";
import TypingIndicator from "../ui/TypingIndicator";
import { sendChat, fetchConversations, fetchConversationHistory } from "../services/api";
import { getCustomerId } from "../services/auth";

export default function Chat() {
  const { domain } = useParams();
  const [openFAQ, setOpenFAQ] = useState(false);
  const [conversations, setConversations] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [messagesByConv, setMessagesByConv] = useState({});
  const [isTyping, setIsTyping] = useState(false);
  const scrollerRef = useRef(null);
  const customerId = getCustomerId();

  const messages = messagesByConv[activeId] || [];

  useEffect(() => {
    async function loadConversations() {
      if (!customerId) return;
      try {
        const fetchedConversations = await fetchConversations(customerId);
        setConversations(fetchedConversations);
        if (fetchedConversations.length > 0) {
          const firstConv = fetchedConversations[0];
          setActiveId(firstConv.session_id);
          const history = await fetchConversationHistory(customerId, firstConv.session_id);
          setMessagesByConv({ [firstConv.session_id]: history.map(m => ({ id: crypto.randomUUID(), ...m, text: m.content })) });
        } else {
          createConversation();
        }
      } catch (e) {
        console.error("Failed to load conversations:", e);
        setConversations([]);
        createConversation();
      }
    }
    loadConversations();
  }, [customerId]);

  useEffect(() => {
    if (activeId) {
      document.title = `Chat • ${conversations.find(c => c.session_id === activeId)?.domain || domain}`;
    } else {
      document.title = `Chat • ${domain}`;
    }
  }, [domain, activeId, conversations]);

  const addMessage = (msg) => {
    setMessagesByConv((prev) => ({
      ...prev,
      [activeId]: [...(prev[activeId] || []), msg],
    }));
  };

  const handleSend = async (text) => {
    if (!text.trim() || !activeId) return;
    addMessage({ id: crypto.randomUUID(), role: "user", text });
    setIsTyping(true);
    try {
      const history = (messagesByConv[activeId] || []).map(m => ({
        role: m.role,
        content: m.text,
        timestamp: new Date().toISOString(),
      }));
      
      const reply = await sendChat({ domain, message: text, history, sessionId: activeId });
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
    const id = crypto.randomUUID();
    const newConv = { session_id: id, title: "New conversation", domain };
    setConversations((c) => [newConv, ...c]);
    setMessagesByConv((m) => ({ ...m, [id]: [] }));
    setActiveId(id);
  };
  
  const handleSetActiveId = async (id) => {
    setActiveId(id);
    if (!messagesByConv[id] || messagesByConv[id].length === 0) {
      try {
        const history = await fetchConversationHistory(customerId, id);
        setMessagesByConv((prev) => ({
          ...prev,
          [id]: history.map(m => ({ id: crypto.randomUUID(), ...m, text: m.content })),
        }));
      } catch (e) {
        console.error("Failed to fetch conversation history:", e);
        setMessagesByConv((prev) => ({ ...prev, [id]: [] }));
      }
    }
  };

  return (
    <div className="h-screen flex">
      <Sidebar
        conversations={conversations}
        activeId={activeId}
        setActiveId={handleSetActiveId}
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