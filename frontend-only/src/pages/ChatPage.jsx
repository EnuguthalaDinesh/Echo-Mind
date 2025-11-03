import React, { useState, useRef, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import ChatMessage from '../components/ChatMessage';
// Added History icon
import { ArrowLeft, Send, Users, Wifi, WifiOff, Plus, MessageCircle, Trash2, Mic, Paperclip, Sparkles, Smile, History } from 'lucide-react'; 
import { motion } from 'framer-motion';

// NOTE: Since utils/constants is not provided, defining placeholders locally
const DOMAIN_LABELS = {
    'general': 'General Support',
    'technical': 'Technical Assistance',
    'finance': 'Billing & Finance',
    'admin': 'Admin Console'
};
const SUPPORT_DOMAINS = {
    'ADMIN': 'admin'
};

const API_BASE_URL = "https://echo-backend-1-ubeb.onrender.com";

const bubbleVariants = {
    hidden: { opacity: 0, scale: 0.9, y: 20 },
    visible: { opacity: 1, scale: 1, y: 0 }
};

const ChatPage = () => {
    const { domain } = useParams();
    const { user } = useAuth();
    const navigate = useNavigate();
    const [message, setMessage] = useState('');
    const [isEscalating, setIsEscalating] = useState(false);
    const [chatHistory, setChatHistory] = useState([]); // Local session history (localStorage)
    
    // 👇 NEW STATE FOR PERSISTENT HISTORY 👇
    const [ticketHistory, setTicketHistory] = useState([]);
    const [isHistoryLoading, setIsHistoryLoading] = useState(true);
    // 👆 END NEW STATE 👆

    const [currentChatId, setCurrentChatId] = useState(null);
    const [messages, setMessages] = useState([]);
    const [connected, setConnected] = useState(true);
    const [typing, setTyping] = useState(false);

    const messagesEndRef = useRef(null);
    const domainTitle = DOMAIN_LABELS[domain] || 'Support Chat';

    // --- FIX 422: Guarantee customerId and generate UUID fallback ---
    const customerId = user?.id || user?.email || 'anon-user-fallback'; 
    
    // Simple UUID v4 generator for consistency
    const uuidv4 = () => {
        return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
            (c ^ Math.random() * 16 >> c / 4).toString(16)
        );
    };
    // -----------------------------------------------------------

    // Existing hook for loading local session history
    useEffect(() => {
        if (user) {
            const savedHistory = localStorage.getItem(`chatHistory_${customerId}`);
            if (savedHistory) setChatHistory(JSON.parse(savedHistory));
        }
    }, [user, customerId]);

    // 👇 NEW HOOK: Fetch Persistent Ticket History on Load 👇
    useEffect(() => {
        if (!user) return;

        const fetchTicketHistory = async () => {
            setIsHistoryLoading(true);
            try {
                const resp = await fetch(`${API_BASE_URL}/history`, {
                    headers: {
                        'Authorization': `Bearer ${user.access_token}`
                    }
                });

                if (!resp.ok) throw new Error(`Failed to fetch ticket history: ${resp.status}`);

                const data = await resp.json();
                
                // Group messages by session_id (which is the ticket_id from backend)
                const groupedHistory = data.reduce((acc, message) => {
                    const ticketId = message.session_id;
                    if (!acc[ticketId]) {
                        acc[ticketId] = {
                            id: ticketId,
                            // Use subject from meta, or default
                            title: message.meta?.subject || 'Ticket Conversation', 
                            timestamp: new Date(message.timestamp).toISOString(),
                            messages: []
                        };
                    }
                    // Keep the entire message object 
                    acc[ticketId].messages.push(message); 
                    return acc;
                }, {});

                const sortedTickets = Object.values(groupedHistory).sort((a, b) => 
                    new Date(b.timestamp) - new Date(a.timestamp)
                );
                setTicketHistory(sortedTickets);
            } catch (err) {
                console.error("Error fetching persistent history:", err);
            } finally {
                setIsHistoryLoading(false);
            }
        };

        fetchTicketHistory();
    }, [user]);
    // 👆 END NEW HOOK 👆

    const saveChatHistory = (history) => {
        if (user) {
            localStorage.setItem(`chatHistory_${customerId}`, JSON.stringify(history));
            setChatHistory(history);
        }
    };

    const createNewChat = () => {
        const newChatId = uuidv4(); // Use UUID generator
        const newChat = {
            id: newChatId,
            title: 'New Chat',
            domain,
            timestamp: new Date().toISOString(),
            messages: []
        };
        const updatedHistory = [newChat, ...chatHistory];
        saveChatHistory(updatedHistory);
        setCurrentChatId(newChatId);
        setMessages([{
            id: Date.now(),
            text: `✨ Welcome to ${domainTitle}! How can I help you today?`,
            sender: 'bot',
            timestamp: new Date().toISOString()
        }]);
    };

    const loadChat = (chatId) => {
        const chat = chatHistory.find(c => c.id === chatId);
        if (chat) {
            setCurrentChatId(chatId);
            setMessages(chat.messages || []);
        }
    };

    // 👇 NEW FUNCTION: Load chat from ticket history (Read-Only) 👇
    const loadTicketChat = (ticketId) => {
        const ticket = ticketHistory.find(c => c.id === ticketId);
        if (ticket) {
            setCurrentChatId(ticketId);
            
            // Convert backend messages to frontend format and sort them
            const convertedMessages = ticket.messages
                .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
                .map(msg => ({
                    id: Date.parse(msg.timestamp) + Math.random(), // Unique ID
                    text: msg.content,
                    sender: msg.role === 'user' || msg.role === 'customer' ? 'user' : 'bot',
                    timestamp: msg.timestamp
                }));

            setMessages([
                { 
                    id: Date.now(), 
                    text: `⚠️ Loaded Ticket: ${ticket.title} (ID: ${ticketId.substring(0, 8)}...). This is a read-only history of the agent/customer ticket conversation. Start a new chat to interact.`, 
                    sender: 'system', 
                    timestamp: new Date().toISOString()
                },
                ...convertedMessages
            ]);
        }
    };
    // 👆 END NEW FUNCTION 👆

    const deleteChat = (chatId, e) => {
        e.stopPropagation();
        const updatedHistory = chatHistory.filter(c => c.id !== chatId);
        saveChatHistory(updatedHistory);
        if (currentChatId === chatId) {
            if (updatedHistory.length > 0) loadChat(updatedHistory[0].id);
            else createNewChat();
        }
    };

    const updateChatTitle = (chatId, firstMessage) => {
        const updatedHistory = chatHistory.map(chat => {
            if (chat.id === chatId && chat.title === 'New Chat') {
                return {
                    ...chat,
                    title: firstMessage.length > 30 ? firstMessage.substring(0, 30) + '...' : firstMessage
                };
            }
            return chat;
        });
        saveChatHistory(updatedHistory);
    };

    const saveCurrentChat = () => {
        if (currentChatId && messages.length > 0) {
            // Only save the current session to local storage if its ID is a UUID (not a MongoDB ObjectId from a ticket)
            const isLocalSession = chatHistory.some(chat => chat.id === currentChatId);
            
            if (isLocalSession) {
                const updatedHistory = chatHistory.map(chat => {
                    if (chat.id === currentChatId) {
                        return {
                            ...chat,
                            messages: messages.filter(m => m.sender !== 'system'), // Exclude system messages
                            timestamp: new Date().toISOString()
                        };
                    }
                    return chat;
                });
                saveChatHistory(updatedHistory);
            }
        }
    };

    useEffect(() => {
        // Only proceed if user/customerId is available
        if (customerId) {
            if (chatHistory.length === 0) createNewChat();
            else if (chatHistory.length > 0 && !currentChatId) loadChat(chatHistory[0].id);
        }
    }, [customerId, chatHistory.length, currentChatId]);

    useEffect(() => {
        if (currentChatId && messages.length > 0) saveCurrentChat();
    }, [messages, currentChatId]);

    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Send message to backend
    const sendToBackend = async (text) => {
        if (!user) {
            console.error("User not authenticated.");
            return;
        }
        setTyping(true);

        const payload = {
            user_query: text,
            session_id: currentChatId || uuidv4(), // Ensures session_id is always a string
            customer_profile: {
                customer_id: customerId, // Guaranteed valid string ID
                previous_interactions: [],
                purchase_history: [],
                preference_settings: {},
                sentiment_history: [],
                active_case_id: currentChatId || uuidv4()
            },
            conversation_history: messages.map(m => ({
                role: m.sender === 'user' ? 'customer' : 'bot',
                content: m.text,
                timestamp: m.timestamp
            })).slice(-20), 
            domain: domain
        };
        
        console.log("Sending Chat Payload:", payload);

        try {
            const resp = await fetch(`${API_BASE_URL}/chat`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${user.access_token}`
                },
                body: JSON.stringify(payload)
            });

            if (!resp.ok) {
                const errorData = await resp.json();
                console.error("Backend Error Details:", errorData);
                throw new Error(errorData.detail?.[0]?.msg || `API failed with status ${resp.status}`);
            }
            const data = await resp.json();

            if (data.bot_response) {
                const botMessage = {
                    id: Date.now() + 1,
                    text: data.bot_response,
                    sender: 'bot',
                    timestamp: new Date().toISOString()
                };
                setMessages(prev => [...prev, botMessage]);
            }

            // Check for escalation status (backend returns case_status = "escalated")
            if (data.case_status === "escalated") { 
                setIsEscalating(true);
                setMessages(prev => [...prev, {
                    id: Date.now() + 2,
                    text: `🚨 Your request has been escalated (Ticket ID: ${data.case_id}).`,
                    sender: 'system',
                    timestamp: new Date().toISOString()
                }]);
            }

            // If it's a brand new chat session that created a ticket, update the currentChatId
            if (!chatHistory.some(chat => chat.id === currentChatId) && data.case_id) {
                setCurrentChatId(data.case_id);
                // Also update the local history to reflect the new ticket ID if this was a new chat
                updateChatTitle(currentChatId, text); 
            }

        } catch (err) {
            console.error("Chat API failed:", err);
            setConnected(false);
            setMessages(prev => [...prev, {
                id: Date.now() + 3,
                text: `Error: Could not connect or receive valid response from AI. Status: ${err.message}`,
                sender: 'system',
                timestamp: new Date().toISOString()
            }]);
        } finally {
            setTyping(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const cleanMessage = message.trim();
        if (!cleanMessage) return;

        // Prevent sending messages if a ticket history (read-only) is loaded
        const isReadOnly = ticketHistory.some(t => t.id === currentChatId);
        if (isReadOnly) {
            alert("This is a read-only ticket history. Start a new chat to send messages.");
            setMessage('');
            return;
        }

        setMessages(prev => [...prev, {
            id: Date.now(),
            text: cleanMessage,
            sender: 'user',
            timestamp: new Date().toISOString()
        }]);

        if (currentChatId && messages.filter(m => m.sender === 'user').length === 0) updateChatTitle(currentChatId, cleanMessage);
        
        setMessage('');
        
        await sendToBackend(cleanMessage);
    };

    const handleInputChange = (e) => setMessage(e.target.value);

    const handleEscalation = () => {
        if (isEscalating) return;
        const escalationMessage = "I need immediate human agent support. Please escalate this case now.";
        
        setMessages(prev => [...prev, {
            id: Date.now(),
            text: escalationMessage,
            sender: 'user',
            timestamp: new Date().toISOString()
        }]);
        
        sendToBackend(escalationMessage);
    };

    if (domain === SUPPORT_DOMAINS.ADMIN && user?.role !== 'admin') {
        return (
            <div className="max-w-4xl mx-auto px-4 py-8">
                <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
                    <h2 className="text-xl font-semibold text-red-800 mb-2">Access Denied</h2>
                    <p className="text-red-600 mb-4">You don't have permission to access this page.</p>
                    <Link to="/dashboard" className="inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700">
                        <ArrowLeft className="h-4 w-4 mr-2" /> Back to Dashboard
                    </Link>
                </div>
            </div>
        );
    }
    
    const sidebarGradient = "bg-gradient-to-br from-indigo-900 via-blue-700 to-sky-500";
    const chatBg = "bg-gradient-to-br from-blue-50 via-fuchsia-50 to-purple-100";

    const isReadOnly = ticketHistory.some(t => t.id === currentChatId);

    return (
        <div className={`flex h-screen ${chatBg}`}>
            {/* Sidebar */}
            <motion.div
                initial={{ x: -60, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ duration: 0.6, type: 'spring' }}
                className={`w-80 h-full ${sidebarGradient} text-white flex flex-col glass backdrop-blur-xl`}
                style={{ boxShadow: "0 0 36px #5b6fcd33" }}
            >
                <div className="p-4 border-b border-blue-900 flex justify-between">
                    <Link to="/dashboard" className="flex items-center text-blue-200 hover:text-white font-semibold">
                        <ArrowLeft className="h-4 w-4 mr-2" /> Dashboard
                    </Link>
                    <motion.button
                        whileHover={{ scale: 1.11 }}
                        onClick={createNewChat}
                        className="flex items-center gap-2 bg-indigo-700 hover:bg-indigo-600 rounded-3xl px-5 py-2 ml-2 transition shadow-md"
                    >
                        <Plus className="h-4 w-4" /> <span>New</span>
                    </motion.button>
                </div>
                
                {/* Scrollable area for both history types */}
                <div className="flex-1 overflow-y-auto p-2 space-y-4">

                    {/* --- PERSISTENT TICKET HISTORY --- */}
                    <div className="pt-2 border-b border-blue-800/50 pb-2">
                        <h3 className="text-xs font-bold uppercase text-blue-200 pl-1 mb-2 flex items-center gap-1">
                            <History className="h-4 w-4" /> Persistent Tickets
                        </h3>
                        {isHistoryLoading && <p className="text-xs text-blue-300 p-1">Loading...</p>}
                        {ticketHistory.length === 0 && !isHistoryLoading && <p className="text-xs text-blue-300 p-1">No tickets found.</p>}
                        {ticketHistory.map(ticket => (
                            <motion.div
                                key={ticket.id}
                                initial="hidden"
                                animate="visible"
                                variants={bubbleVariants}
                                className={`group flex items-center justify-between p-3 rounded-xl glass cursor-pointer transition-colors border border-indigo-200/30 mb-2 ${currentChatId === ticket.id ? 'bg-white/10 border-white' : 'hover:bg-white/20'}`}
                                onClick={() => loadTicketChat(ticket.id)}
                            >
                                <span className="truncate max-w-[120px] text-sm font-medium">
                                    🎫 {ticket.title}
                                </span>
                                <span className="text-xs text-blue-300 min-w-max">
                                    {new Date(ticket.timestamp).toLocaleDateString()}
                                </span>
                            </motion.div>
                        ))}
                    </div>

                    {/* --- LOCAL SESSION HISTORY --- */}
                    <div className="pt-2">
                        <h3 className="text-xs font-bold uppercase text-blue-200 pl-1 mb-2 flex items-center gap-1">
                            <MessageCircle className="h-4 w-4" /> Local Session History
                        </h3>
                        {chatHistory.map(chat => (
                            <motion.div
                                key={chat.id}
                                initial="hidden"
                                animate="visible"
                                variants={bubbleVariants}
                                className={`group flex items-center justify-between p-3 rounded-xl glass cursor-pointer transition-colors border border-indigo-200/30 mb-2 ${currentChatId === chat.id ? 'bg-white/10 border-white' : 'hover:bg-white/20'}`}
                                onClick={() => loadChat(chat.id)}
                            >
                                <span className="truncate max-w-[120px]">{chat.title}</span>
                                <Trash2
                                    onClick={(e) => deleteChat(chat.id, e)}
                                    className="h-4 w-4 text-blue-200 group-hover:text-red-500"
                                />
                            </motion.div>
                        ))}
                    </div>
                </div>
            </motion.div>

            {/* Main chat area and fixed input */}
            <div className="flex-1 flex flex-col h-screen relative">
                {/* Glassy header */}
                <motion.div className="w-full py-5 px-7 glass bg-white/60 backdrop-blur-xl border-b border-blue-200 flex items-center gap-2">
                    <MessageCircle className="text-indigo-400 mr-2" />
                    <h2 className="text-lg md:text-2xl font-bold text-indigo-800">{domainTitle} <Sparkles className="text-pink-400 inline-block animate-pulse" /></h2>
                    <div className="flex-1" />
                    {isReadOnly && <span className='text-sm font-semibold text-red-500 border border-red-300 bg-red-50 px-3 py-1 rounded-full'>READ-ONLY HISTORY</span>}
                    <Wifi className={`ml-3 ${connected ? 'text-green-500' : 'text-red-500 animate-pulse'}`} />
                </motion.div>

                {/* Messages scrollable */}
                <div className="flex-1 overflow-y-auto px-7 py-5 space-y-4">
                    {messages.map(msg => (
                        <motion.div
                            key={msg.id}
                            initial="hidden"
                            animate="visible"
                            variants={bubbleVariants}
                            className={`max-w-2xl ${msg.sender === "user" ? "ml-auto" : ""}`}
                        >
                            <ChatMessage message={msg} />
                        </motion.div>
                    ))}
                    {typing && (
                        <motion.div
                            key="typing"
                            initial={{ opacity: 0, x: 12 }}
                            animate={{ opacity: 1, x: 0 }}
                            className="text-blue-500 text-lg font-mono flex items-center"
                        >
                            Bot is typing
                            <span className="dot-flash ml-2"><span>.</span><span>.</span><span>.</span></span>
                        </motion.div>
                    )}
                    <div ref={messagesEndRef} />
                </div>

                {/* Static chat input at the bottom */}
                <motion.form
                    onSubmit={handleSubmit}
                    initial={{ y: 30, opacity: 0 }}
                    animate={{ y: 0, opacity: 1 }}
                    transition={{ duration: 0.6 }}
                    className="p-5 bg-white/80 backdrop-blur border-t border-blue-200 flex items-center space-x-2"
                >
                    <input
                        type="text"
                        value={message}
                        onChange={handleInputChange}
                        placeholder={isReadOnly ? "Start a new chat to send a message..." : "Type your message... 🚀"}
                        className="flex-1 px-5 py-3 rounded-xl bg-gradient-to-br from-blue-50 to-white border border-blue-200 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-medium text-gray-900"
                        disabled={isReadOnly}
                    />
                    <motion.button
                        type="submit"
                        whileHover={{ scale: isReadOnly ? 1.0 : 1.13, backgroundColor: isReadOnly ? "#e0e7ff" : "#c7d2fe" }}
                        className={`p-3 bg-gradient-to-tr from-indigo-500 to-blue-400 text-white rounded-full shadow-lg transition ${isReadOnly ? 'opacity-50 cursor-not-allowed' : 'hover:from-indigo-600'}`}
                        disabled={isReadOnly}
                    >
                        <Send className="h-5 w-5" />
                    </motion.button>
                    <motion.button
                        type="button"
                        whileHover={{ scale: isReadOnly ? 1.0 : 1.11, backgroundColor: isReadOnly ? "#bbf7d0" : "#bbf7d0" }}
                        onClick={handleEscalation}
                        className={`p-3 bg-gradient-to-tr from-teal-400 to-green-400 text-white rounded-full shadow-md transition ${isReadOnly ? 'opacity-50 cursor-not-allowed' : 'hover:from-teal-500'}`}
                        disabled={isReadOnly}
                    >
                        <Users className="h-5 w-5" />
                    </motion.button>
                    <motion.button
                        type="button"
                        whileHover={{ scale: 1.11, backgroundColor: "#fef3c7" }}
                        className="p-3 bg-gradient-to-tr from-pink-200 to-yellow-100 text-indigo-500 rounded-full shadow-md transition"
                        disabled={isReadOnly}
                    >
                        <Mic className="h-5 w-5" />
                    </motion.button>
                    <motion.button
                        type="button"
                        whileHover={{ scale: 1.11, backgroundColor: "#c7d2fe" }}
                        className="p-3 bg-gradient-to-tr from-indigo-100 to-blue-50 text-blue-500 rounded-full shadow-md transition"
                        disabled={isReadOnly}
                    >
                        <Paperclip className="h-5 w-5" />
                    </motion.button>
                </motion.form>
                {!connected && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="absolute left-7 bottom-24 text-red-600 bg-white/80 rounded-xl px-4 py-3 shadow border border-red-100 font-bold">
                        <WifiOff className="inline mr-2" /> Connection lost
                    </motion.div>
                )}
            </div>
        </div>
    );
};

export default ChatPage;