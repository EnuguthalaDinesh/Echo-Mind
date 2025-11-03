import React, { useState, useEffect } from "react";
import { MessageCircle, Clock, AlertCircle, CheckCircle, Send, X, User, DollarSign, List, RefreshCw, BarChart3, TrendingUp, Zap } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import LoadingSpinner from "../components/LoadingSpinner";
import { motion } from "framer-motion";

// Assume API is running on localhost:8000 (Based on previous config)
const API_BASE_URL = "http://localhost:8000";

// --- Helper: SLA Color ---
function slaColor(openedAt) {
    const openedDate = new Date(openedAt);
    const now = new Date();
    const diffDays = (now - openedDate) / 1000 / 60 / 60 / 24;

    if (diffDays < 1) return "bg-green-100 text-green-800 border-green-300";
    if (diffDays < 2) return "bg-yellow-100 text-yellow-800 border-yellow-300";
    return "bg-red-100 text-red-800 border-red-400 animate-pulse"; // > 2 days
}

// --- Helper: Time Since ---
const timeSince = (dateString) => {
    const seconds = Math.floor((new Date() - new Date(dateString)) / 1000);
    let interval = seconds / 31536000;

    if (interval > 1) return Math.floor(interval) + " years";
    interval = seconds / 2592000;
    if (interval > 1) return Math.floor(interval) + " months";
    interval = seconds / 86400;
    if (interval > 1) return Math.floor(interval) + " days";
    interval = seconds / 3600;
    if (interval > 1) return Math.floor(interval) + " hours";
    interval = seconds / 60;
    if (interval > 1) return Math.floor(interval) + " minutes";
    return Math.floor(seconds) + " seconds";
};

// --- Ticket Detail & Response Modal Component ---
const TicketDetailModal = ({ ticket, onClose, onResolve, onReply, onStatusChange }) => {
    const { user } = useAuth();
    const [response, setResponse] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [status, setStatus] = useState(ticket.status);
    
    const ticketIdentifier = ticket._id; 
    
    // Placeholder data for Customer 360 (In a real app, this would be passed via prop)
    const customerInfo = {
        name: "Sharath S.",
        email: "sharath@example.com",
        tier: ticket.customer_id.length % 2 === 0 ? "VIP" : "Standard", 
        lastSentiment: "Angry 😠 (last message)",
        lastOrder: "2025-10-15",
        recentTickets: [
             { id: 1, subject: "Refund delayed", status: "resolved" },
             { id: 2, subject: "Broken API key", status: "closed" },
             { id: 3, subject: "VIP lounge access", status: "resolved" },
        ]
    };

    const conversation = ticket.conversation_history || [
        { role: 'user', content: ticket.description || "No detailed issue provided.", timestamp: ticket.created_at }
    ];

    const handleReplySubmit = async (e) => {
        e.preventDefault();
        if (!response.trim()) return;
        setIsSubmitting(true);
        try {
            await onReply(ticketIdentifier, response); 
            onClose(); // Close on successful reply
        } catch (error) {
             console.error("Failed to send reply, keeping modal open.", error);
        } finally {
            setIsSubmitting(false);
            setResponse('');
        }
    };
    
    const handleStatusUpdate = async (newStatus) => {
        if (!window.confirm(`Are you sure you want to change status to ${newStatus.toUpperCase()}?`)) return;
        setIsSubmitting(true);
        try {
            await onStatusChange(ticketIdentifier, newStatus);
            setStatus(newStatus); // Update local status on success
            if (newStatus === 'resolved') onClose();
        } catch (error) {
             console.error("Failed to update status.", error);
        } finally {
            setIsSubmitting(false);
        }
    };

    const StatusDropdown = () => (
        <select 
            value={status} 
            onChange={(e) => handleStatusUpdate(e.target.value)}
            disabled={isSubmitting}
            className={`px-3 py-1 rounded-lg font-semibold border-2 transition ${
                status === 'resolved' ? 'bg-emerald-500 text-white' : 
                status === 'open' ? 'bg-red-500 text-white' : 
                'bg-gray-200 text-gray-800'
            }`}
        >
            <option value="open">Open</option>
            <option value="escalated">Escalated (L2)</option>
            <option value="pending">Pending Customer</option>
            <option value="resolved">Resolved</option>
        </select>
    );

    return (
        <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-70 p-4"
        >
            <motion.div
                initial={{ scale: 0.9, y: 50 }}
                animate={{ scale: 1, y: 0 }}
                transition={{ type: "spring", stiffness: 200 }}
                className="bg-white rounded-xl shadow-2xl w-full max-w-4xl max-h-[95vh] grid grid-cols-3 overflow-hidden"
            >
                {/* --- Left Column: Customer 360 View --- */}
                <div className="p-6 bg-gray-50 border-r col-span-1 flex flex-col">
                    <h3 className="text-lg font-bold mb-4 text-gray-700 flex items-center gap-2"><User className="h-5 w-5" /> Customer 360 View</h3>
                    
                    <div className="text-sm space-y-3 p-3 bg-white rounded-lg shadow-sm border">
                        <p><strong>Customer ID:</strong> {ticket.customer_id.substring(0, 10)}...</p>
                        <p><strong>Name:</strong> {customerInfo.name} 
                            <span className={`ml-2 text-xs px-2 py-0.5 rounded-full font-semibold ${customerInfo.tier === 'VIP' ? 'bg-yellow-200 text-yellow-800' : 'bg-blue-100 text-blue-800'}`}>
                                {customerInfo.tier}
                            </span>
                        </p>
                        <p><strong>Initial Sentiment:</strong> <span className="font-semibold">{customerInfo.lastSentiment}</span></p>
                    </div>
                    
                    <h4 className="text-md font-semibold mt-6 mb-2 text-gray-600 flex items-center gap-1"><List className="h-4 w-4" /> Recent Interactions</h4>
                    <ul className="text-xs space-y-1 overflow-y-auto max-h-32">
                        {customerInfo.recentTickets.map(t => (
                            <li key={t.id} className="truncate text-gray-700 hover:text-indigo-600 cursor-pointer">
                                [{t.status.substring(0,1).toUpperCase()}] {t.subject}
                            </li>
                        ))}
                    </ul>
                    
                     <h4 className="text-md font-semibold mt-6 mb-2 text-gray-600 flex items-center gap-1"><DollarSign className="h-4 w-4" /> Financial Overview</h4>
                     <p className="text-xs">Account Balance: $450.00</p>
                     <p className="text-xs text-red-500 font-medium">Overdue Invoice: $49.99</p>

                     <h4 className="text-md font-semibold mt-6 mb-2 text-gray-600 flex items-center gap-1"><Zap className="h-4 w-4" /> Internal Notes</h4>
                     <textarea
                        placeholder="Add private notes (customer cannot see this)..."
                        rows="3"
                        className="w-full p-2 border rounded-lg text-xs resize-none"
                     ></textarea>

                </div>


                {/* --- Right Column: Ticket Conversation & Response --- */}
                <div className="col-span-2 flex flex-col h-full">
                    <div className="flex justify-between items-center p-6 border-b bg-white">
                        <h2 className="text-xl font-bold text-gray-800 truncate">{ticket.subject || ticket.description}</h2>
                        <button onClick={onClose} className="text-gray-500 hover:text-red-500 transition">
                            <X className="h-6 w-6" />
                        </button>
                    </div>

                    <div className="p-6 flex-1 overflow-y-auto space-y-4 bg-gray-50/50">
                        {/* Conversation History */}
                        <div className="h-full overflow-y-auto space-y-3 pr-2">
                             <p className="text-xs text-gray-500 mb-4 font-semibold border-b pb-2">Ticket ID: {ticketIdentifier} | Domain: {ticket.domain.toUpperCase()}</p>
                            {conversation.map((msg, index) => (
                                <div key={index} className={`flex ${msg.role === 'agent' ? 'justify-end' : 'justify-start'}`}>
                                    <div
                                        className={`max-w-md p-3 rounded-xl text-sm shadow-md ${
                                            msg.role === 'agent'
                                                ? 'bg-indigo-600 text-white rounded-br-sm'
                                                : 'bg-blue-50 text-gray-800 rounded-bl-sm'
                                        }`}
                                    >
                                        <strong className="capitalize text-xs">{msg.role}:</strong> 
                                        <div className="text-xs text-gray-400 mt-1">{new Date(msg.timestamp).toLocaleTimeString()}</div>
                                        {msg.content}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                    
                    {/* Footer: Actions and Response Form */}
                    <div className="p-6 border-t bg-white">
                        {/* Resolution/Status Bar */}
                        <div className="flex justify-between items-center pb-4">
                            <div className="flex items-center gap-3">
                                <strong>Status:</strong>
                                <StatusDropdown />
                            </div>
                            
                            {/* Quick Resolve Button */}
                            {status !== 'resolved' && (
                                <button
                                    onClick={() => handleStatusUpdate('resolved')}
                                    disabled={isSubmitting}
                                    className="px-4 py-2 bg-emerald-500 text-white rounded-full hover:bg-emerald-600 transition disabled:opacity-50 flex items-center gap-1 shadow-md text-sm"
                                >
                                    <CheckCircle className="h-4 w-4" /> {isSubmitting ? '...' : 'Quick Resolve'}
                                </button>
                            )}
                        </div>

                        {/* Response Form */}
                        {status !== 'resolved' && (
                            <form onSubmit={handleReplySubmit}>
                                <textarea
                                    value={response}
                                    onChange={(e) => setResponse(e.target.value)}
                                    placeholder={`Type your reply to the customer...`}
                                    rows="3"
                                    className="w-full p-3 border rounded-lg focus:ring-blue-500 focus:border-blue-500 mb-3 resize-none"
                                    required
                                />
                                <button
                                    type="submit"
                                    disabled={isSubmitting || !response.trim()}
                                    className="w-full py-3 bg-blue-500 text-white rounded-lg font-semibold hover:bg-blue-600 transition disabled:opacity-50 flex items-center justify-center gap-2 shadow-lg"
                                >
                                    <Send className="h-5 w-5" /> {isSubmitting ? 'Sending Reply...' : 'Send Reply'}
                                </button>
                            </form>
                        )}
                    </div>
                </div>
            </motion.div>
        </motion.div>
    );
};

// --- Agent Dashboard Main Component ---
const AgentDashboard = () => {
    const { user } = useAuth();
    const [tickets, setTickets] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [selectedTicket, setSelectedTicket] = useState(null);
    
    // Placeholder Metrics (These should come from a dedicated backend endpoint)
    const metrics = {
        totalOpen: tickets.length,
        overdue: tickets.filter(t => new Date() - new Date(t.created_at) > 48 * 3600 * 1000).length,
        assignedToMe: 8, // Fixed placeholder
        resolutionTime: "1.8h (Avg)",
        csat: "91%",
        closedToday: 12
    };

    // Function to fetch tickets from the backend
    const fetchTickets = async () => {
        if (!user || !user.access_token) {
            setError("Authentication failed. Please log in.");
            return;
        }
        setLoading(true);
        setError(null);
        try {
            const res = await fetch(`${API_BASE_URL}/tickets`, {
                headers: {
                    'Authorization': `Bearer ${user.access_token}`,
                    'Content-Type': 'application/json',
                },
            });
            
            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || `Failed to fetch tickets (Status: ${res.status})`);
            }

            const data = await res.json();
            setTickets(data); 

        } catch (err) {
            console.error("Ticket fetch error:", err);
            setError(err.message || "Could not load tickets. Check API URL.");
            setTickets([]);
        } finally {
            setLoading(false);
        }
    };
    
    // Function to handle agent response (reply)
    const handleReply = async (ticketId, message) => {
        try {
            const res = await fetch(`${API_BASE_URL}/tickets/${ticketId}/message`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${user.access_token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message, role: 'agent' }) 
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || "Failed to send reply.");
            }
            
            await fetchTickets(); 
            // Note: Modal closes on success, so no need to clear selectedTicket here.
            
        } catch (err) {
            console.error("Reply error:", err);
            throw err;
        }
    };
    
    // Function to change ticket status
    const handleStatusChange = async (ticketId, newStatus) => {
        try {
            const res = await fetch(`${API_BASE_URL}/tickets/${ticketId}/status`, {
                method: 'PUT',
                headers: {
                    'Authorization': `Bearer ${user.access_token}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ status: newStatus })
            });

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(errData.detail || `Failed to update status to ${newStatus}.`);
            }
            
            // Re-fetch to update all data immediately
            await fetchTickets(); 
            
            // If the selected ticket was the one modified, update its local state too
            if (selectedTicket && selectedTicket._id === ticketId) {
                setSelectedTicket(prev => ({ ...prev, status: newStatus }));
            }
            
        } catch (err) {
            console.error("Status update error:", err);
            throw err;
        }
    };


    useEffect(() => {
        if (user && user.access_token) {
            fetchTickets();
        }
    }, [user]); 

    // --- Component for high-level metrics ---
    const AgentMetrics = ({ metrics }) => (
        <div className="grid grid-cols-6 gap-4 mb-8 text-center bg-white p-4 rounded-xl shadow-lg border border-gray-100">
            {[{ title: "Total Open", value: metrics.totalOpen, color: "text-blue-500" },
              { title: "Overdue SLA", value: metrics.overdue, color: "text-red-500", icon: AlertCircle },
              { title: "Assigned To Me", value: metrics.assignedToMe, color: "text-indigo-500" },
              { title: "Closed Today", value: metrics.closedToday, color: "text-green-600" },
              { title: "Avg. Resolution", value: metrics.resolutionTime, color: "text-cyan-500" },
              { title: "CSAT Score", value: metrics.csat, color: "text-pink-500" }
            ].map((metric, index) => (
                <motion.div key={index} whileHover={{ scale: 1.05, backgroundColor: "#f5f8ff" }} className="border-r last:border-r-0 px-3 p-2 rounded-lg">
                    <p className="text-sm font-medium text-gray-500">{metric.title}</p>
                    <p className={`text-2xl font-extrabold ${metric.color} mt-1 flex items-center justify-center`}>
                        {metric.icon && <metric.icon className="h-5 w-5 mr-1" />}
                        {metric.value}
                    </p>
                </motion.div>
            ))}
        </div>
    );


    return (
        <div className="min-h-screen bg-gradient-to-tr from-blue-50 via-white to-emerald-50 px-8 py-10">
            <div className="mb-7 flex justify-between items-center">
                <div className="flex items-center gap-2">
                    <MessageCircle className="h-7 w-7 text-blue-600" />
                    <h1 className="text-3xl font-bold text-gray-900">Agent Workspace</h1>
                    <span className="text-sm font-medium text-gray-500 ml-2">({user?.email || "Guest"})</span>
                </div>
                <motion.button 
                    whileHover={{ rotate: 30 }}
                    onClick={fetchTickets}
                    disabled={loading}
                    className="px-4 py-2 bg-blue-500 text-white font-semibold rounded-full shadow-md hover:bg-blue-600 transition disabled:opacity-50 flex items-center gap-2"
                >
                    <RefreshCw className={`h-5 w-5 ${loading ? 'animate-spin' : ''}`} />
                    {loading ? 'Refreshing...' : 'Refresh Queue'}
                </motion.button>
            </div>
            
            <AgentMetrics metrics={metrics} />

            {error && <div className="bg-red-100 text-red-700 p-3 rounded-lg mb-4">{error}</div>}
            
            {!loading && tickets.length === 0 && !error && (
                <div className="text-center py-10 text-gray-500 border-2 border-dashed border-gray-300 rounded-xl">
                    <CheckCircle className="h-10 w-10 mx-auto mb-3 text-green-500" />
                    <p className="text-lg font-semibold">All clear! No open tickets at the moment.</p>
                </div>
            )}
            
            {!loading && tickets.length > 0 && (
                <>
                <h2 className="text-xl font-bold text-gray-700 mb-4">Open Tickets ({tickets.length})</h2>
                <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    {tickets.map(ticket => {
                        const openedAtString = ticket.created_at || new Date().toISOString(); 
                        const color = slaColor(openedAtString);
                        const openedDate = new Date(openedAtString);
                        const diffHours = Math.round((new Date() - openedDate) / 1000 / 60 / 60);

                        return (
                            <motion.div
                                key={ticket._id}
                                whileHover={{ scale: 1.03, boxShadow: "0 8px 24px rgba(0, 150, 255, 0.3)" }}
                                whileTap={{ scale: 0.98 }}
                                className={`p-6 rounded-2xl shadow-xl ${color} transition-all cursor-pointer flex flex-col justify-between`}
                                onClick={() => setSelectedTicket(ticket)}
                            >
                                <div>
                                    <div className="flex justify-between items-start mb-2">
                                        <span className="font-extrabold text-lg truncate pr-2">{ticket.subject || ticket.description.substring(0, 30) + '...'}</span>
                                        {diffHours > 48
                                            ? <AlertCircle className="text-red-600 h-5 w-5 flex-shrink-0" title="SLA Overdue" />
                                            : diffHours < 24
                                                ? <CheckCircle className="text-green-600 h-5 w-5 flex-shrink-0" title="New Ticket" />
                                                : <Clock className="text-yellow-600 h-5 w-5 flex-shrink-0 animate-pulse" title="Pending" />}
                                    </div>
                                    <div className="mb-3 text-gray-800 text-sm">
                                        <p>Domain: <span className="font-semibold">{ticket.domain?.toUpperCase() || 'GENERAL'}</span></p>
                                        <p>Last Activity: <span className="font-medium">{timeSince(ticket.updated_at || ticket.created_at)} ago</span></p>
                                        <p>Sentiment: <span className="font-semibold">Neutral 😐</span></p>
                                    </div>
                                </div>
                                <div className="text-xs text-gray-500 pt-3 border-t border-gray-300/50 flex justify-between items-center">
                                    <div>
                                        <p className="font-mono text-gray-700">ID: {ticket._id.substring(0, 8)}</p>
                                        <p>Customer: {ticket.customer_id.substring(0, 8)}...</p>
                                    </div>
                                    <button 
                                        onClick={(e) => { e.stopPropagation(); alert(`Assigning ${ticket._id} to you!`); }}
                                        className="px-2 py-1 bg-indigo-500 text-white rounded-full text-xs font-medium hover:bg-indigo-600"
                                    >
                                        Assign to Me
                                    </button>
                                </div>
                            </motion.div>
                        );
                    })}
                </div>
                </>
            )}

            {/* Render the modal when a ticket is selected */}
            {selectedTicket && (
                <TicketDetailModal
                    ticket={selectedTicket}
                    onClose={() => setSelectedTicket(null)}
                    onReply={handleReply}
                    onStatusChange={handleStatusChange} // Use the specific status change handler
                />
            )}
        </div>
    );
};

export default AgentDashboard;
