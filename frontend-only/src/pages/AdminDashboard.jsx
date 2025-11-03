import React, { useState } from 'react';
import {
  Users, TrendingUp, CheckCircle, Activity, ArrowLeft, Clock,
  UserCheck, Bell, MessageSquare, Briefcase, BarChart3
} from 'lucide-react';
import { motion } from "framer-motion";

// --- SIMULATED DATA & FUNCTIONS ---
const getDashboardStats = () => ({
  // Core KPIs
  totalUsers: 42,
  totalAgents: 9,
  avgSatisfaction: 4.7,
  resolved: 75,
  pending: 8, // Now a key metric
  
  // New Operational Data
  slaBreach: 2, // New: Number of tickets past their due time
  ticketsInProcess: 15,
  
  // Agent Performance (More detailed to simulate activity)
  agentPerformance: [
    { name: "Alice", resolved: 25, rating: 4.9, status: "Online" },
    { name: "Bob", resolved: 19, rating: 4.7, status: "Away" },
    { name: "Charlie", resolved: 31, rating: 4.6, status: "Online" },
  ],
  
  // Activity Log (Simulated)
  recentActivity: [
    { id: 1, type: "New User", description: "Sam B. signed up.", time: "2 min ago" },
    { id: 2, type: "High Priority", description: "Ticket #102 opened.", time: "15 min ago" },
    { id: 3, type: "Agent Login", description: "Alice logged in.", time: "1 hr ago" },
  ],
});

// --- NEW COMPONENT: Pending Tickets List (Simulated) ---
const PendingTickets = ({ tickets, onClose }) => {
  return (
    <motion.div 
      initial={{ x: "100%" }}
      animate={{ x: 0 }}
      exit={{ x: "100%" }}
      transition={{ type: "spring", stiffness: 100, damping: 20 }}
      className="fixed top-0 right-0 h-full w-80 bg-white shadow-2xl p-6 z-50 border-l"
    >
      <div className="flex justify-between items-center mb-6 border-b pb-3">
        <h3 className="text-xl font-bold text-red-700 flex items-center gap-2">
          <Clock className="h-5 w-5" /> Pending Tickets ({tickets.length})
        </h3>
        <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-100 transition">
          <ArrowLeft className="h-6 w-6 text-gray-600" />
        </button>
      </div>
      
      <ul className="space-y-4">
        {tickets.map((ticket, index) => (
          <li key={index} className="p-3 border rounded-lg hover:bg-red-50 transition cursor-pointer">
            <div className="font-semibold text-gray-800 flex justify-between items-start">
                <span className="truncate">{ticket.subject}</span>
                <span className="text-xs font-medium text-red-500 ml-2">P{ticket.priority}</span>
            </div>
            <div className="text-sm text-gray-500 mt-1">Assigned to: {ticket.agent}</div>
          </li>
        ))}
      </ul>
    </motion.div>
  );
};

// --- NEW COMPONENT: Dynamic Stat Card ---
const StatCard = ({ title, value, icon: Icon, colorClass, linkLabel, onClick }) => (
    <motion.div 
        whileHover={{ scale: 1.03, boxShadow: "0 10px 15px rgba(0, 0, 0, 0.1)" }} 
        className={`p-7 rounded-xl bg-white shadow-lg border border-opacity-50 ${colorClass.border} flex flex-col justify-between`}
        onClick={onClick}
    >
      <div className="flex justify-between items-start">
          <span className="text-lg font-semibold text-gray-800">{title}</span>
          <Icon className={`h-8 w-8 ${colorClass.text}`} />
      </div>
      <div className="text-4xl font-extrabold mt-2 leading-none text-gray-900">{value}</div>
      {linkLabel && (
          <button className={`text-sm font-medium ${colorClass.text} mt-3 flex items-center gap-1 hover:underline`}>
              {linkLabel} <ArrowLeft className="h-4 w-4 rotate-180" />
          </button>
      )}
    </motion.div>
);


// --- MAIN DASHBOARD COMPONENT ---
const AdminDashboard = () => {
  const [stats, setStats] = useState(getDashboardStats());
  const [showPending, setShowPending] = useState(false);
  
  // Simulated Pending Tickets Data
  const pendingTicketsData = Array.from({ length: stats.pending }).map((_, i) => ({
    subject: `Urgent Issue with Login #${100 + i}`,
    agent: i % 2 === 0 ? "Bob" : "Unassigned",
    priority: i < 3 ? 1 : 2,
  }));

  const statCards = [
      { 
        title: "Total Users", 
        value: stats.totalUsers, 
        icon: Users, 
        colorClass: { text: "text-blue-600", border: "border-blue-200" } 
      },
      { 
        title: "Agents Online", 
        value: stats.totalAgents, 
        icon: UserCheck, 
        colorClass: { text: "text-pink-600", border: "border-pink-200" } 
      },
      { 
        title: "Avg Satisfaction", 
        value: `${stats.avgSatisfaction} ⭐`, 
        icon: TrendingUp, 
        colorClass: { text: "text-green-600", border: "border-green-200" } 
      },
      { 
        title: "Pending Tickets", 
        value: stats.pending, 
        icon: Bell, 
        colorClass: { text: "text-red-600", border: "border-red-200" }, 
        linkLabel: "View Details",
        onClick: () => setShowPending(true)
      },
      { 
        title: "SLA Breaches", 
        value: stats.slaBreach, 
        icon: Clock, 
        colorClass: { text: "text-orange-600", border: "border-orange-200" } 
      },
      { 
        title: "Resolved Today", 
        value: stats.resolved, 
        icon: CheckCircle, 
        colorClass: { text: "text-emerald-600", border: "border-emerald-200" } 
      },
      { 
        title: "In Process", 
        value: stats.ticketsInProcess, 
        icon: Briefcase, 
        colorClass: { text: "text-indigo-600", border: "border-indigo-200" } 
      },
      { 
        title: "View Analytics", 
        value: "Trends", 
        icon: BarChart3, 
        colorClass: { text: "text-purple-600", border: "border-purple-200" }, 
        linkLabel: "Full Report",
        onClick: () => alert("Navigating to Analytics Page...")
      },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-red-50 via-white to-blue-50 p-10 relative overflow-hidden">
      
      {/* Dashboard Header */}
      <div className="mb-10 flex items-center justify-between">
        <div className="flex items-center gap-3">
            <Users className="h-8 w-8 text-pink-600" />
            <h1 className="text-4xl font-bold text-gray-900">Admin Command Center</h1>
        </div>
      </div>

      {/* Expanded Top-level Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-10">
        {statCards.map((card, index) => (
            <StatCard key={index} {...card} />
        ))}
      </div>

      {/* Agent Performance & Recent Activity (Side by Side) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-10">
        
        {/* Agent Performance Table (2/3 width) */}
        <div className="lg:col-span-2 bg-white/80 border rounded-xl p-8 shadow-lg">
          <h2 className="text-2xl font-bold text-pink-800 mb-6 flex items-center gap-2">
            <TrendingUp className="h-6 w-6" /> Agent Performance
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {stats.agentPerformance.map((agent) => (
              <motion.div
                key={agent.name}
                whileHover={{ scale: 1.05, boxShadow: "0 5px 10px rgba(0, 0, 0, 0.1)" }}
                className={`p-5 rounded-xl shadow-md border-t-4 ${agent.status === "Online" ? 'border-green-500 bg-green-50/50' : 'border-red-500 bg-red-50/50'}`}
              >
                <div className="font-bold text-lg text-indigo-700">{agent.name}</div>
                <div className="text-xs font-semibold text-gray-500 uppercase mt-1">{agent.status}</div>
                <div className="text-md font-semibold text-gray-700 mt-3">Resolved: <span className="text-emerald-700">{agent.resolved}</span></div>
                <div className="text-md mt-1">Rating: <span className="text-yellow-500">{agent.rating} ⭐</span></div>
              </motion.div>
            ))}
          </div>
        </div>
        
        {/* Recent Activity Log (1/3 width) */}
        <div className="lg:col-span-1 bg-white border rounded-xl p-8 shadow-lg">
          <h2 className="text-2xl font-bold text-blue-800 mb-6 flex items-center gap-2">
            <Activity className="h-6 w-6" /> Recent Activity
          </h2>
          <ul className="space-y-4">
            {stats.recentActivity.map((item) => (
              <li key={item.id} className="border-b pb-4 last:border-b-0 last:pb-0">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${item.type === "New User" ? 'bg-blue-500' : item.type === "High Priority" ? 'bg-red-500' : 'bg-gray-400'}`}></span>
                  <p className="font-medium text-gray-800">{item.description}</p>
                </div>
                <p className="text-xs text-gray-500 mt-1 ml-4">{item.type} - {item.time}</p>
              </li>
            ))}
            <li className="pt-2">
                <button className="w-full text-center text-sm text-blue-600 hover:text-blue-800 transition">
                    View Full Log...
                </button>
            </li>
          </ul>
        </div>
      </div>

      {/* Admin Action Shortcuts */}
      <div className="bg-white border rounded-xl p-8 shadow-lg">
        <h2 className="text-xl font-bold text-gray-700 mb-4 flex items-center gap-2">
            <MessageSquare className="h-5 w-5 text-purple-600" /> Admin Action Shortcuts
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <motion.button whileHover={{ scale: 1.05 }} className="p-4 bg-purple-100 text-purple-800 font-semibold rounded-lg shadow hover:bg-purple-200 transition">
                Manage Users
            </motion.button>
            <motion.button whileHover={{ scale: 1.05 }} className="p-4 bg-purple-100 text-purple-800 font-semibold rounded-lg shadow hover:bg-purple-200 transition">
                Reset System
            </motion.button>
            <motion.button whileHover={{ scale: 1.05 }} className="p-4 bg-purple-100 text-purple-800 font-semibold rounded-lg shadow hover:bg-purple-200 transition">
                Assign Tickets
            </motion.button>
            <motion.button whileHover={{ scale: 1.05 }} className="p-4 bg-purple-100 text-purple-800 font-semibold rounded-lg shadow hover:bg-purple-200 transition">
                Configure Roles
            </motion.button>
        </div>
      </div>
      
      {/* Pending Tickets Sidebar (Dynamic Feature) */}
      {showPending && (
          <PendingTickets tickets={pendingTicketsData} onClose={() => setShowPending(false)} />
      )}
      
    </div>
  );
};

export default AdminDashboard;