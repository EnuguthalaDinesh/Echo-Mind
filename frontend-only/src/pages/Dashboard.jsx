import React from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { MessageCircle, Wrench, DollarSign, Plane, Shield, ArrowRight, Sparkles, Star } from 'lucide-react';
import { SUPPORT_DOMAINS, DOMAIN_LABELS } from '../utils/constants';
import { motion } from 'framer-motion';

const supportDomains = [
  {
    id: SUPPORT_DOMAINS.GENERAL,
    title: DOMAIN_LABELS[SUPPORT_DOMAINS.GENERAL],
    description: 'General queries, account help, basic support.',
    icon: MessageCircle,
    gradient: 'from-blue-200 via-blue-100 to-purple-50',
    shadow: 'shadow-blue-200/50',
    to: (id) => `/chat/${id}`,
    featured: true
  },
  {
    id: SUPPORT_DOMAINS.TECHNICAL,
    title: DOMAIN_LABELS[SUPPORT_DOMAINS.TECHNICAL],
    description: 'Technical issues, troubleshooting, advanced support.',
    icon: Wrench,
    gradient: 'from-green-200 via-white to-lime-100',
    shadow: 'shadow-green-200/40',
    to: (id) => `/chat/${id}`,
    featured: true
  },
  {
    id: SUPPORT_DOMAINS.FINANCE,
    title: DOMAIN_LABELS[SUPPORT_DOMAINS.FINANCE],
    description: 'Billing, payments, financial account support.',
    icon: DollarSign,
    gradient: 'from-yellow-100 via-orange-100 to-amber-50',
    shadow: 'shadow-yellow-100/40',
    to: (id) => `/chat/${id}`,
    featured: false
  },
  {
    id: SUPPORT_DOMAINS.TRAVEL,
    title: DOMAIN_LABELS[SUPPORT_DOMAINS.TRAVEL],
    description: 'Bookings, itinerary changes, travel help.',
    icon: Plane,
    gradient: 'from-sky-100 via-indigo-50 to-blue-50',
    shadow: 'shadow-sky-100/40',
    to: (id) => `/chat/${id}`,
    featured: false
  }
];

const fade = {
  hidden: { opacity: 0, y: 24, scale: 0.95 },
  show: (i) => ({
    opacity: 1, y: 0, scale: 1,
    transition: { delay: 0.16 * i, duration: 0.65, type: 'spring' }
  })
};

const Dashboard = () => {
  const { user } = useAuth();

  // Group grid for 2+2 layout
  const gridLayout = [
    supportDomains.slice(0, 2), // First row
    supportDomains.slice(2, 4)  // Second row
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-100 via-white to-blue-50 px-2 sm:px-6 lg:px-24 py-8">
      <motion.h1 initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.05 }} className="text-4xl md:text-5xl font-black text-gray-900 drop-shadow-sm flex items-center">
        👋 Welcome, {user?.name || 'Guest'}!
        <Sparkles className="ml-2 text-yellow-400 animate-pulse" />
      </motion.h1>
      <motion.p initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.18 }} className="mt-3 text-md md:text-lg text-gray-600">
        What do you need support with? Explore our smart tools!
      </motion.p>

      {/* Main Support Cards: 2+2 grid */}
      <div className="mt-10 flex flex-col gap-8">
        {gridLayout.map((row, rIdx) => (
          <div key={`row-${rIdx}`} className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {row.map((domain, i) => {
              const Icon = domain.icon;
              return (
                <motion.div
                  key={domain.id}
                  custom={rIdx * 2 + i} initial="hidden" animate="show" variants={fade}
                  className={`relative px-7 py-7 rounded-3xl bg-gradient-to-br ${domain.gradient} ${domain.shadow} shadow-lg border border-white/60 hover:scale-[1.04] transition-all duration-500 group overflow-hidden`}
                  style={{ minHeight: 190 }}
                >
                  <span className="flex items-center gap-3 mb-3">
                    <motion.span whileHover={{ rotate: 15, scale: 1.15 }} className="p-4 rounded-2xl bg-white/90 shadow group-hover:scale-105 transition">
                      <Icon className="h-8 w-8 text-gray-700" />
                    </motion.span>
                    <h3 className="text-xl md:text-2xl font-semibold bg-clip-text text-transparent bg-gradient-to-r from-blue-800 via-gray-900 to-purple-700">{domain.title}</h3>
                    {domain.featured && <Star className="ml-2 text-yellow-400" />}
                  </span>
                  <p className="ml-2 text-slate-600 text-[0.98rem] mb-7">{domain.description}</p>
                  <Link to={domain.to(domain.id)} className="flex items-center gap-2 absolute right-7 bottom-7 font-medium text-blue-600 transition group-hover:text-blue-800">
                    Chat <ArrowRight className="h-5 w-5 group-hover:translate-x-1 transition-transform" />
                  </Link>
                </motion.div>
              );
            })}
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.8 }} className="mt-14 mx-auto max-w-2xl bg-white/80 backdrop-blur-md rounded-2xl shadow-md border border-gray-100 p-6">
        <h2 className="text-lg md:text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">Quick Actions <Sparkles className="text-pink-400 animate-spin" size={18} /></h2>
        <div className="grid sm:grid-cols-2 gap-4">
          <motion.button whileHover={{ scale: 1.07 }} className="p-4 text-left border border-gray-200 bg-white/90 rounded-xl hover:shadow transition flex items-center gap-2">
            <MessageCircle className="text-blue-500" />
            <span>
              <h3 className="font-medium text-gray-900">Recent Chats</h3>
              <p className="text-sm text-gray-600 mt-1">Access your previous conversations</p>
            </span>
          </motion.button>
          <motion.button whileHover={{ scale: 1.07 }} className="p-4 text-left border border-gray-200 bg-white/90 rounded-xl hover:shadow transition flex items-center gap-2">
            <Shield className="text-fuchsia-500" />
            <span>
              <h3 className="font-medium text-gray-900">Contact Preferences</h3>
              <p className="text-sm text-gray-600 mt-1">Manage notification settings</p>
            </span>
          </motion.button>
        </div>
        <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4, delay: 1.2 }} className="mt-5 text-center">
          <Link to="/help" className="text-pink-600 underline font-semibold hover:text-pink-800 transition">Browse Frequently Asked Questions</Link>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default Dashboard;
