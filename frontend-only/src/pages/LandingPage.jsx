import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  MessageCircle, Users, Clock, Shield, Sparkles, Zap, Heart,
  ChevronLeft, User, Briefcase
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

// --- Global Animation Variants ---
const heroVariants = {
  hidden: { opacity: 0, y: 40 },
  show: { opacity: 1, y: 0, transition: { duration: 0.7, type: 'spring' } }
};

const iconJump = {
  rest: { y: 0 },
  hover: { y: -12, transition: { type: 'spring', stiffness: 300 } }
};

const pageTransitionVariants = {
  initial: { opacity: 0, x: 100 },
  in: { opacity: 1, x: 0 },
  out: { opacity: 0, x: -100 }
};

// --- Role Data (Professional Look) ---
const roles = [
  {
    name: "User",
    icon: <User className="h-12 w-12 text-blue-600" />,
    desc: "Chat, get instant help & support.",
    link: "/login?role=user",
    circle: "from-blue-50 to-blue-100",
    text: "text-blue-700",
    button: "bg-blue-600 hover:bg-blue-700 text-white",
  },
  {
    name: "Admin",
    icon: <Shield className="h-12 w-12 text-red-600" />,
    desc: "Manage system, agents & users.",
    link: "/login?role=admin",
    circle: "from-red-50 to-red-100",
    text: "text-red-700",
    button: "bg-red-600 hover:bg-red-700 text-white",
  },
  {
    name: "Agent",
    icon: <Briefcase className="h-12 w-12 text-emerald-600" />,
    desc: "View, manage, and resolve tickets.",
    link: "/login?role=agent",
    circle: "from-emerald-50 to-emerald-100",
    text: "text-emerald-700",
    button: "bg-emerald-600 hover:bg-emerald-700 text-white",
  }
];

const roleCardVariants = {
  rest: {
    scale: 1,
    boxShadow: '0 4px 12px rgba(0,0,0,0.08)',
    transition: { type: "spring", stiffness: 300, damping: 20 }
  },
  hover: {
    scale: 1.05,
    boxShadow: '0 10px 30px rgba(0,0,0,0.15)',
    transition: { type: "spring", stiffness: 300, damping: 10 }
  }
};

// --- Feature Card Component (Helper) ---
const FeatureCard = ({ Icon, title, description, delay }) => (
  <motion.div
    initial={{ opacity: 0, y: 50, scale: 0.92 }}
    whileInView={{ opacity: 1, y: 0, scale: 1 }}
    transition={{ duration: 0.6, delay }}
    viewport={{ once: true, amount: 0.5 }}
    className="rounded-3xl p-8 bg-white bg-opacity-70 shadow-lg hover:shadow-xl transition-shadow border-2 border-fuchsia-100 hover:border-pink-200"
  >
    <div className="mb-2 flex items-center">
      <Icon className="h-8 w-8 text-blue-500 drop-shadow-md" />
      <span className="ml-3 text-2xl font-bold text-gray-700">{title}</span>
    </div>
    <p className="text-gray-500 text-lg">{description}</p>
  </motion.div>
);

// ==========================================================
// 1. Initial Landing Page (Retained)
// ==========================================================

const InitialLandingPage = ({ onGetStarted }) => (
  <motion.div
    key="initial-landing"
    initial="initial"
    animate="in"
    exit="out"
    variants={pageTransitionVariants}
    className="min-h-screen bg-gradient-to-br from-blue-100 via-fuchsia-100 to-yellow-50 px-4 pt-12 pb-24 flex flex-col justify-between"
  >
    {/* Hero Section */}
    <motion.div
      initial="hidden"
      animate="show"
      variants={heroVariants}
      className="text-center"
    >
      <div className="flex justify-center mb-7">
        <motion.div
          whileHover="hover"
          initial="rest"
          animate="rest"
          variants={iconJump}
          className="relative"
        >
          <MessageCircle className="h-20 w-20 text-blue-600 drop-shadow-lg" />
          <motion.div
            animate={{ rotate: [0, 35, -20, 0], scale: [1, 1.07, 1] }}
            transition={{ repeat: Infinity, duration: 2 }}
            className="absolute -top-3 -right-4"
          >
            <Sparkles className="h-8 w-8 text-yellow-400 animate-pulse" />
          </motion.div>
        </motion.div>
      </div>
      <h1 className="text-5xl md:text-7xl font-bold text-gray-900 mb-4">
        <span className="bg-gradient-to-r from-blue-600 via-pink-500 to-purple-600 bg-clip-text text-transparent">
          Customer Support
        </span> <br />
        <span className="text-4xl md:text-6xl block mt-2">Made Simple</span>
      </h1>
      <motion.p
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4, duration: 1.0 }}
        className="text-xl text-gray-600 max-w-2xl mx-auto my-3 mb-6"
      >
        Get instant help from Echo Mind or connect with our expert support team.<br />
        Solve your problems 24/7 with lightning-fast responses, secure conversations, and joyful experience!
      </motion.p>
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ delay: 0.8, duration: 0.6, type: 'spring' }}
      >
        <button
          onClick={onGetStarted}
          className="inline-block px-8 py-4 rounded-full bg-gradient-to-tr from-blue-500 via-teal-400 to-pink-400 text-white text-lg font-bold shadow-md hover:scale-105 hover:from-pink-500 hover:via-yellow-400 hover:to-lime-400 transition-all duration-200"
        >
          Get Started 🚀
        </button>
      </motion.div>
    </motion.div>

    {/* Animated Features Section */}
    <div className="max-w-4xl mx-auto mt-20 grid md:grid-cols-2 gap-10">
      <FeatureCard Icon={Users} title="Human + AI Agents" description="Get a perfect blend of helpful humans and intelligent AI working together." delay={0} />
      <FeatureCard Icon={Clock} title="24/7 Availability" description="No more waiting! Help is always available, any time, any day." delay={0.2} />
      <FeatureCard Icon={Shield} title="End-to-End Security" description="Your conversations and data are always securely encrypted." delay={0.4} />
      <FeatureCard Icon={Zap} title="Lightning Fast" description="Experience responses at the speed of thought—no more delays." delay={0.6} />
    </div>

    {/* Trust Section */}
    <motion.div
      className="mt-24 flex flex-col items-center"
      initial={{ opacity: 0, y: 60 }}
      whileInView={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.7 }}
      viewport={{ once: true }}
    >
      <Heart className="h-10 w-10 text-pink-500 animate-pulse" />
      <p className="mt-2 text-lg text-purple-700 font-semibold">
        Trusted by thousands. Loved by everyone 🥳
      </p>
    </motion.div>
  </motion.div>
);

// ==========================================================
// 2. Role Selection Page (After Get Started)
// ==========================================================

const RoleSelectionPage = ({ onBack }) => (
  <motion.div
    key="role-selection"
    initial="initial"
    animate="in"
    exit="out"
    variants={pageTransitionVariants}
    className="min-h-screen bg-gray-50 flex flex-col items-center justify-center p-4 py-12"
  >
    <div className="w-full max-w-5xl">
      {/* Back Button */}
      <button
        onClick={onBack}
        className="flex items-center text-gray-500 hover:text-gray-700 font-medium mb-8 transition-colors"
      >
        <ChevronLeft className="h-5 w-5 mr-1" /> Back to Home
      </button>

      {/* Header Section */}
      <div className="text-center mb-10">
        <h2 className="text-4xl sm:text-5xl font-extrabold text-gray-900">
          Pick Your Role
        </h2>
        <p className="mt-3 text-lg text-gray-500">
          Where would you like to log in today?
        </p>
      </div>

      {/* Roles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        {roles.map(role => (
          <motion.div
            key={role.name}
            initial="rest"
            whileHover="hover"
            animate="rest"
            variants={roleCardVariants}
            className={`
                            flex flex-col items-center p-8 
                            rounded-xl shadow-lg border border-gray-100 
                            transition-all duration-500 cursor-pointer h-full
                            bg-gradient-to-br ${role.circle}
                        `}
          >
            {/* Icon Circle */}
            <div className="mb-4 p-4 rounded-full bg-white shadow-md">
              {role.icon}
            </div>

            {/* Role Name */}
            <h3 className={`text-2xl font-bold ${role.text} mb-2`}>{role.name}</h3>

            {/* Description */}
            <p className="text-md text-gray-600 mb-6 text-center flex-grow">{role.desc}</p>

            {/* Login Button */}
            <Link to={role.link} className="w-full mt-auto">
              <motion.button
                whileTap={{ scale: 0.95 }}
                className={`
                                    w-full px-6 py-3 rounded-lg font-semibold text-lg 
                                    shadow-md transition duration-300 ease-in-out 
                                    transform hover:-translate-y-0.5
                                    ${role.button}
                                `}
              >
                Login
              </motion.button>
            </Link>
          </motion.div>
        ))}
      </div>

      <div className="mt-10 text-gray-400 text-sm text-center">
        Each role redirects to a tailored, secure login experience.
      </div>
    </div>
  </motion.div>
);


// ==========================================================
// 3. Main Export Component (Manages State)
// ==========================================================

const AppEntry = () => {
  const [showRoles, setShowRoles] = useState(false);

  const handleGetStarted = () => {
    setShowRoles(true);
  };

  const handleBack = () => {
    setShowRoles(false);
  };

  return (
    <AnimatePresence mode="wait">
      {showRoles ? (
        <RoleSelectionPage onBack={handleBack} />
      ) : (
        <InitialLandingPage onGetStarted={handleGetStarted} />
      )}
    </AnimatePresence>
  );
};

// Export the wrapper component
export default AppEntry;