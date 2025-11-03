import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import LoadingSpinner from '../components/LoadingSpinner';
import { ArrowLeft, Mail, Lock, Chrome } from 'lucide-react';
import { motion } from 'framer-motion';

const AnimatedInput = ({ icon, name, type, placeholder, value, onChange }) => (
  <motion.div whileFocus={{ scale: 1.02 }} whileHover={{ scale: 1.02 }}>
    <div className="flex items-center bg-purple-50 rounded-full px-4 transition focus-within:ring-2 focus-within:ring-blue-400">
      <motion.div
        animate={{ scale: [1, 1.15, 1] }}
        transition={{ repeat: Infinity, duration: 2 }}
        className="text-purple-400 mr-2"
      >
        {icon}
      </motion.div>
      <input
        required
        name={name}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={onChange}
        className="border-0 bg-transparent flex-1 outline-none py-3 text-lg font-medium placeholder:text-purple-200"
      />
    </div>
  </motion.div>
);

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleGoogleLogin = () => {
    // In a real app, this would initiate OAuth flow
    console.log('Google OAuth integration requested');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      // login() returns the user object with the 'role' and 'id' fields
      const loggedInUser = await login(email, password); 
      
      console.log("Redirecting user with role:", loggedInUser.role); 
      
      // --- ROLE-BASED REDIRECTION LOGIC ---
      if (loggedInUser.role === "admin") {
        navigate('/admin-dashboard');
      } else if (loggedInUser.role === "agent") {
        navigate('/agent-dashboard');
      } else {
        // Default for 'user' or any other role not explicitly mapped
        navigate('/dashboard'); 
      }
    } catch (err) {
      setError(err.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-tr from-lime-100 via-sky-100 to-pink-100 flex items-center justify-center px-2">
      <motion.form
        initial={{ opacity: 0, scale: 0.8, x: -24 }}
        animate={{ opacity: 1, scale: 1, x: 0 }}
        transition={{ duration: 0.6, type: 'spring' }}
        onSubmit={handleSubmit}
        className="w-full max-w-sm bg-white shadow-2xl rounded-3xl px-10 py-12"
      >
        <div className="text-center mb-6">
          <motion.div
            animate={{ rotate: [0, 15, -12, 0] }}
            transition={{ repeat: Infinity, duration: 2 }}
            className="inline-block"
          >
            <ArrowLeft className="h-10 w-10 mx-auto text-purple-400 drop-shadow-md" />
          </motion.div>
          <h2 className="mt-2 text-3xl font-bold text-purple-600">Welcome Back!</h2>
          <p className="text-md text-gray-500">Access your personalized support dashboard.</p>
        </div>
        <div className="space-y-5">
          <AnimatedInput icon={<Mail />} name="email" type="email" placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
          <AnimatedInput icon={<Lock />} name="password" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
        </div>
        {error && (
          <motion.div initial={{ x: -30, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="bg-red-50 rounded-md border border-red-200 text-red-600 font-semibold py-2 mt-4 px-3 text-center">
            {error}
          </motion.div>
        )}
        <motion.button
          type="submit"
          whileHover={{ scale: 1.06, boxShadow: "0 0 24px #f7cfff" }}
          whileTap={{ scale: 0.97 }}
          className="mt-7 w-full bg-gradient-to-tr from-purple-400 via-pink-400 to-blue-400 text-white font-bold py-3 rounded-full shadow-md transition-all text-lg relative"
        >{loading ? <LoadingSpinner /> : "Sign In 😊"}
        </motion.button>
        <motion.button
          type="button"
          whileHover={{ scale: 1.04, backgroundColor: "#fffde4" }}
          onClick={handleGoogleLogin}
          className="mt-4 w-full bg-white hover:bg-purple-50 border border-purple-300 text-purple-600 font-medium py-3 rounded-full shadow-sm flex items-center justify-center space-x-2 transition"
        >
          <Chrome className="h-5 w-5 text-yellow-400 animate-spin" />
          <span>Sign in with Google</span>
        </motion.button>
        <div className="mt-5 text-center text-sm">
          New here?{' '}
          <Link to="/register" className="font-bold text-purple-500 hover:text-blue-800 transition-all">Register</Link>
        </div>
      </motion.form>
    </div>
  );
};

export default Login;
