import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ArrowLeft, Mail, Lock, User, Chrome } from 'lucide-react';
import LoadingSpinner from '../components/LoadingSpinner';
import { motion } from 'framer-motion';

const RegisterPage = () => {
  const [formData, setFormData] = useState({ name: '', email: '', password: '', confirmPassword: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { register } = useAuth();
  const navigate = useNavigate();

  const handleGoogleRegister = () => {
    window.location.href = "http://localhost:8000/auth/google/login";
  };
  const handleChange = (e) => {
    setFormData(prev => ({ ...prev, [e.target.name]: e.target.value }));
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (formData.password.length < 6) {
      setError('Password must be at least 6 characters long');
      return;
    }
    setLoading(true);
    try {
      await register(formData.name, formData.email, formData.password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-tr from-pink-100 via-sky-100 to-yellow-100 flex items-center justify-center px-2">
      <motion.form
        initial={{ opacity: 0, scale: 0.8, y: 36 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.6, type: 'spring' }}
        onSubmit={handleSubmit}
        className="w-full max-w-md bg-white shadow-2xl rounded-3xl px-12 py-12"
      >
        <div className="text-center mb-6">
          <motion.div
            animate={{ rotate: [0, 12, -8, 0], scale: [1, 1.1, 1] }}
            transition={{ repeat: Infinity, duration: 2 }}
            className="inline-block"
          >
            <User className="h-12 w-12 mx-auto text-blue-400 drop-shadow-md" />
          </motion.div>
          <h2 className="mt-2 text-3xl font-bold text-blue-600 animate-fade-in">Join Us!</h2>
          <p className="text-md text-gray-500 animate-fade-in">Sign up to get personalized support.</p>
        </div>
        <div className="space-y-5">
          <AnimatedInput icon={<User />} name="name" type="text" placeholder="Name" value={formData.name} onChange={handleChange} />
          <AnimatedInput icon={<Mail />} name="email" type="email" placeholder="Email" value={formData.email} onChange={handleChange} />
          <AnimatedInput icon={<Lock />} name="password" type="password" placeholder="Password" value={formData.password} onChange={handleChange} />
          <AnimatedInput icon={<Lock />} name="confirmPassword" type="password" placeholder="Confirm Password" value={formData.confirmPassword} onChange={handleChange} />
        </div>
        {error && (
          <motion.div initial={{ x: -30, opacity: 0 }} animate={{ x: 0, opacity: 1 }} className="bg-red-50 rounded-md border border-red-200 text-red-600 font-semibold py-2 mt-4 px-3 text-center">
            {error}
          </motion.div>
        )}
        <motion.button
          type="submit"
          whileHover={{ scale: 1.06, boxShadow: "0 0 24px #bae7ff" }}
          whileTap={{ scale: 0.97 }}
          className="mt-7 w-full bg-gradient-to-tr from-blue-500 via-pink-400 to-lime-400 text-white font-bold py-3 rounded-full shadow-md transition-all text-lg relative"
        >{loading ? <LoadingSpinner /> : "Create Account ðŸŽ‰"}
        </motion.button>
        <motion.button
          type="button"
          whileHover={{ scale: 1.04, backgroundColor: "#fffde4" }}
          onClick={handleGoogleRegister}
          className="mt-4 w-full bg-white hover:bg-blue-50 border border-blue-300 text-blue-600 font-medium py-3 rounded-full shadow-sm flex items-center justify-center space-x-2 transition"
        >
          <Chrome className="h-5 w-5 text-yellow-400 animate-spin" />
          <span>Sign up with Google</span>
        </motion.button>
        <div className="mt-5 text-center text-sm">
          Already have an account?{" "}
          <Link to="/login" className="font-bold text-blue-400 hover:text-blue-700 transition-all">Login</Link>
        </div>
      </motion.form>
    </div>
  );
};

const AnimatedInput = ({ icon, name, type, placeholder, value, onChange }) => (
  <motion.div whileFocus={{ scale: 1.02 }} whileHover={{ scale: 1.02 }}>
    <div className="flex items-center bg-blue-50 rounded-full px-4 transition focus-within:ring-2 focus-within:ring-pink-400">
      <motion.div
        animate={{ scale: [1, 1.15, 1] }}
        transition={{ repeat: Infinity, duration: 2 }}
        className="text-blue-400 mr-2"
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
        className="border-0 bg-transparent flex-1 outline-none py-3 text-lg font-medium placeholder:text-blue-200"
      />
    </div>
  </motion.div>
);

export default RegisterPage;