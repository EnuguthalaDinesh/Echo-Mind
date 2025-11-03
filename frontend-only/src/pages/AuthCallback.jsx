// src/pages/AuthCallback.js

import React, { useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import LoadingSpinner from '../components/LoadingSpinner';

const AuthCallback = () => {
    const { user, loading } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        // If the user object is already populated and we are not loading, 
        // it means the JWT token was successfully set via the backend redirect 
        // (which sets the cookie) and the AuthProvider loaded the session.

        if (user && !loading) {
            console.log("OAuth Success: User session established.");
            
            // Redirect based on the user role (same logic as in Login/Register)
            if (user.role === "admin") {
                navigate('/admin-dashboard', { replace: true });
            } else if (user.role === "agent") {
                navigate('/agent-dashboard', { replace: true });
            } else {
                navigate('/dashboard', { replace: true });
            }
        } else if (!loading && !user) {
            // This case should ideally not happen after a successful callback 
            // unless the cookie failed to set.
            console.error("OAuth Callback Failed: User object missing.");
            navigate('/login', { replace: true });
        }
    }, [user, loading, navigate]);

    return (
        <div className="min-h-screen flex items-center justify-center">
            <LoadingSpinner message="Finalizing sign-in..." />
        </div>
    );
};

export default AuthCallback;