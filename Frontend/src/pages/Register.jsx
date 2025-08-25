import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { registerApi } from "../services/api";

export default function Register() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true); setError(null);
    try {
      await registerApi({ name, email, password });
      navigate("/login");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <form onSubmit={submit} className="w-full max-w-sm bg-white p-6 rounded-xl border">
        <h1 className="text-xl font-semibold">Create Account</h1>
        <div className="mt-4 space-y-3">
          <input className="w-full border rounded-lg px-3 py-2" placeholder="Full name" value={name} onChange={e=>setName(e.target.value)} />
          <input className="w-full border rounded-lg px-3 py-2" placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} />
          <input type="password" className="w-full border rounded-lg px-3 py-2" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} />
          {error && <div className="text-sm text-red-600">{error}</div>}
          <button disabled={loading} className="w-full rounded-lg bg-blue-600 text-white py-2 hover:bg-blue-700">
            {loading ? "Creating..." : "Create account"}
          </button>
          <button type="button" onClick={()=>navigate("/login")} className="w-full rounded-lg border py-2">
            Back to login
          </button>
        </div>
      </form>
    </div>
  );
}