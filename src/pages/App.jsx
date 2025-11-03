import React from "react";
import { useNavigate } from "react-router-dom";
import { Headphones, Wrench, Wallet, Plane } from "lucide-react";

const domains = [
  { name: "General Customer Support", path: "general", Icon: Headphones, color: "bg-blue-50 text-blue-700" },
  { name: "Technical Support", path: "technical", Icon: Wrench, color: "bg-emerald-50 text-emerald-700" },
  { name: "Finance", path: "finance", Icon: Wallet, color: "bg-amber-50 text-amber-700" },
  { name: "Travel", path: "travel", Icon: Plane, color: "bg-purple-50 text-purple-700" },
];

export default function App() {
  const navigate = useNavigate();
  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b bg-white">
        <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold">Gemini Customer Support Chatbot</h1>
          <div className="space-x-2">
            <button onClick={() => navigate("/faq")} className="px-3 py-2 rounded border hover:bg-gray-50">FAQs</button>
            <button onClick={() => navigate("/dashboard")} className="px-3 py-2 rounded bg-gray-900 text-white">Admin</button>
            <button onClick={() => navigate("/login")} className="px-3 py-2 rounded border hover:bg-gray-50">Login</button>
          </div>
        </div>
      </header>
      <main className="flex-1">
        <section className="max-w-6xl mx-auto px-4 py-10">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="text-3xl font-bold tracking-tight">Instant, context-aware help across four domains</h2>
            <p className="text-gray-600 mt-3">
              Powered by Google Gemini. Case memory + FAQ learning for faster resolutions.
            </p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-10">
            {domains.map(({ name, path, Icon, color }) => (
              <button
                key={path}
                onClick={() => navigate(`/chat/${path}`)}
                className={`flex items-center gap-3 rounded-xl p-4 border hover:shadow ${color} transition`}
              >
                <span className="inline-flex p-2 rounded-lg bg-white border">
                  <Icon className="w-5 h-5" />
                </span>
                <span className="text-left font-medium">{name}</span>
              </button>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
