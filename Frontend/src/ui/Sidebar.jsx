import React from "react";
import { Plus } from "lucide-react";

export default function Sidebar({ conversations, activeId, setActiveId, createConversation }) {
  return (
    <aside className="hidden md:flex md:w-72 border-r bg-white flex-col">
      <div className="h-14 border-b px-4 flex items-center justify-between">
        <div className="font-semibold">Conversations</div>
        <button
          onClick={createConversation}
          className="inline-flex items-center gap-1 px-2 py-1 rounded border hover:bg-gray-50"
        >
          <Plus className="w-4 h-4" /> New
        </button>
      </div>
      <div className="flex-1 overflow-y-auto px-2 py-2">
        {conversations.map((c) => (
          <button
            key={c.session_id}
            onClick={() => setActiveId(c.session_id)}
            className={`w-full text-left px-3 py-2 rounded-lg hover:bg-gray-50 ${
              c.session_id === activeId ? "bg-gray-100" : ""
            }`}
          >
            <div className="text-sm font-medium truncate">{c.title}</div>
            <div className="text-xs text-gray-500 capitalize">{c.domain}</div>
          </button>
        ))}
      </div>
    </aside>
  );
}