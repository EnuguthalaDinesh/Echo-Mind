import React from "react";
import { BookText, LogOut } from "lucide-react";
import { clearToken, clearCustomerId, isAuthenticated } from "../services/auth";

export default function Topbar({ domain, onOpenFAQ }) {
  const authed = isAuthenticated();
  return (
    <div className="h-14 border-b bg-white flex items-center justify-between px-4">
      <div className="font-medium">
        Chat • <span className="capitalize">{domain}</span>
      </div>
      <div className="flex items-center gap-2">
        <button
          onClick={onOpenFAQ}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border hover:bg-gray-50"
        >
          <BookText className="w-4 h-4" />
          FAQs
        </button>
        {authed && (
          <button
            onClick={() => { clearToken(); clearCustomerId(); location.reload(); }}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border hover:bg-gray-50"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
}