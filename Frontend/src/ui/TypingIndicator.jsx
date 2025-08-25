import React from "react";

export default function TypingIndicator() {
  return (
    <div className="max-w-3xl mx-auto px-4 pb-4">
      <div className="inline-flex items-center gap-2 bg-white border rounded-2xl px-4 py-2">
        <span className="inline-flex gap-1">
          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:-.2s]"></span>
          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce [animation-delay:-.1s]"></span>
          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></span>
        </span>
        <span className="text-gray-500">Gemini is typing…</span>
      </div>
    </div>
  );
}
