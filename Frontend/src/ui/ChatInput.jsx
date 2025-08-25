import React, { useState } from "react";
import { Send } from "lucide-react";

export default function ChatInput({ onSend }) {
  const [value, setValue] = useState("");

  const submit = () => {
    if (!value.trim()) return;
    onSend(value);
    setValue("");
  };

  return (
    <div className="border-t bg-white">
      <div className="max-w-3xl mx-auto p-3 flex gap-2">
        <textarea
          rows={1}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => (e.key === "Enter" && !e.shiftKey) ? (e.preventDefault(), submit()) : null}
          placeholder="Message Gemini…"
          className="flex-1 resize-none rounded-xl border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
        />
        <button
          onClick={submit}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-blue-600 text-white hover:bg-blue-700"
        >
          <Send className="w-4 h-4" />
          Send
        </button>
      </div>
    </div>
  );
}
