import React, { useEffect, useRef } from "react";

export default function MessageList({ messages }) {
  const ref = useRef(null);
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "auto" });
  }, [messages]);

  return (
    <div ref={ref} className="max-w-3xl mx-auto px-4 py-6">
      {!messages.length && (
        <div className="text-center text-gray-500 mt-8">
          Ask anything about <strong>General</strong>, <strong>Technical</strong>, <strong>Finance</strong>, or <strong>Travel</strong>.
        </div>
      )}
      <div className="space-y-3">
        {messages.map((m) => (
          <div key={m.id} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`px-4 py-2 rounded-2xl max-w-[80%] whitespace-pre-wrap ${
                m.role === "user" ? "bg-blue-600 text-white" : "bg-white border"
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
