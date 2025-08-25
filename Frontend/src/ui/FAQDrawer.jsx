import React from "react";

const faqs = [
  { q: "Reset password?", a: "Use 'Forgot password' from login screen." },
  { q: "Change travel dates?", a: "Go to My Trips → Manage Booking." },
  { q: "Refund timeline?", a: "Refunds appear in 3–5 business days." },
];

export default function FAQDrawer({ open, onClose }) {
  return (
    <div className={`fixed inset-0 z-40 ${open ? "" : "pointer-events-none"}`}>
      <div
        className={`absolute inset-0 bg-black/30 transition-opacity ${open ? "opacity-100" : "opacity-0"}`}
        onClick={onClose}
      />
      <aside className={`absolute right-0 top-0 h-full w-[380px] bg-white border-l p-4 transition-transform
                         ${open ? "translate-x-0" : "translate-x-full"}`}>
        <div className="flex items-center justify-between">
          <h3 className="font-semibold">FAQ Memory</h3>
          <button onClick={onClose} className="px-2 py-1 rounded border hover:bg-gray-50">Close</button>
        </div>
        <div className="mt-4 space-y-3">
          {faqs.map((f, i) => (
            <details key={i} className="border rounded-lg p-3">
              <summary className="cursor-pointer font-medium">{f.q}</summary>
              <p className="text-gray-700 mt-2">{f.a}</p>
            </details>
          ))}
        </div>
      </aside>
    </div>
  );
}
