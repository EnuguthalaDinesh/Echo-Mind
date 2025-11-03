import React, { useEffect, useMemo, useState } from "react";
import { fetchFaqs } from "../services/api";

export default function FAQ() {
  const [query, setQuery] = useState("");
  const [faqs, setFaqs] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await fetchFaqs();
        setFaqs(Array.isArray(data) ? data : []);
      } catch (e) {
        setError(e.message);
        setFaqs([
          { q: "How do I reset my password?", a: "Use the 'Forgot Password' link on the sign-in page." },
          { q: "Can I change my travel dates?", a: "Yes, go to 'My Trips' → 'Manage Booking'." },
          { q: "Where can I view my invoices?", a: "Billing → Invoices in your account." },
        ]);
      }
    })();
  }, []);

  const results = useMemo(() => {
    const q = query.toLowerCase();
    return faqs.filter(({ q:Q, a }) => Q.toLowerCase().includes(q) || a.toLowerCase().includes(q));
  }, [query, faqs]);

  return (
    <div className="min-h-screen p-6 max-w-3xl mx-auto">
      <h1 className="text-2xl font-semibold">FAQs</h1>
      <input
        className="mt-4 w-full border rounded-lg px-3 py-2"
        placeholder="Search FAQs..."
        value={query}
        onChange={e => setQuery(e.target.value)}
      />
      {error && <div className="mt-3 text-sm text-red-600">Using demo FAQs. API error: {error}</div>}
      <div className="mt-6 space-y-3">
        {results.map((item, i) => (
          <details key={i} className="bg-white border rounded-lg p-4">
            <summary className="font-medium cursor-pointer">{item.q}</summary>
            <p className="text-gray-700 mt-2">{item.a}</p>
          </details>
        ))}
        {!results.length && <p className="text-gray-500">No FAQs found.</p>}
      </div>
    </div>
  );
}
