# Integration: Backend (FastAPI + OAuth) and Frontend API

## Backend
1. `cd backend`
2. Copy `.env.example` to `.env` and fill values (Gemini, DBs, OAuth client IDs/secrets, FRONTEND_ORIGIN).
3. `bash run.sh` (or `pip install -r requirements.txt && uvicorn main:app --reload`)

Default API: `http://localhost:8000`

OAuth redirects back to: `${FRONTEND_ORIGIN}/auth/callback?token=...`

## Frontend
- Set `VITE_API_BASE` in `.env` (e.g., `http://localhost:8000`).
- Make sure your app renders `AuthProvider` high in the tree and routes `/login` and `/auth/callback` to the provided pages.
- New files created:
  - `src/api/chatbot.js`
  - `src/context/AuthContext.jsx`
  - `src/pages/Login.jsx`
  - `src/pages/AuthCallback.jsx`
  - `src/components/ChatBox.jsx`

### Example (Vite + React Router)
```jsx
// main.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "./src/context/AuthContext.jsx";
import Login from "./src/pages/Login.jsx";
import AuthCallback from "./src/pages/AuthCallback.jsx";
import ChatBox from "./src/components/ChatBox.jsx";

ReactDOM.createRoot(document.getElementById("root")).render(
  <AuthProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ChatBox />} />
        <Route path="/login" element={<Login />} />
        <Route path="/auth/callback" element={<AuthCallback />} />
      </Routes>
    </BrowserRouter>
  </AuthProvider>
);
```
```

### Packages to install (frontend)
```
npm i axios react-router-dom
```

## Notes
- For Google OAuth, set OAuth consent screen and authorized redirect URI:
  - `http://localhost:8000/auth/google/callback`
- For GitHub OAuth, set callback URL:
  - `http://localhost:8000/auth/github/callback`
- Ensure `FRONTEND_ORIGIN` in backend `.env` matches your dev server (e.g., `http://localhost:5173`).

