import { googleLoginUrl, githubLoginUrl } from "../api/chatbot";

export default function Login() {
  return (
    <div style={{ maxWidth: 480, margin: "4rem auto", padding: 24, border: "1px solid #ddd", borderRadius: 16 }}>
      <h2>Login</h2>
      <p>Use OAuth to sign in:</p>
      <div style={{ display: "flex", gap: 12 }}>
        <a href={googleLoginUrl()}><button>Continue with Google</button></a>
        <a href={githubLoginUrl()}><button>Continue with GitHub</button></a>
      </div>
    </div>
  );
}