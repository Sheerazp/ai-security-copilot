import { useState, useRef, useEffect } from "react";
import { askCopilot } from "../api";

const SUGGESTIONS = [
  "What was the most serious threat in the last 24 hours?",
  "How many critical events happened today?",
  "Are there any correlated attack campaigns right now?",
];

export default function CopilotChat() {
  const [messages, setMessages] = useState([
    {
      role: "assistant",
      text: "Hi, I'm your Security Operations Copilot. Ask me about recent events, threats, or attack patterns — I only read and analyze, I never take action on my own.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, loading]);

  async function send(question) {
    const q = question ?? input;
    if (!q.trim() || loading) return;
    setMessages((m) => [...m, { role: "user", text: q }]);
    setInput("");
    setLoading(true);
    try {
      const res = await askCopilot(q);
      setMessages((m) => [...m, { role: "assistant", text: res.answer, tools: res.tools_used }]);
    } catch (e) {
      setMessages((m) => [
        ...m,
        { role: "assistant", text: "Sorry, I couldn't reach the backend. Is the API running?" },
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={styles.wrap}>
      <div style={styles.header}>🤖 Security Copilot</div>

      <div style={styles.messages} ref={scrollRef}>
        {messages.map((m, i) => (
          <div
            key={i}
            style={{
              ...styles.bubble,
              alignSelf: m.role === "user" ? "flex-end" : "flex-start",
              background: m.role === "user" ? "var(--cyan)" : "var(--card-dark-2)",
              color: m.role === "user" ? "#0b0f19" : "var(--white)",
            }}
          >
            {m.text}
            {m.tools?.length > 0 && (
              <div style={styles.toolTag}>tools used: {m.tools.join(", ")}</div>
            )}
          </div>
        ))}
        {loading && (
          <div style={{ ...styles.bubble, alignSelf: "flex-start", background: "var(--card-dark-2)" }}>
            Thinking…
          </div>
        )}
      </div>

      {messages.length === 1 && (
        <div style={styles.suggestions}>
          {SUGGESTIONS.map((s) => (
            <button key={s} style={styles.suggestionBtn} onClick={() => send(s)}>
              {s}
            </button>
          ))}
        </div>
      )}

      <div style={styles.inputRow}>
        <input
          style={styles.input}
          value={input}
          placeholder="Ask about recent threats…"
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
        />
        <button style={styles.sendBtn} onClick={() => send()} disabled={loading}>
          Send
        </button>
      </div>
    </div>
  );
}

const styles = {
  wrap: {
    background: "var(--card-dark)",
    border: "1px solid var(--magenta)",
    borderRadius: 12,
    display: "flex",
    flexDirection: "column",
    height: "100%",
    overflow: "hidden",
  },
  header: {
    padding: "12px 16px",
    borderBottom: "1px solid var(--border)",
    fontWeight: 600,
  },
  messages: {
    flex: 1,
    overflowY: "auto",
    padding: 14,
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  bubble: {
    maxWidth: "85%",
    padding: "10px 13px",
    borderRadius: 12,
    fontSize: 13.5,
    lineHeight: 1.45,
    whiteSpace: "pre-wrap",
  },
  toolTag: {
    marginTop: 6,
    fontSize: 10,
    opacity: 0.7,
    fontStyle: "italic",
  },
  suggestions: {
    display: "flex",
    flexDirection: "column",
    gap: 6,
    padding: "0 14px 10px",
  },
  suggestionBtn: {
    textAlign: "left",
    background: "var(--card-dark-2)",
    border: "1px solid var(--border)",
    color: "var(--cyan)",
    borderRadius: 8,
    padding: "8px 10px",
    fontSize: 12,
    cursor: "pointer",
  },
  inputRow: {
    display: "flex",
    borderTop: "1px solid var(--border)",
    padding: 10,
    gap: 8,
  },
  input: {
    flex: 1,
    background: "var(--card-dark-2)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    padding: "9px 12px",
    color: "var(--white)",
    fontSize: 13,
    outline: "none",
  },
  sendBtn: {
    background: "var(--magenta)",
    color: "#0b0f19",
    border: "none",
    borderRadius: 8,
    padding: "0 16px",
    fontWeight: 700,
    cursor: "pointer",
  },
};
