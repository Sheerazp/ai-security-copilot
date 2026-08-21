const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_BASE = API_BASE.replace(/^http/, "ws");

export async function getStats(hours = 24) {
  const res = await fetch(`${API_BASE}/stats?hours=${hours}`);
  if (!res.ok) throw new Error("Failed to fetch stats");
  return res.json();
}

export async function getEvents(severity = "any", hours = 24, limit = 50) {
  const res = await fetch(`${API_BASE}/events?severity=${severity}&hours=${hours}&limit=${limit}`);
  if (!res.ok) throw new Error("Failed to fetch events");
  return res.json();
}

export async function getCampaigns(hours = 24) {
  const res = await fetch(`${API_BASE}/correlate?hours=${hours}`);
  if (!res.ok) throw new Error("Failed to fetch campaigns");
  return res.json();
}

export async function askCopilot(question) {
  const res = await fetch(`${API_BASE}/copilot/ask`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question }),
  });
  if (!res.ok) throw new Error("Copilot request failed");
  return res.json();
}

export function connectLiveFeed(onEvent) {
  const ws = new WebSocket(`${WS_BASE}/ws/live`);
  ws.onmessage = (msg) => {
    try {
      onEvent(JSON.parse(msg.data));
    } catch (e) {
      console.error("Bad WS payload", e);
    }
  };
  return ws;
}
