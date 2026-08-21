import { useEffect, useRef, useState } from "react";
import StatsCards from "./components/StatsCards";
import EventTable from "./components/EventTable";
import CampaignsPanel from "./components/CampaignsPanel";
import CopilotChat from "./components/CopilotChat";
import { getStats, getEvents, getCampaigns, connectLiveFeed } from "./api";

const MAX_LIVE_EVENTS = 40;

export default function App() {
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef(null);

  // Initial load: historical events + stats + campaigns
  useEffect(() => {
    getEvents("any", 24, 30).then((r) => setEvents(r.events)).catch(() => {});
    getStats(24).then(setStats).catch(() => {});
    getCampaigns(24).then((r) => setCampaigns(r.campaigns)).catch(() => {});
  }, []);

  // Live WebSocket feed
  useEffect(() => {
    const ws = connectLiveFeed((event) => {
      setEvents((prev) => [event, ...prev].slice(0, MAX_LIVE_EVENTS));
    });
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onerror = () => setConnected(false);
    wsRef.current = ws;
    return () => ws.close();
  }, []);

  // Periodically refresh stats + campaigns (every 15s) since those are aggregates
  useEffect(() => {
    const interval = setInterval(() => {
      getStats(24).then(setStats).catch(() => {});
      getCampaigns(24).then((r) => setCampaigns(r.campaigns)).catch(() => {});
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <div style={styles.titleBlock}>
          <span style={styles.shield}>🛡️</span>
          <div>
            <div style={styles.title}>AI Security Operations Copilot</div>
            <div style={styles.subtitle}>Real-time threat detection & analyst support</div>
          </div>
        </div>
        <div style={styles.status}>
          <span
            style={{
              ...styles.dot,
              background: connected ? "var(--green)" : "var(--red)",
            }}
          />
          {connected ? "Live feed connected" : "Reconnecting…"}
        </div>
      </header>

      <main style={styles.main}>
        <StatsCards stats={stats} />

        <div style={styles.grid}>
          <div style={styles.leftCol}>
            <EventTable events={events} />
          </div>
          <div style={styles.rightCol}>
            <CampaignsPanel campaigns={campaigns} />
            <CopilotChat />
          </div>
        </div>
      </main>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "16px 24px",
    borderBottom: "1px solid var(--border)",
  },
  titleBlock: { display: "flex", alignItems: "center", gap: 12 },
  shield: { fontSize: 28 },
  title: { fontSize: 18, fontWeight: 700 },
  subtitle: { fontSize: 12, color: "var(--textgray)" },
  status: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontSize: 12,
    color: "var(--textgray)",
  },
  dot: { width: 8, height: 8, borderRadius: "50%" },
  main: { flex: 1, padding: 20, overflow: "hidden", display: "flex", flexDirection: "column" },
  grid: {
    display: "grid",
    gridTemplateColumns: "1.6fr 1fr",
    gap: 16,
    flex: 1,
    minHeight: 0,
  },
  leftCol: { minHeight: 0 },
  rightCol: {
    display: "grid",
    gridTemplateRows: "1fr 1.4fr",
    gap: 16,
    minHeight: 0,
  },
};
