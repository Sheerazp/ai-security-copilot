export default function StatsCards({ stats }) {
  const cards = [
    { label: "Total Events", value: stats?.total_events ?? "—", color: "var(--cyan)" },
    { label: "Normal", value: stats?.normal ?? "—", color: "var(--green)" },
    { label: "Suspicious", value: stats?.suspicious ?? "—", color: "var(--orange)" },
    { label: "Critical", value: stats?.critical ?? "—", color: "var(--red)" },
    { label: "Active Campaigns", value: stats?.active_campaigns ?? "—", color: "var(--magenta)" },
  ];

  return (
    <div style={styles.grid}>
      {cards.map((c) => (
        <div key={c.label} style={styles.card}>
          <div style={{ ...styles.value, color: c.color }}>{c.value}</div>
          <div style={styles.label}>{c.label}</div>
        </div>
      ))}
    </div>
  );
}

const styles = {
  grid: {
    display: "grid",
    gridTemplateColumns: "repeat(5, 1fr)",
    gap: 12,
    marginBottom: 20,
  },
  card: {
    background: "var(--card-dark)",
    border: "1px solid var(--border)",
    borderRadius: 12,
    padding: "16px 14px",
    textAlign: "center",
  },
  value: {
    fontSize: 28,
    fontWeight: 700,
  },
  label: {
    fontSize: 12,
    color: "var(--textgray)",
    marginTop: 4,
    textTransform: "uppercase",
    letterSpacing: 0.5,
  },
};
