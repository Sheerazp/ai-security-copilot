export default function CampaignsPanel({ campaigns }) {
  return (
    <div style={styles.wrap}>
      <div style={styles.header}>🕸️ Correlated Attack Campaigns</div>
      <div style={styles.list}>
        {campaigns.length === 0 && (
          <div style={styles.empty}>No correlated campaigns in this window.</div>
        )}
        {campaigns.map((c, i) => (
          <div key={i} style={styles.item}>
            <div style={styles.itemHeader}>
              <span style={{ fontFamily: "monospace" }}>{c.src_ip}</span>
              <span
                style={{
                  ...styles.sevBadge,
                  background:
                    c.max_severity === "critical" ? "var(--red)" : "var(--orange)",
                }}
              >
                {c.max_severity}
              </span>
            </div>
            <div style={styles.summary}>{c.summary}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

const styles = {
  wrap: {
    background: "var(--card-dark)",
    border: "1px solid var(--border)",
    borderRadius: 12,
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
    height: "100%",
  },
  header: {
    padding: "12px 16px",
    borderBottom: "1px solid var(--border)",
    fontWeight: 600,
  },
  list: { overflowY: "auto", flex: 1, padding: 12 },
  empty: { color: "var(--textgray)", fontSize: 13, padding: 8 },
  item: {
    background: "var(--card-dark-2)",
    borderRadius: 8,
    padding: 12,
    marginBottom: 10,
  },
  itemHeader: {
    display: "flex",
    justifyContent: "space-between",
    marginBottom: 6,
    fontSize: 13,
  },
  sevBadge: {
    padding: "1px 8px",
    borderRadius: 999,
    fontSize: 10,
    fontWeight: 700,
    color: "#0b0f19",
    textTransform: "uppercase",
  },
  summary: { fontSize: 12.5, color: "var(--textgray)", lineHeight: 1.4 },
};
