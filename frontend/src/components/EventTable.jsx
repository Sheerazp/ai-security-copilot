const SEVERITY_COLOR = {
  normal: "var(--green)",
  suspicious: "var(--orange)",
  critical: "var(--red)",
};

export default function EventTable({ events }) {
  return (
    <div style={styles.wrap}>
      <div style={styles.header}>
        <span>🔴 Live Event Feed</span>
        <span style={styles.count}>{events.length} events</span>
      </div>
      <div style={styles.tableWrap}>
        <table style={styles.table}>
          <thead>
            <tr>
              <th style={styles.th}>Time</th>
              <th style={styles.th}>Source IP</th>
              <th style={styles.th}>Type</th>
              <th style={styles.th}>Severity</th>
              <th style={styles.th}>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 && (
              <tr>
                <td colSpan={5} style={styles.empty}>Waiting for events…</td>
              </tr>
            )}
            {events.map((e, i) => (
              <tr key={e.id ?? i} style={i === 0 ? styles.newRow : undefined}>
                <td style={styles.td}>
                  {new Date(e.timestamp).toLocaleTimeString()}
                </td>
                <td style={{ ...styles.td, fontFamily: "monospace" }}>{e.src_ip}</td>
                <td style={styles.td}>{e.predicted_label}</td>
                <td style={styles.td}>
                  <span
                    style={{
                      ...styles.badge,
                      background: SEVERITY_COLOR[e.severity] || "var(--textgray)",
                    }}
                  >
                    {e.severity}
                  </span>
                </td>
                <td style={styles.td}>
                  {e.confidence != null ? `${Math.round(e.confidence * 100)}%` : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
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
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    padding: "12px 16px",
    borderBottom: "1px solid var(--border)",
    fontWeight: 600,
  },
  count: { fontSize: 12, color: "var(--textgray)", fontWeight: 400 },
  tableWrap: { overflowY: "auto", flex: 1 },
  table: { width: "100%", borderCollapse: "collapse", fontSize: 13 },
  th: {
    textAlign: "left",
    padding: "8px 16px",
    color: "var(--textgray)",
    fontWeight: 500,
    position: "sticky",
    top: 0,
    background: "var(--card-dark)",
    borderBottom: "1px solid var(--border)",
  },
  td: { padding: "8px 16px", borderBottom: "1px solid var(--border)" },
  empty: { padding: 20, textAlign: "center", color: "var(--textgray)" },
  badge: {
    padding: "2px 10px",
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 700,
    color: "#0b0f19",
    textTransform: "uppercase",
  },
  newRow: {
    animation: "none",
    background: "rgba(0,217,255,0.06)",
  },
};
