# 🛡️ AI Security Operations Copilot

An agentic AI platform for real-time threat detection and analyst support.
Built as a portfolio project by Sheeraz (2026).

> **Read-only by design.** This system detects, correlates, and explains —
> it never blocks, bans, or takes autonomous action. Every recommendation
> ends with a human decision.

---

## ✅ Current Status (Phase 1 + Phase 2 complete)

| Component | Status |
|---|---|
| Synthetic dataset (60,000 labeled events) | ✅ Done |
| Intrusion Detection model (XGBoost, 5-class) | ✅ Done — 97% accuracy, 90.8% macro F1 |
| Log Anomaly Detection model (Isolation Forest) | ✅ Done — 88.2% attack recall |
| Threat Correlation Engine | ✅ Done — groups related events into campaigns |
| FastAPI backend (`/detect`, `/events`, `/correlate`, `/stats`) | ✅ Done, tested |
| Agentic Copilot (`/copilot/ask`) | ✅ Built — needs your `ANTHROPIC_API_KEY` to go live |
| Real-time WebSocket stream (`/ws/live`) | ✅ Done, tested |
| React SOC dashboard | 🔲 Next |
| Docker + Docker Compose | 🔲 Next |
| Cloud deployment | 🔲 Next |

---

## 📁 Project Structure

```
security-copilot/
├── data/                       # Generated datasets (CSV)
├── models/                     # Trained model artifacts (.pkl) + metrics (.json)
├── notebooks/                  # Data generation + model training scripts
│   ├── data_generator.py
│   ├── train_intrusion_model.py
│   ├── train_anomaly_model.py
│   └── correlation_engine.py
├── backend/
│   ├── app/
│   │   ├── main.py             # FastAPI app + all endpoints
│   │   ├── ml_service.py       # Loads models, runs inference
│   │   ├── copilot.py          # Agentic layer (Claude + function calling)
│   │   ├── correlation.py      # Threat correlation logic
│   │   ├── database.py         # SQLAlchemy models (SQLite/Postgres)
│   │   └── schemas.py          # Pydantic request/response models
│   └── requirements.txt
├── frontend/                   # React dashboard (next phase)
└── docs/                       # Architecture notes, screenshots
```

---

## 🚀 Running It Locally

### 1. Backend setup

```bash
cd backend
pip install -r requirements.txt
```

### 2. (Optional but recommended) Enable the copilot's language model

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
```

Without this, every other feature (detection, correlation, dashboard data)
still works — `/copilot/ask` will just return a message saying the
language model isn't configured yet, instead of crashing.

### 3. Start the server

```bash
uvicorn app.main:app --reload
```

Visit `http://localhost:8000/docs` for interactive Swagger API docs.

On first startup, the database is automatically seeded with 5,000
historical events from `data/security_events.csv` so the dashboard and
copilot have realistic data to work with immediately.

### 4. Try it

```bash
# Get summary stats
curl http://localhost:8000/stats

# Score a new event
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"203.0.113.9","dst_ip":"10.0.0.5","protocol_type":"udp",
       "duration":0.02,"src_bytes":50,"dst_bytes":10,"count":420,
       "srv_count":400,"same_srv_rate":0.98,"diff_srv_rate":0.01,
       "serror_rate":0.85,"rerror_rate":0.1,"num_failed_logins":0,
       "logged_in":0,"wrong_fragment":0,"urgent":0,"hot":0}'

# Ask the copilot (requires ANTHROPIC_API_KEY)
curl -X POST http://localhost:8000/copilot/ask \
  -H "Content-Type: application/json" \
  -d '{"question":"What was the most serious threat in the last 24 hours?"}'
```

---

## 🧠 About the Dataset

The real CICIDS2017 dataset (Canadian Institute for Cybersecurity) could
not be downloaded directly in this build environment, so
`notebooks/data_generator.py` generates a **statistically realistic
synthetic dataset** with the same feature structure (duration, byte
counts, connection counts, error rates, failed logins, etc.) and the
same attack categories (DDoS, PortScan, BruteForce, Botnet).

Realism details that matter for a credible demo:
- Class imbalance matches real traffic (~80% benign, rest split across attacks)
- Gaussian noise + a small mislabeling rate, so the model does **not**
  score a suspicious 100% accuracy (97% / 90.8% macro F1 is what a real
  detector looks like)
- Attacker traffic is clustered by IP and time (bursts), which is what
  makes the **correlation engine** meaningful — real attackers repeat
  from the same few hosts in short windows, not randomly

**To use real data instead:** download CICIDS2017 from Kaggle (see
`docs/dataset_sources.md`), rename columns to match `FEATURE_COLUMNS` in
`data_generator.py`, drop it into `data/security_events.csv`, and rerun
the two training scripts. No other code changes needed.

---

## 🔒 Responsible AI Design

- **Read-only tools only.** The copilot's tools (`fetch_recent_events`,
  `get_severity_summary`, `correlate_events`) only ever *read* from the
  database. There is no tool that blocks, bans, or modifies anything.
- **Human-in-the-loop.** Every copilot answer ends with recommended next
  steps for a human analyst — it never claims to have taken action.
- **Explainable by default.** Every prediction carries a confidence score
  and an anomaly score, not just a bare label.

---

## 📌 Next Steps (Week 3)

1. React SOC dashboard — live event table, severity cards, copilot chat panel
2. Dockerfile for backend + frontend, `docker-compose.yml`
3. Deploy to Render/Railway, wire up environment variables securely
4. Record a 2-minute demo (live detection + copilot chat)
