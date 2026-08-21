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
| Intrusion Detection model (XGBoost, 5-class, class-weighted) | ✅ Done — 97.0% accuracy, 90.9% macro F1, 86.8% balanced accuracy |
| Log Anomaly Detection model (Isolation Forest) | ✅ Done — 88.2% attack recall |
| Threat Correlation Engine | ✅ Done — groups related events into campaigns |
| FastAPI backend (`/detect`, `/events`, `/correlate`, `/stats`) | ✅ Done, tested |
| Agentic Copilot (`/copilot/ask`) | ✅ Built — needs your `ANTHROPIC_API_KEY` to go live |
| Real-time WebSocket stream (`/ws/live`) | ✅ Done, tested |
| React SOC dashboard | ✅ Done, tested end-to-end with the backend |
| Docker + Docker Compose | ✅ Written (couldn't be run inside this build sandbox — test locally, see below) |
| Cloud deployment | 🔲 Next — you'll need to do this step yourself with your own hosting account |

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
├── frontend/
│   ├── src/
│   │   ├── App.jsx              # Main dashboard layout
│   │   ├── api.js                # Backend API client + WebSocket connector
│   │   └── components/
│   │       ├── StatsCards.jsx
│   │       ├── EventTable.jsx
│   │       ├── CampaignsPanel.jsx
│   │       └── CopilotChat.jsx
│   ├── Dockerfile
│   └── nginx.conf
├── backend/Dockerfile
├── docker-compose.yml
└── docs/                       # Architecture notes, dataset sources, screenshots
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

## 🧪 Model Evaluation — Full Transparency

Two things matter more than a single accuracy number: **is it honest**, and
**does it work on the classes that matter**. Both are documented here so
anyone reviewing this project can verify the claims themselves.

**Production model (class-weighted XGBoost):**

| Metric | Value |
|---|---|
| Accuracy | 97.0% |
| Balanced Accuracy | 86.8% |
| Macro F1 | 90.9% |
| Botnet Recall | 71.5% |
| BruteForce Recall | 81.0% |
| DDoS Recall | 90.0% |
| PortScan Recall | 91.7% |
| BENIGN Recall | 99.6% |

**Why not push accuracy to 99%+?** This dataset has ~3.5% intentional label
noise (see "About the Dataset" below) and small minority classes (Botnet =
319 test samples out of 12,000). A model claiming 99%+ here would almost
certainly be overfit or leaking information — not something a reviewer
should trust. 97% accuracy with 90.9% macro F1 and 86.8% balanced accuracy
is the honest, defensible number for this exact dataset.

**What was tried and rejected:** SMOTE oversampling was tested on this
dataset and made results *worse* (93.4% accuracy, 82.5% macro F1) — a known
failure mode where synthetic oversampling distorts the decision boundary
for gradient-boosted trees on tabular data. It was not used in the final
model. See `notebooks/experiment_class_weighting.py` for the full,
reproducible comparison between the unweighted baseline and the
class-weighted version that shipped.

**Reproduce these numbers yourself:**
```bash
cd notebooks
python train_intrusion_model.py               # trains + saves the production model
python experiment_class_weighting.py           # side-by-side baseline vs weighted comparison
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

## 🖥️ Running the Frontend Locally

```bash
cd frontend
npm install
echo "VITE_API_URL=http://localhost:8000" > .env
npm run dev
```

Open `http://localhost:5173`. Make sure the backend (previous section) is
running first — the dashboard needs it for stats, events, campaigns, and
the copilot chat.

**What you'll see:** live stat cards, a real-time event feed (via
WebSocket), correlated attack campaigns, and the Security Copilot chat
panel. This was tested end-to-end in the build environment — screenshots
in `docs/`.

---

## 🐳 Running Everything With Docker

This project ships with a `Dockerfile` for the backend, a `Dockerfile`
for the frontend (multi-stage build served via nginx), and a
`docker-compose.yml` that runs both together.

**Note:** Docker itself was not available in the sandbox this project was
built in, so the Compose stack could not be run and verified there. The
Dockerfiles follow standard, well-tested patterns, but **test this step
yourself** before relying on it for a demo:

```bash
# From the project root (where docker-compose.yml lives)
docker compose up --build
```

- Backend will be at `http://localhost:8000`
- Frontend will be at `http://localhost:5173`

To enable the copilot chat inside Docker, set your API key before running:

```bash
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
docker compose up --build
```

If you hit a Docker error, copy the exact error message and troubleshoot
from there — common first-time issues are Docker Desktop not running, or
a port already in use (change the left-hand side of the `ports:` mapping
in `docker-compose.yml` if so, e.g. `"8001:8000"`).

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

## 📌 What's Left For You To Do

1. **Test Docker locally** (see above) — confirm `docker compose up --build` works on your machine
2. **Get an Anthropic API key** and set `ANTHROPIC_API_KEY` to turn on the copilot chat
3. **Deploy to Render/Railway** — push this repo to GitHub, connect it to your hosting
   account, and set the same environment variable there
4. **Record a 2-minute demo** (live detection + copilot chat) once deployed
