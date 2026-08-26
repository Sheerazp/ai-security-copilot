# AI Security Operations Copilot

AI Security Operations Copilot is a cybersecurity monitoring project that combines machine learning, anomaly detection, event correlation, and an AI assistant to help analysts investigate security events.

The system is designed as a read-only analyst tool. It analyzes security data and provides recommendations, but it does not block IPs, disable accounts, or make changes to the environment.

## What the project does

The system processes security events and produces:

* attack classification
* anomaly detection
* severity information
* correlated attack campaigns
* live event monitoring
* AI-assisted investigation

## Machine Learning

The project uses two main ML approaches.

### XGBoost

XGBoost is used for supervised network attack classification.

The classifier predicts:

* BENIGN
* DDoS
* PortScan
* BruteForce
* Botnet

Reported evaluation results for the current model:

| Metric            | Result |
| ----------------- | -----: |
| Accuracy          |  97.0% |
| Balanced Accuracy |  86.8% |
| Macro F1          |  90.9% |

### Isolation Forest

Isolation Forest is used separately for anomaly detection.

It produces:

* anomaly score
* anomaly flag

This helps identify unusual network behavior in addition to the attack classification result.

## Threat Correlation

The correlation layer groups related suspicious events based on source and timing. This helps turn repeated individual alerts into a more useful view of a possible attack campaign.

## Security Copilot

The project includes a Gemini-powered Security Copilot.

An analyst can ask questions such as:

* What was the most serious threat in the last 24 hours?
* Which source IP generated the most suspicious activity?
* Are there any correlated attack campaigns?
* What should I investigate first?

The Copilot uses security evidence from the backend and returns an explanation with recommended next steps.

The Copilot is intentionally read-only.

## System Flow

```text
Security Events
      |
      v
Feature Processing
      |
      +----------------------+
      |                      |
      v                      v
   XGBoost             Isolation Forest
      |                      |
      v                      v
Attack Type             Anomaly Score
      |                      |
      +----------+-----------+
                 |
                 v
              Severity
                 |
                 v
        Correlation Engine
                 |
                 v
              Database
                 |
        +--------+--------+
        |                 |
        v                 v
     Dashboard        Gemini Copilot
```

## Technology

Backend:

* Python
* FastAPI
* SQLAlchemy
* Pandas
* Scikit-learn
* XGBoost
* Joblib
* Google Gemini

Frontend:

* React
* Vite
* WebSocket

Deployment:

* Railway
* Vercel

## Project Structure

```text
security-copilot/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── ml_service.py
│   │   ├── copilot.py
│   │   ├── correlation.py
│   │   ├── database.py
│   │   └── schemas.py
│   └── requirements.txt
├── data/
├── models/
├── notebooks/
├── frontend/
├── docs/
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Live Demo

Frontend:

https://ai-security-copilot-eight.vercel.app/

Backend API:

https://ai-security-copilot-production-cc51.up.railway.app/

API documentation:

https://ai-security-copilot-production-cc51.up.railway.app/docs

## Notes

The current system is primarily a security monitoring and analyst-support project. The ML models, backend APIs, dashboard, correlation layer, and Gemini Copilot are integrated into the deployed application.

The ML evaluation numbers above refer to the current training/evaluation setup used in this repository. They should be interpreted together with class-level performance rather than accuracy alone.

## Current Scope

The current version focuses on:

1. network event classification
2. anomaly detection
3. severity and event analysis
4. attack correlation
5. live monitoring
6. AI-assisted security investigation

Future improvements can include additional real-world log sources, explainable ML, threat-intelligence enrichment, and broader telemetry ingestion.
