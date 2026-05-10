
# AI Threat Hunter

A cybersecurity research project designed to explore the intersection of machine learning, anomaly detection, and real-time threat analysis, while explaining threats in plain English. The system ingests network traffic data, detects unusual behavior, classifies threats, and lays the foundation for LLM-powered contextual explanations — all aimed at automating parts of the threat hunting process.

## Project Progress

| Phase | Status |
|-------|--------|
| Load & Inspect Dataset | ✅ |
| Data Cleaning + Preprocessing | ✅ |
| Anomaly Detection Model | ✅ |
| Threat Classification & MITRE Mapping |In Progress |
| LLM-Powered Explanation Engine | Next |
| CLI or Streamlit Dashboard | Later |
| Dockerization & Deployment | Final Phase |

---

## Features

- Ingests and inspects real network traffic datasets (CSV format)
- Cleans, preprocesses, and encodes data for machine learning
- Anomaly detection using AI models like Isolation Forest and AutoEncoders
- Threat classification & potential mapping to [MITRE ATT&CK](https://attack.mitre.org/)
- (Planned) GPT/LLM-based explanation of threats for human analysts
- (Planned) CLI tool or Streamlit dashboard for visual exploration
- (Planned) Dockerized deployment for portable threat hunting

---

- **Languages:** Python 3.x
- **Libraries:**  
  `pandas`, `numpy`, `scikit-learn`, `matplotlib`, `seaborn`  
- **Future Tools:** GPT-4 API (or other LLM), MITRE ATT&CK framework, Docker

---

## Project Structure

