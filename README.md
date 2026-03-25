# 🛡️ Malicious URL Detection: DevSecOps Pipeline
### **Architected by Yatharth | Student at MIET **

This repository contains a production-grade security gate that uses **Machine Learning** to scan URLs within CI/CD pipelines.

---

## 🏗️ System Architecture
The system follows a "Shift-Left" security model, intercepting threats before they reach production.



### **Operational Phases:**
* **Dynamic Acquisition:** Uses **Playwright** to crawl URLs in a headless Chromium sandbox.
* **Feature Extraction:** Converts HTML/Security metadata into a **12-dimensional vector**.
* **Intelligence Engine:** Uses **LightGBM** to calculate a probability score (0.0 to 1.0).
* **Automated Gating:** Integrated with **GitHub Actions** to block malicious Pull Requests.

---

## 📊 Threshold Logic
The pipeline uses the following mathematical boundaries to decide the fate of a Pull Request:

| Score | Classification | Action |
| :--- | :--- | :--- |
| **< 0.3** | ✅ Safe | **Allow Merge** |
| **0.3 - 0.7** | ⚠️ Suspicious | **Human Review Required** |
| **> 0.7** | ❌ Malicious | **Hard Block (Fail Build)** |

---

## 🛠️ Setup Instructions

### **1. Environment Setup**
```bash
pip install -r requirements.txt
playwright install chromium
