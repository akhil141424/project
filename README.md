# Aegis: Hybrid AI Intrusion Detection System (IDS)

**A Next-Gen AI-Powered IDS detecting Zero-Day attacks using Isolation Forests and Autoencoders.**

![Project Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Docker-lightgrey)

## 📌 Overview
Traditional firewalls rely on "signatures" (rules) to catch attacks, which means they fail against new, unknown threats (**Zero-Day Attacks**). 

**Aegis** is a Hybrid IDS that solves this by combining two unsupervised AI models:
1.  **Isolation Forest:** Detects statistical outliers (e.g., DoS floods) instantly.
2.  **Deep Autoencoder:** Detects complex, non-linear pattern deviations (e.g., subtle infiltration attempts).

This project includes a **Real-Time Dashboard**, a **Network Sniffer**, and an **Attack Simulator** to verify detection.

---

## 🏗️ Architecture
The system consists of three modular components:

1.  **The Sensor (`sniffer.py`):** * Captures live network traffic using `Scapy`.
    * Extracts 10+ statistical features (Packet size, TTL, TCP Flags, Window size).
2.  **The Brain (`brain.py`):** * **Model A:** Isolation Forest (Scikit-Learn).
    * **Model B:** Deep Autoencoder (TensorFlow/Keras).
    * Analyzes features in real-time and assigns a "Severity Score".
3.  **The Face (`server.py` & Dashboard):** * FastAPI Backend serving a responsive HTML5 Dashboard.
    * Visualizes threats via WebSockets/API polling.

---

## ⚙️ Installation

### Prerequisites
* Python 3.8 or higher.
* **Windows Users ONLY:** You MUST install **[Npcap](https://npcap.com/#download)**.
    * *Critical:* During installation, check the box **"Install Npcap in WinPcap API-compatible Mode"**.

### Setup
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/aegis-ids.git](https://github.com/yourusername/aegis-ids.git)
    cd aegis-ids
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # Linux/Mac:
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🚀 How to Run
You need to run **two separate terminals**.

**Terminal 1: The Dashboard Server
Start the backend server to visualize alerts.**
```bash
python server.py```

**Terminal 2: The Network Sensor
Start the sniffer to capture traffic. (Requires Admin/Root privileges).**
'''bash
python sniffer.py
