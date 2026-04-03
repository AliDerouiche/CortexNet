# CortexNet — AI-Powered Network Anomaly Detection

> Real-time network intrusion detection system using PyTorch Deep Learning, trained on CICIDS2018 (16M+ flows).

**Developed by Ali Derouiche — Cybersecurity Engineer & AI Researcher**

---

## Overview

CortexNet is a desktop application that monitors live network traffic and detects malicious activity in real time using a deep learning model trained on the CICIDS2018 dataset. It captures packets directly from your network interface, extracts 34 statistical features per flow window, and classifies traffic as benign or attack with **96.02% accuracy**.

---

## Demo

```
[00:53:03]  BENIGN     prob=0.043  conf=95.7%  |  pkts=50  SYN=0  RST=0  ports=8   IPs=4
[00:53:07]  BENIGN     prob=0.061  conf=93.9%  |  pkts=50  SYN=1  RST=0  ports=6   IPs=3
[00:53:14]  ATTACK     prob=0.923  conf=92.3%  |  pkts=50  SYN=48 RST=2  ports=312 IPs=1
```

---

## Model Performance

| Metric    | Score  |
|-----------|--------|
| Accuracy  | 96.02% |
| Precision | 97.51% |
| Recall    | 94.45% |
| F1-Score  | 95.95% |

**Architecture:** PyTorch Neural Network (53,121 parameters)
```
Input(34) → Dense(256) + BN + ReLU + Dropout(0.3)
          → Dense(128) + BN + ReLU + Dropout(0.3)
          → Dense(64)  + BN + ReLU + Dropout(0.2)
          → Dense(32)  + ReLU
          → Dense(1)   + Sigmoid
```

**Training:** 600,000 balanced flows (300K benign + 300K attacks) — 86 seconds on RTX 3050

---

## Attack Coverage (14 categories)

| Category | Attack Types |
|---|---|
| Brute Force | FTP-BruteForce, SSH-Bruteforce, Web Brute Force |
| DDoS | LOIC-HTTP, LOIC-UDP, HOIC |
| DoS | GoldenEye, Slowloris, SlowHTTPTest, Hulk |
| Web Attacks | XSS, SQL Injection |
| Other | Botnet, Infiltration |

---

## Features (34 total)

Extracted from 50 live packets per analysis window:

| Family | Features |
|---|---|
| Volume | Tot Fwd/Bwd Pkts, TotLen Fwd/Bwd Pkts, Flow Byts/s, Flow Pkts/s |
| Packet size | Pkt Len Min/Max/Mean/Std, Fwd/Bwd Pkt Len ×4, Pkt Size Avg |
| Timing (IAT) | Flow IAT Mean/Std, Fwd/Bwd IAT Tot/Mean, Seg Size Avg ×2 |
| TCP flags | SYN, RST, FIN, PSH, ACK, URG Flag Count |
| Direction | Down/Up Ratio |

---

## Project Structure

```
CortexNet/
├── entrainement.py       # PyTorch training script
├── CortexNet.py       # Main GUI application
├── embed_models.py       # Embed .pkl/.pt into models_data.py
├── models_data.py        # Auto-generated — embedded models (base64)
├── colonnes.py  # Dataset column inspector
└── README.md
```

---

## Requirements

### Runtime (end users)
- Windows 10/11
- [Wireshark + Npcap](https://www.wireshark.org/download.html) — required for live capture

### Development
```
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install pyshark scikit-learn pandas numpy joblib pyarrow pyinstaller
```

---

## Usage

### 1. Train the model
```bash
python entrainement.py
```
Trains on CICIDS2018 CSV files. Saves `modele.pt`, `scaler.pkl`, `features.pkl` to Desktop.

### 2. Embed models
```bash
python embed_models.py
```
Encodes the 3 model files into `models_data.py` (base64) — enables standalone exe.

### 3. Run the application
```bash
python CortexNet.py
```

### 4. Build standalone executable
```bash
python -m PyInstaller --onefile --windowed --name "CortexNet" \
  --add-data "models_data.py;." \
  --collect-all sklearn \
  --hidden-import torch \
  --collect-all torch \
  CortexNet.py
```

---

## Dataset

**CICIDS2018** — Canadian Institute for Cybersecurity  
- 10 CSV files, ~6.89 GB  
- 16,137,183 total flows  
- 15 labels (1 benign + 14 attack categories)  
- Available on [Kaggle](https://www.kaggle.com/datasets/solarmainframe/ids-intrusion-csv)

---

## How It Works

```
Live packets (Wi-Fi / Ethernet)
        ↓  pyshark captures 50 packets
Extract 34 statistical features
        ↓  StandardScaler normalization
PyTorch Neural Network inference
        ↓  probability [0.0 → 1.0]
threshold (default 0.5)
        ↓
BENIGN ✅  or  ATTACK 🚨
```

---

## Author

**Ali Derouiche**  
Cybersecurity Engineering Student — EPI Digital School, Sousse, Tunisia  
Specialization: Cybersecurity & AI  


---

## License

MIT License — feel free to use, modify, and distribute.
