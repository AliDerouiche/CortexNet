"""
CortexSecure Network Analyser
Developed by Ali Derouiche - Cybersecurity Engineer & AI Researcher
PyTorch Deep Learning Edition
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import asyncio
import time
import numpy as np
import joblib
import pyshark
import os
import sys
import subprocess
import base64
import io
import torch
import torch.nn as nn

# ================================================================
# HIDE TSHARK WINDOWS ON WINDOWS
# ================================================================
if os.name == "nt":
    _orig_popen = subprocess.Popen
    def _silent_popen(*args, **kwargs):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x08000000
        kwargs["startupinfo"]   = si
        return _orig_popen(*args, **kwargs)
    subprocess.Popen = _silent_popen

    _orig_create = asyncio.create_subprocess_exec
    async def _silent_create(*args, **kwargs):
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x08000000
        kwargs["startupinfo"]   = si
        return await _orig_create(*args, **kwargs)
    asyncio.create_subprocess_exec = _silent_create

# ================================================================
# PYTORCH MODEL DEFINITION
# ================================================================

class NetworkClassifier(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.net(x).squeeze(1)

# ================================================================
# LOAD EMBEDDED MODELS
# ================================================================

def load_embedded_models():
    import models_data as md
    import warnings
    warnings.filterwarnings("ignore")

    # Load scaler and features
    scaler   = joblib.load(io.BytesIO(base64.b64decode(md.SCALER)))
    features = joblib.load(io.BytesIO(base64.b64decode(md.FEATURES)))
    if isinstance(features, (list, np.ndarray)) and len(features) == 1:
        features = list(features[0])
    features = list(features)

    # Load PyTorch model
    model_bytes = base64.b64decode(md.MODELE)
    checkpoint  = torch.load(io.BytesIO(model_bytes), map_location="cpu")
    input_dim   = checkpoint["input_dim"]
    model       = NetworkClassifier(input_dim=input_dim)
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()

    return model, scaler, features

# ================================================================
# CAPTURE & FEATURE EXTRACTION
# ================================================================

def capture_and_extract(interface):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(packet_count=50)
    packets = []
    for pkt in capture:
        try:
            syn = rst = fin = psh = ack = urg = 0
            dst_port = src_port = 0
            size = int(pkt.length)
            if hasattr(pkt, "tcp"):
                flags    = int(pkt.tcp.flags, 16)
                syn      = 1 if (flags & 0x02) else 0
                rst      = 1 if (flags & 0x04) else 0
                fin      = 1 if (flags & 0x01) else 0
                psh      = 1 if (flags & 0x08) else 0
                ack      = 1 if (flags & 0x10) else 0
                urg      = 1 if (flags & 0x20) else 0
                dst_port = int(pkt.tcp.dstport)
                src_port = int(pkt.tcp.srcport)
            elif hasattr(pkt, "udp"):
                dst_port = int(pkt.udp.dstport)
                src_port = int(pkt.udp.srcport)
            src_ip = str(pkt.ip.src) if hasattr(pkt, "ip") else "?"
            packets.append({
                "src_ip": src_ip, "dst_port": dst_port,
                "src_port": src_port, "size": size,
                "syn": syn, "rst": rst, "fin": fin,
                "psh": psh, "ack": ack, "urg": urg,
            })
        except Exception:
            pass

    n = len(packets)
    if n == 0:
        return None

    sizes    = [p["size"] for p in packets]
    nb_fwd   = sum(1 for p in packets if p["dst_port"] >= 1024)
    nb_bwd   = n - nb_fwd
    size_avg = float(np.mean(sizes))
    size_std = float(np.std(sizes))
    size_max = float(max(sizes))
    size_min = float(min(sizes))

    fwd_sizes = [p["size"] for p in packets if p["dst_port"] >= 1024] or [0]
    bwd_sizes = [p["size"] for p in packets if p["dst_port"] < 1024]  or [0]

    feats = {
        "Tot Fwd Pkts"       : nb_fwd,
        "Tot Bwd Pkts"       : nb_bwd,
        "TotLen Fwd Pkts"    : sum(fwd_sizes),
        "TotLen Bwd Pkts"    : sum(bwd_sizes),
        "Fwd Pkt Len Max"    : float(max(fwd_sizes)),
        "Fwd Pkt Len Min"    : float(min(fwd_sizes)),
        "Fwd Pkt Len Mean"   : float(np.mean(fwd_sizes)),
        "Fwd Pkt Len Std"    : float(np.std(fwd_sizes)),
        "Bwd Pkt Len Max"    : float(max(bwd_sizes)),
        "Bwd Pkt Len Min"    : float(min(bwd_sizes)),
        "Bwd Pkt Len Mean"   : float(np.mean(bwd_sizes)),
        "Bwd Pkt Len Std"    : float(np.std(bwd_sizes)),
        "Flow Byts/s"        : sum(sizes) * 10.0,
        "Flow Pkts/s"        : n * 10.0,
        "Flow IAT Mean"      : 1e5,
        "Flow IAT Std"       : 5e4,
        "Fwd IAT Tot"        : sum(fwd_sizes),
        "Fwd IAT Mean"       : 1e5,
        "Bwd IAT Tot"        : sum(bwd_sizes),
        "Bwd IAT Mean"       : 1e5,
        "FIN Flag Cnt"       : sum(p["fin"] for p in packets),
        "SYN Flag Cnt"       : sum(p["syn"] for p in packets),
        "RST Flag Cnt"       : sum(p["rst"] for p in packets),
        "PSH Flag Cnt"       : sum(p["psh"] for p in packets),
        "ACK Flag Cnt"       : sum(p["ack"] for p in packets),
        "URG Flag Cnt"       : sum(p["urg"] for p in packets),
        "Pkt Len Min"        : size_min,
        "Pkt Len Max"        : size_max,
        "Pkt Len Mean"       : size_avg,
        "Pkt Len Std"        : size_std,
        "Pkt Size Avg"       : size_avg,
        "Fwd Seg Size Avg"   : float(np.mean(fwd_sizes)),
        "Bwd Seg Size Avg"   : float(np.mean(bwd_sizes)),
        "Down/Up Ratio"      : nb_bwd / (nb_fwd + 1),
    }

    stats = {
        "n"    : n,
        "syn"  : sum(p["syn"] for p in packets),
        "rst"  : sum(p["rst"] for p in packets),
        "ports": len(set(p["dst_port"] for p in packets)),
        "ips"  : len(set(p["src_ip"]   for p in packets)),
        "size" : round(size_avg, 1),
    }
    return feats, stats

# ================================================================
# THEME
# ================================================================

BG      = "#060a12"
BG2     = "#0a1120"
BG3     = "#0f1a2e"
BG4     = "#162035"
BORDER  = "#1e2d4a"
CYAN    = "#00c8f0"
CYAN2   = "#0090b8"
GREEN   = "#00e676"
GREEN2  = "#00a854"
RED     = "#ff1744"
RED2    = "#b71c1c"
AMBER   = "#ffab00"
PURPLE  = "#7c4dff"
TXTPRI  = "#e8edf5"
TXTSEC  = "#5a7090"
TXTDIM  = "#2d4060"

MONO       = "Consolas"
FONT_LABEL = (MONO, 9, "bold")
FONT_VALUE = (MONO, 24, "bold")
FONT_LOG   = (MONO, 10)
FONT_BTN   = (MONO, 10, "bold")
FONT_SUB   = (MONO, 10)
FONT_BADGE = (MONO, 8, "bold")

# ================================================================
# APP
# ================================================================

class CortexSecure:
    def __init__(self, root):
        self.root = root
        self.root.title("CortexNet  |  Network Analyser")
        self.root.configure(bg=BG)
        self.root.geometry("1100x780")
        self.root.minsize(960, 660)

        self.running      = False
        self.thread       = None
        self.nb_total     = 0
        self.nb_anomalies = 0
        self.model = self.scaler = self.features = None
        self.threshold = tk.DoubleVar(value=0.5)

        self._build()
        self._load_models()

    def _build(self):
        # Top bar
        topbar = tk.Frame(self.root, bg=BG2)
        topbar.pack(fill="x")
        tk.Frame(topbar, bg=CYAN, width=4).pack(side="left", fill="y")

        left = tk.Frame(topbar, bg=BG2, padx=16, pady=12)
        left.pack(side="left")
        title_row = tk.Frame(left, bg=BG2)
        title_row.pack(anchor="w")
        tk.Label(title_row, text="CORTEX", font=(MONO, 22, "bold"),
                 fg=CYAN, bg=BG2).pack(side="left")
        tk.Label(title_row, text="Net", font=(MONO, 22, "bold"),
                 fg=TXTPRI, bg=BG2).pack(side="left")
        tk.Label(title_row, text="  //  Network Analyser",
                 font=(MONO, 11), fg=TXTSEC, bg=BG2).pack(side="left", padx=6)
        tk.Label(left,
                 text="AI-Powered Intrusion Detection  |  CICIDS2018  |  PyTorch Deep Learning  |  Accuracy: 96.02%",
                 font=FONT_SUB, fg=TXTSEC, bg=BG2).pack(anchor="w")

        right = tk.Frame(topbar, bg=BG2, padx=20, pady=12)
        right.pack(side="right")
        tk.Label(right, text="By Ali Derouiche",
                 font=(MONO, 10, "bold"), fg=CYAN, bg=BG2).pack(anchor="e")
        tk.Label(right, text="Cybersecurity Engineer & AI Researcher",
                 font=FONT_SUB, fg=TXTSEC, bg=BG2).pack(anchor="e")

        tk.Frame(self.root, bg=CYAN, height=2).pack(fill="x")

        # Model status
        panel = tk.Frame(self.root, bg=BG3, pady=10, padx=18)
        panel.pack(fill="x", padx=16, pady=(10, 0))
        tk.Label(panel, text="ML ENGINE", font=FONT_LABEL,
                 fg=CYAN, bg=BG3).pack(side="left")
        self.lbl_status = tk.Label(panel, text="Loading embedded models...",
                                   font=FONT_SUB, fg=AMBER, bg=BG3)
        self.lbl_status.pack(side="left", padx=16)

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(10, 0))

        # Control bar
        ctrl = tk.Frame(self.root, bg=BG2, pady=10, padx=18)
        ctrl.pack(fill="x", padx=16, pady=(4, 0))

        iface_col = tk.Frame(ctrl, bg=BG2)
        iface_col.pack(side="left")
        tk.Label(iface_col, text="NETWORK INTERFACE",
                 font=FONT_LABEL, fg=TXTSEC, bg=BG2).pack(anchor="w")
        self.iface_var = tk.StringVar(value="Wi-Fi")
        self._style_combobox()
        ttk.Combobox(iface_col, textvariable=self.iface_var,
                     width=28, state="readonly",
                     values=["Wi-Fi", "Ethernet", "Ethernet 3",
                             "VMware Network Adapter VMnet1",
                             "VMware Network Adapter VMnet8"]
                     ).pack(anchor="w", pady=(3, 0))

        # Threshold slider
        thresh_col = tk.Frame(ctrl, bg=BG2, padx=24)
        thresh_col.pack(side="left")
        self.lbl_thresh = tk.Label(thresh_col,
                                   text=f"THRESHOLD  {self.threshold.get():.2f}",
                                   font=FONT_LABEL, fg=TXTSEC, bg=BG2)
        self.lbl_thresh.pack(anchor="w")
        tk.Scale(thresh_col, variable=self.threshold,
                 from_=0.10, to=0.90, resolution=0.05,
                 orient="horizontal", length=160,
                 bg=BG2, fg=TXTPRI, troughcolor=BG4,
                 highlightthickness=0, bd=0, showvalue=False,
                 command=self._on_threshold).pack(anchor="w")

        # Status
        status_col = tk.Frame(ctrl, bg=BG2, padx=24)
        status_col.pack(side="left")
        tk.Label(status_col, text="STATUS",
                 font=FONT_LABEL, fg=TXTSEC, bg=BG2).pack(anchor="w")
        self.lbl_run = tk.Label(status_col, text="●  IDLE",
                                font=(MONO, 13, "bold"), fg=TXTDIM, bg=BG2)
        self.lbl_run.pack(anchor="w", pady=(3, 0))

        self.btn_start = tk.Button(ctrl, text="▶  START",
                                   font=(MONO, 12, "bold"),
                                   fg=BG, bg=GREEN,
                                   activebackground=GREEN2, activeforeground=BG,
                                   bd=0, padx=28, pady=10,
                                   cursor="hand2", relief="flat",
                                   command=self._toggle)
        self.btn_start.pack(side="right")

        tk.Frame(self.root, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(8, 0))

        # Stat cards
        cards = tk.Frame(self.root, bg=BG)
        cards.pack(fill="x", padx=16, pady=8)
        self.c_total = self._card(cards, 0, "TOTAL ANALYSES", "0",    CYAN)
        self.c_alert = self._card(cards, 1, "ANOMALIES",      "0",    RED)
        self.c_rate  = self._card(cards, 2, "ALERT RATE",     "0.0%", AMBER)
        self.c_conf  = self._card(cards, 3, "CONFIDENCE",     "--",   PURPLE)
        self.c_pkts  = self._card(cards, 4, "LAST PACKETS",   "--",   GREEN)
        for i in range(5):
            cards.columnconfigure(i, weight=1)

        # Live feed
        feed_hdr = tk.Frame(self.root, bg=BG4, pady=6, padx=14)
        feed_hdr.pack(fill="x", padx=16)
        tk.Label(feed_hdr, text="◈  LIVE FEED",
                 font=(MONO, 9, "bold"), fg=CYAN, bg=BG4).pack(side="left")
        tk.Button(feed_hdr, text="CLEAR LOG", font=FONT_BADGE,
                  fg=TXTSEC, bg=BG4, activebackground=BG3,
                  bd=0, cursor="hand2", relief="flat",
                  command=self._clear).pack(side="right")

        self.log = scrolledtext.ScrolledText(
            self.root, bg=BG2, fg=TXTPRI, font=FONT_LOG,
            insertbackground=CYAN, bd=0, padx=14, pady=10,
            relief="flat", state="disabled", wrap="none")
        self.log.pack(fill="both", expand=True, padx=16)

        self.log.tag_config("ok",    foreground=GREEN)
        self.log.tag_config("alert", foreground=RED)
        self.log.tag_config("info",  foreground=CYAN)
        self.log.tag_config("warn",  foreground=AMBER)
        self.log.tag_config("dim",   foreground=TXTSEC)

        # Footer
        tk.Frame(self.root, bg=CYAN, height=1).pack(fill="x")
        foot = tk.Frame(self.root, bg=BG2, pady=5, padx=16)
        foot.pack(fill="x")
        tk.Label(foot,
                 text="CortexNet Network Analyser  |  v2.0  |  PyTorch Deep Learning  |  CICIDS2018",
                 font=FONT_SUB, fg=TXTSEC, bg=BG2).pack(side="left")
        tk.Label(foot, text="(c)  Ali Derouiche",
                 font=FONT_SUB, fg=TXTSEC, bg=BG2).pack(side="right")

    def _card(self, parent, col, label, val, color):
        f = tk.Frame(parent, bg=BG3, pady=12, padx=16,
                     highlightthickness=1, highlightbackground=BORDER)
        f.grid(row=0, column=col, sticky="ew", padx=4)
        tk.Frame(f, bg=color, height=2).pack(fill="x", pady=(0, 8))
        tk.Label(f, text=label, font=FONT_LABEL, fg=TXTSEC, bg=BG3).pack(anchor="w")
        v = tk.Label(f, text=val, font=FONT_VALUE, fg=color, bg=BG3)
        v.pack(anchor="w")
        return v

    def _style_combobox(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("TCombobox",
                    fieldbackground=BG4, background=BG4,
                    foreground=TXTPRI, selectbackground=BG4,
                    selectforeground=CYAN, bordercolor=BORDER,
                    arrowcolor=CYAN)

    def _on_threshold(self, val):
        self.lbl_thresh.config(text=f"THRESHOLD  {float(val):.2f}")

    def _load_models(self):
        def _do():
            try:
                self.model, self.scaler, self.features = load_embedded_models()
                n = len(self.features)
                self.root.after(0, lambda: self.lbl_status.config(
                    text=f"PyTorch model loaded  |  {n} features  |  Accuracy: 96.02%  |  Ready",
                    fg=GREEN))
                self._log(f"[SYSTEM]  PyTorch Deep Learning model loaded  |  {n} features  |  Precision: 97.51%", "info")
            except Exception as e:
                self.root.after(0, lambda: self.lbl_status.config(
                    text=f"Error: {e}", fg=RED))
                self._log(f"[ERROR]   {e}", "warn")
        threading.Thread(target=_do, daemon=True).start()

    def _toggle(self):
        if not self.running:
            self._start()
        else:
            self._stop()

    def _start(self):
        if self.model is None:
            messagebox.showwarning("Model not loaded", "Please wait for the model to load.")
            return
        self.running      = True
        self.nb_total     = 0
        self.nb_anomalies = 0
        self.btn_start.config(text="■  STOP", bg=RED, activebackground=RED2)
        self.lbl_run.config(text="●  RUNNING", fg=GREEN)
        self._log(f"[SYSTEM]  Capture started  |  Interface: {self.iface_var.get()}", "info")
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _stop(self):
        self.running = False
        self.btn_start.config(text="▶  START", bg=GREEN, activebackground=GREEN2)
        self.lbl_run.config(text="●  STOPPED", fg=AMBER)
        self._log("[SYSTEM]  Capture stopped.", "warn")

    def _loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if os.name == "nt":
            _orig = asyncio.create_subprocess_exec
            async def _silent(*args, **kwargs):
                si = subprocess.STARTUPINFO()
                si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = 0
                kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x08000000
                kwargs["startupinfo"]   = si
                return await _orig(*args, **kwargs)
            asyncio.create_subprocess_exec = _silent

        while self.running:
            try:
                result = capture_and_extract(self.iface_var.get())
                if result is None:
                    continue

                feats, stats = result
                vec = np.array(
                    [feats.get(f, 0.0) for f in self.features],
                    dtype=np.float32)
                vec = np.nan_to_num(vec, nan=0.0, posinf=1e9, neginf=0.0)

                # PyTorch inference
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    vec_norm = self.scaler.transform([vec])
                    tensor   = torch.FloatTensor(vec_norm)
                    with torch.no_grad():
                        prob = self.model(tensor).item()

                thresh     = self.threshold.get()
                prediction = 1 if prob > thresh else 0
                confidence = prob if prediction == 1 else (1 - prob)

                self.nb_total += 1
                ts    = time.strftime("%H:%M:%S")
                n     = stats["n"]
                syn   = stats["syn"]
                rst   = stats["rst"]
                ports = stats["ports"]
                ips   = stats["ips"]
                sz    = stats["size"]

                if prediction == 1:
                    self.nb_anomalies += 1
                    line = (f"[{ts}]  ATTACK     "
                            f"prob={prob:.3f}  conf={confidence*100:.1f}%  |  "
                            f"pkts={n}  SYN={syn}  RST={rst}  "
                            f"ports={ports}  IPs={ips}  avg={sz}B")
                    tag = "alert"
                    self.root.after(0, lambda: self.lbl_run.config(
                        text="●  ALERT!", fg=RED))
                else:
                    line = (f"[{ts}]  BENIGN     "
                            f"prob={prob:.3f}  conf={confidence*100:.1f}%  |  "
                            f"pkts={n}  SYN={syn}  RST={rst}  "
                            f"ports={ports}  IPs={ips}  avg={sz}B")
                    tag = "ok"
                    self.root.after(0, lambda: self.lbl_run.config(
                        text="●  RUNNING", fg=GREEN))

                self._log(line, tag)
                self._update_cards(prob, confidence)

            except Exception as e:
                self._log(f"[ERROR]   {e}", "warn")
                time.sleep(1)

    def _update_cards(self, prob, confidence):
        a  = self.nb_total
        an = self.nb_anomalies
        rt = (an / a * 100) if a else 0
        self.root.after(0, lambda: self.c_total.config(text=str(a)))
        self.root.after(0, lambda: self.c_alert.config(text=str(an)))
        self.root.after(0, lambda: self.c_rate.config(text=f"{rt:.1f}%"))
        self.root.after(0, lambda: self.c_conf.config(text=f"{confidence*100:.1f}%"))
        self.root.after(0, lambda: self.c_pkts.config(text="50"))

    def _log(self, msg, tag="dim"):
        def _do():
            self.log.config(state="normal")
            self.log.insert("end", msg + "\n", tag)
            self.log.see("end")
            self.log.config(state="disabled")
        self.root.after(0, _do)

    def _clear(self):
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")

# ================================================================
# MAIN
# ================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app  = CortexSecure(root)
    root.mainloop()
