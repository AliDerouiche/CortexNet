"""
CortexNet Network Analyzer
Deep Learning with PyTorch — CICIDS2018 CSV
Developed by Ali Derouiche
Optimized for 16GB RAM and GPU
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
import joblib
import os
import time
import warnings
warnings.filterwarnings("ignore")

# ================================================================
# CONFIGURATION
# ================================================================

FOLDER   = r"C:\Users\ali\Desktop\CICIDS2018"
MODEL    = r"C:\Users\ali\Desktop\model.pt"
SCALER   = r"C:\Users\ali\Desktop\scaler.pkl"
FEATURES = r"C:\Users\ali\Desktop\features.pkl"

FEATURES_COLS = [
    "Tot Fwd Pkts", "Tot Bwd Pkts",
    "TotLen Fwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean", "Fwd Pkt Len Std",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Tot", "Fwd IAT Mean",
    "Bwd IAT Tot", "Bwd IAT Mean",
    "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
    "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt",
    "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std",
    "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg",
    "Down/Up Ratio",
]

BATCH_SIZE = 4096
EPOCHS     = 20
LR         = 0.001

# ================================================================
# PYTORCH MODEL
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
# STEP 1: OPTIMIZED DATA LOADING
# ================================================================

print("=" * 60)
print("  CortexNet — PyTorch Training")
print("  CICIDS2018 — Deep Learning (Optimized)")
print("=" * 60)

# Check GPU
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
if device.type == "cuda":
    print(f"\n  GPU detected : {torch.cuda.get_device_name(0)}")
    print(f"  VRAM         : {torch.cuda.get_device_properties(0).total_memory // 1024**2} MB")
else:
    print("\n  GPU not detected — using CPU")

# List CSV files
files = sorted([f for f in os.listdir(FOLDER) if f.endswith(".csv")])
print(f"\n  {len(files)} CSV files found")

data_list = []

for f in files:
    print(f"  Loading {f}...", end=" ")
    df = pd.read_csv(os.path.join(FOLDER, f), low_memory=False)
    df.columns = df.columns.str.strip()
    
    # Available features
    feat_ok = [col for col in FEATURES_COLS if col in df.columns]
    df = df[feat_ok + ["Label"]]
    
    # Type conversion to reduce RAM usage
    for col in feat_ok:
        df[col] = pd.to_numeric(df[col], errors='coerce').astype('float32')
    
    # Binary label
    df["y"] = (df["Label"] != "Benign").astype('int8')
    
    # Fast cleaning
    df = df[np.isfinite(df[feat_ok]).all(axis=1)]
    
    print(f"{len(df):,} rows after cleaning")
    data_list.append(df)

# Concatenate all cleaned files
data = pd.concat(data_list, ignore_index=True)
print(f"\n  Total dataset : {len(data):,} rows")
print(f"  Labels : {data['y'].value_counts().to_dict()}")

# ================================================================
# STEP 2: SAMPLING AND PREPARATION
# ================================================================

# Balance classes
n_benign = (data["y"] == 0).sum()
n_attack = (data["y"] == 1).sum()
n_sample = min(300_000, n_benign, n_attack)
print(f"\n  Balanced sample : {n_sample} x 2 = {n_sample*2}")

idx_b = data[data["y"]==0].sample(n=n_sample, random_state=42).index
idx_a = data[data["y"]==1].sample(n=n_sample, random_state=42).index
idx = idx_b.union(idx_a)

feat_ok = [col for col in FEATURES_COLS if col in data.columns]
X = data.loc[idx, feat_ok].values.astype('float32')
y = data.loc[idx, "y"].values.astype('int8')

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"  Train : {len(X_train):,}  |  Test : {len(X_test):,}")

# Normalization
scaler    = StandardScaler()
X_train_n = scaler.fit_transform(X_train).astype('float32')
X_test_n  = scaler.transform(X_test).astype('float32')

# ================================================================
# STEP 3: PYTORCH TRAINING
# ================================================================

print(f"\nTraining on {device}...")

dataset    = TensorDataset(torch.from_numpy(X_train_n), torch.from_numpy(y_train))
dataloader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

X_te = torch.from_numpy(X_test_n).to(device)
y_te = torch.from_numpy(y_test).float().to(device)

model     = NetworkClassifier(input_dim=len(feat_ok)).to(device)
optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
criterion = nn.BCELoss()

print(f"  Model parameters : {sum(p.numel() for p in model.parameters()):,}")
print(f"  Epochs : {EPOCHS}  |  Batch size : {BATCH_SIZE}  |  LR : {LR}\n")

start = time.time()
for epoch in range(EPOCHS):
    model.train()
    total_loss = 0
    for X_batch, y_batch in dataloader:
        X_batch = X_batch.to(device)
        y_batch = y_batch.float().to(device)
        optimizer.zero_grad()
        pred = model(X_batch)
        loss = criterion(pred, y_batch)
        loss.backward()
        optimizer.step()
        total_loss += loss.item()

    # Validation
    model.eval()
    with torch.no_grad():
        pred_te = model(X_te)
        val_loss = criterion(pred_te, y_te).item()
        y_pred_bin = (pred_te.cpu().numpy() > 0.5).astype(int)
        acc = accuracy_score(y_test, y_pred_bin)

    scheduler.step(val_loss)
    avg_loss = total_loss / len(dataloader)
    print(f"  Epoch {epoch+1:02d}/{EPOCHS}  "
          f"loss={avg_loss:.4f}  val_loss={val_loss:.4f}  acc={acc*100:.2f}%")

print(f"\n  Finished in {time.time()-start:.1f}s")

# ================================================================
# STEP 4: FINAL EVALUATION
# ================================================================

print("\nFinal evaluation on test set...")
model.eval()
with torch.no_grad():
    pred_final = model(X_te).cpu().numpy()

y_pred = (pred_final > 0.5).astype(int)
y_true = y_test

acc  = accuracy_score(y_true, y_pred)
prec = precision_score(y_true, y_pred, zero_division=0)
rec  = recall_score(y_true, y_pred, zero_division=0)
f1   = f1_score(y_true, y_pred, zero_division=0)
cm   = confusion_matrix(y_true, y_pred)

print("\n" + "=" * 60)
print("  FINAL RESULTS")
print("=" * 60)
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1-Score  : {f1*100:.2f}%")
print(f"\n  Confusion Matrix :")
print(f"    True Benign -> Benign  : {cm[0][0]:,}  (correct)")
print(f"    True Benign -> Attack  : {cm[0][1]:,}  (false positive)")
print(f"    True Attack -> Benign  : {cm[1][0]:,}  (false negative)")
print(f"    True Attack -> Attack  : {cm[1][1]:,}  (correct)")
print("=" * 60)

# ================================================================
# STEP 5: SAVE
# ================================================================

print("\nSaving...")

torch.save({
    "model_state_dict": model.state_dict(),
    "input_dim"       : len(feat_ok),
    "architecture"    : "NetworkClassifier",
}, MODEL)

joblib.dump(scaler,  SCALER)
joblib.dump(feat_ok, FEATURES)

print(f"  model.pt    -> Desktop  ({os.path.getsize(MODEL)//1024} KB)")
print(f"  scaler.pkl  -> Desktop")
print(f"  features.pkl -> Desktop  ({len(feat_ok)} features)")
print(f"\n  Now run embed_models.py then CortexNet.exe")