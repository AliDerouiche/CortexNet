import pandas as pd
import os

DOSSIER = r"C:\Users\ali\Desktop\CICIDS2018"
# Charger juste le premier fichier CSV
fichiers = [f for f in os.listdir(DOSSIER) if f.endswith(".csv")]
print("Fichiers CSV trouvés :", fichiers)

# Lire juste 5 lignes pour voir les colonnes
df = pd.read_csv(os.path.join(DOSSIER, fichiers[0]), nrows=5)
print(f"\nColonnes ({len(df.columns)}) :")
for col in df.columns:
    print(f"  '{col}'")

print("\nLabels uniques :")
df2 = pd.read_csv(os.path.join(DOSSIER, fichiers[0]), usecols=["Label"])
print(df2["Label"].unique())