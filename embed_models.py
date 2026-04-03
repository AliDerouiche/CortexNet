import base64, os, sys

# Chemins des fichiers
bureau = os.path.join(os.path.expanduser("~"), "Desktop")
fichiers = {
    "MODELE"  : os.path.join(bureau, "modele.pt"),
    "SCALER"  : os.path.join(bureau, "scaler.pkl"),
    "FEATURES": os.path.join(bureau, "features.pkl"),
}
sortie = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models_data.py")

print("Embedding models...")
lignes = []
for nom, chemin in fichiers.items():
    if not os.path.exists(chemin):
        print(f"ERROR: {chemin} not found!")
        sys.exit(1)
    with open(chemin, "rb") as f:
        data = base64.b64encode(f.read()).decode("ascii")
    taille = os.path.getsize(chemin) // 1024
    chunks = [data[i:i+76] for i in range(0, len(data), 76)]
    lignes.append(f"{nom} = (\n")
    for chunk in chunks:
        lignes.append(f'    b"{chunk}"\n')
    lignes.append(")\n\n")
    print(f"   {nom}: {taille} KB embedded")

with open(sortie, "w", encoding="ascii") as f:
    f.writelines(lignes)

print(f"\nmodels_data.py created successfully!")
print("Now run: python CortexSecure.py")
