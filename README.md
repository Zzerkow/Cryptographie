## TP MonECC

### Auteur
Victor Besson & Léo Filsnoel

### Installation

#### Prérequis
- Python 3.7 ou supérieur une version supérieure
- pip (gestionnaire de paquets Python)

#### Mise en place de l'environnement

1. Cloner le repo git
```bash
git clone 
```

2. Dans la racine du projet, mettre en place l'environnement venv
```bash
python -m venv venv
```

3. Si le système d'exploitation est windows on utilise la première commande d'activation de l'environnement, sinon l'autre pour linux et mac.
```bash
.\venv\Scripts\activate
```
```bash
source venv/bin/activate
```

3. Installer la dépendance cryptography pour le bon fonctionnement du projet.
```bash
pip install cryptography
```

#### Utilisation du TP
```bash
python3 monECC.py <commande> [<clé>] [<texte>]
```

Pour afficher une aide des différentes commandes.
```bash
python3 monECC.py help
```

### Commandes disponibles
- `keygen` : Génère une paire de clés (publique et privée)
- `crypt` : Chiffre un message avec une clé publique
- `decrypt` : Déchiffre un message avec une clé privée
- `help` : Affiche le manuel d'utilisation

### Exemples

Générer une paire de clés :
```bash
python3 monECC.py keygen
```

Chiffrer un message :
```bash
python3 monECC.py crypt monECC.pub "message à crypter"
```

Déchiffrer un message :
```bash
python3 monECC.py decrypt monECC.priv "données à décrypter"
```