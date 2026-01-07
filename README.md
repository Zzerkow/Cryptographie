## TP MonECC

### Auteur
Victor Besson & Léo Filsnoel

### Description
Application en ligne de commande pour le chiffrement et déchiffrement de messages utilisant la cryptographie sur courbes elliptiques (ECC).

Courbe utilisée : Y² = X³ + 35X + 3 (modulo 101)
Point de base P : (2, 9)

### Installation

#### Prérequis
- Python 3.7 ou supérieur
- pip (gestionnaire de paquets Python)

#### Dépendances
Installez les dépendances nécessaires :

```bash
pip install cryptography
```

#### Utilisation
```bash
python3 monECC.py <commande> [<clé>] [<texte>] [switches]
```

Pour afficher l'aide complète :
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
python3 monECC.py crypt monECC.pub "Message secret"
```

Déchiffrer un message :
```bash
python3 monECC.py decrypt monECC.priv "message_chiffré"
```

### Options (switches)

- `-f <nom>` : Spécifie le nom des fichiers de clés (défaut: monECC)
- `-s <taille>` : Définit la plage de génération aléatoire (défaut: 1000)
- `-i` : Utilise un fichier texte en entrée au lieu d'une chaîne
- `-o <fichier>` : Spécifie un fichier de sortie au lieu d'afficher à l'écran

### Statut du projet

✅ Section 3.1 - Gestion des paramètres en ligne de commande
⏳ Section 3.2 - Génération de clés (keygen)
⏳ Section 3.3 - Chiffrement (crypt)
⏳ Section 3.4 - Déchiffrement (decrypt)
⏳ Section 4 - Options avancées