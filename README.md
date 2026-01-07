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

### Détails techniques

**Opérations ECC implémentées :**
- Addition de points sur la courbe elliptique
- Doublement de points
- Multiplication scalaire (algorithme Double-and-Add)
- Inverse modulaire (algorithme d'Euclide étendu)

**Format des clés :**
- Les clés sont encodées en Base64
- Format compatible entre différentes instances du programme
- Clés privées : contiennent le scalaire k
- Clés publiques : contiennent les coordonnées (x, y) du point Q

**Algorithme de chiffrement (ECIES) :**
1. Génération d'une clé éphémère aléatoire k_eph
2. Calcul du point éphémère public R = k_eph * P
3. Calcul du secret partagé S = k_eph * Qb (Qb = clé publique du destinataire)
4. Hachage de S avec SHA256 pour obtenir la clé de chiffrement
5. Chiffrement du message avec AES-128 en mode CBC
6. Format de sortie : `R_x;R_y;ciphertext_base64`

**Déchiffrement :**
Pour déchiffrer, le destinataire :
1. Extrait R du message chiffré
2. Calcule S = k * R (k = sa clé privée)
3. Obtient la même clé de chiffrement par hachage de S
4. Déchiffre avec AES-128 CBC

**Note sur la sécurité :**
Cette implémentation utilise des paramètres trop faibles pour une utilisation réelle (point de base d'ordre 4). Elle est destinée uniquement à des fins pédagogiques.

### Statut du projet

Section 3.1 - Gestion des paramètres en ligne de commande -> Done
Section 3.2 - Génération de clés (keygen) -> Done
Section 3.3 - Chiffrement (crypt) -> Done
Section 3.4 - Déchiffrement (decrypt)
Section 4 - Options avancées (switches -f, -s, -i, -o)