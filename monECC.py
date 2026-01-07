#!/usr/bin/env python3
"""
monECC - Elliptic Curve Cryptography Tool
Implements ECC encryption/decryption using curve Y^2 = X^3 + 35X + 3 (mod 101)
"""

import sys
import hashlib
import base64
import random


# ECC Parameters
CURVE_A = 35
CURVE_B = 3
CURVE_P = 101
BASE_POINT = (2, 9)


def display_help():
    """Display the help manual"""
    help_text = """
Script monECC par Victor Besson

Syntaxe :
    monECC <commande> [<clé>] [<texte>] [switchs]

Commande :
    keygen  : Génère une paire de clé
    crypt   : Chiffre <texte> pour la clé publique <clé>
    decrypt : Déchiffre <texte> pour la clé privée <clé>
    help    : Affiche ce manuel

Clé :
    Un fichier qui contient une clé publique monECC ("crypt") ou une clé
    privée ("decrypt")

Texte :
    Une phrase en clair ("crypt") ou une phrase chiffrée ("decrypt")

Switchs :
    -f <file>   : permet de choisir le nom des clés générées,
                  monECC.pub et monECC.priv par défaut
    -s <size>   : précise la plage d'aléa (1 à <size>), défaut 1000
    -i          : utilise un fichier texte au lieu d'une chaîne
    -o <file>   : nom du fichier de sortie (au lieu d'afficher)
"""
    print(help_text)


def parse_arguments():
    """Parse and validate command-line arguments"""
    if len(sys.argv) < 2 or sys.argv[1] == "help":
        display_help()
        sys.exit(0)

    command = sys.argv[1]

    # Validate command
    valid_commands = ["keygen", "crypt", "decrypt", "help"]
    if command not in valid_commands:
        print(f"Erreur : Commande invalide '{command}'")
        print(f"Commandes valides : {', '.join(valid_commands)}")
        sys.exit(1)

    # Parse arguments based on command
    args = {
        'command': command,
        'key_file': None,
        'text': None,
        'filename': 'monECC',  # Default filename (without extension)
        'size': 1000,  # Default key size range
        'input_file': False,
        'output_file': None
    }

    # For crypt and decrypt, key and text are required
    if command in ["crypt", "decrypt"]:
        if len(sys.argv) < 4:
            print(f"Erreur : La commande '{command}' nécessite <clé> et <texte>")
            display_help()
            sys.exit(1)

        args['key_file'] = sys.argv[2]
        args['text'] = sys.argv[3]

        # Parse switches starting from position 4
        i = 4
    else:
        # For keygen, parse switches starting from position 2
        i = 2

    # Parse optional switches
    while i < len(sys.argv):
        switch = sys.argv[i]

        if switch == '-f':
            if i + 1 >= len(sys.argv):
                print("Erreur : Le switch -f nécessite un nom de fichier")
                sys.exit(1)
            args['filename'] = sys.argv[i + 1]
            i += 2

        elif switch == '-s':
            if i + 1 >= len(sys.argv):
                print("Erreur : Le switch -s nécessite une taille")
                sys.exit(1)
            try:
                args['size'] = int(sys.argv[i + 1])
                if args['size'] < 1:
                    raise ValueError()
            except ValueError:
                print("Erreur : Le switch -s nécessite un nombre positif")
                sys.exit(1)
            i += 2

        elif switch == '-i':
            args['input_file'] = True
            i += 1

        elif switch == '-o':
            if i + 1 >= len(sys.argv):
                print("Erreur : Le switch -o nécessite un nom de fichier")
                sys.exit(1)
            args['output_file'] = sys.argv[i + 1]
            i += 2

        else:
            print(f"Erreur : Switch inconnu '{switch}'")
            sys.exit(1)

    return args


def main():
    """Main entry point"""
    args = parse_arguments()

    if args['command'] == 'keygen':
        print("Commande keygen appelée")
        print(f"Nom des fichiers : {args['filename']}.pub et {args['filename']}.priv")
        print(f"Plage de clé : 1 à {args['size']}")
        # TODO: Implement keygen

    elif args['command'] == 'crypt':
        print("Commande crypt appelée")
        print(f"Fichier de clé : {args['key_file']}")
        print(f"Texte : {args['text']}")
        # TODO: Implement crypt

    elif args['command'] == 'decrypt':
        print("Commande decrypt appelée")
        print(f"Fichier de clé : {args['key_file']}")
        print(f"Texte chiffré : {args['text']}")
        # TODO: Implement decrypt


if __name__ == "__main__":
    main()