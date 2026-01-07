"""
TP monECC - Victor Besson & Léo FILSNOEL
"""

import sys
import hashlib
import base64
import random

CURVE_A = 35
CURVE_B = 3
CURVE_P = 101
BASE_POINT = (2, 9)

def mod_inverse(a, p):
    if a < 0:
        a = (a % p + p) % p

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a, p)
    if gcd != 1:
        raise ValueError(f"Inverse modulaire n'existe pas pour {a} mod {p}")
    return (x % p + p) % p


def point_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and y1 != y2:
        return None

    if x1 == x2 and y1 == y2:
        return point_double(P)

    slope = ((y2 - y1) * mod_inverse(x2 - x1, CURVE_P)) % CURVE_P

    x3 = (slope * slope - x1 - x2) % CURVE_P

    y3 = (slope * (x1 - x3) - y1) % CURVE_P

    return (x3, y3)


def point_double(P):
    if P is None:
        return None

    x, y = P

    if y == 0:
        return None

    numerator = (3 * x * x + CURVE_A) % CURVE_P
    denominator = (2 * y) % CURVE_P
    slope = (numerator * mod_inverse(denominator, CURVE_P)) % CURVE_P

    x3 = (slope * slope - 2 * x) % CURVE_P

    y3 = (slope * (x - x3) - y) % CURVE_P

    return (x3, y3)


def scalar_multiply(k, P):
    if k == 0:
        return None  

    if k < 0:
        raise ValueError("Scalar must be positive")

    result = None  
    addend = P

    while k:
        if k & 1: 
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1  

    return result

def generate_keypair(key_range=1000):
    k = random.randint(1, key_range)

    Q = scalar_multiply(k, BASE_POINT)

    if Q is None:
        return generate_keypair(key_range)

    return k, Q


def save_private_key(k, filename):
    k_str = str(k)
    k_b64 = base64.b64encode(k_str.encode('utf-8')).decode('utf-8')

    content = f"""---begin monECC private key---
    {k_b64}
    ---end monECC key---
    """

    with open(filename, 'w') as f:
        f.write(content)


def save_public_key(Q, filename):
    
    x, y = Q
    q_str = f"{x};{y}"
    q_b64 = base64.b64encode(q_str.encode('utf-8')).decode('utf-8')

    content = f"""---begin monECC public key---
    {q_b64}
    ---end monECC key---
    """

    with open(filename, 'w') as f:
        f.write(content)


def load_private_key(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        if len(lines) < 3:
            raise ValueError("Format de fichier invalide")

        if not lines[0].strip().startswith("---begin monECC private key---"):
            raise ValueError("Ce n'est pas une clé privée monECC valide")

        k_b64 = lines[1].strip()
        k_str = base64.b64decode(k_b64).decode('utf-8')
        k = int(k_str)

        return k
    except FileNotFoundError:
        print(f"Erreur : Fichier '{filename}' introuvable")
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors de la lecture de la clé privée : {e}")
        sys.exit(1)


def load_public_key(filename):
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        if len(lines) < 3:
            raise ValueError("Format de fichier invalide")

        if not lines[0].strip().startswith("---begin monECC public key---"):
            raise ValueError("Ce n'est pas une clé publique monECC valide")

        q_b64 = lines[1].strip()
        q_str = base64.b64decode(q_b64).decode('utf-8')

        x_str, y_str = q_str.split(';')
        x = int(x_str)
        y = int(y_str)

        return (x, y)
    except FileNotFoundError:
        print(f"Erreur : Fichier '{filename}' introuvable")
        sys.exit(1)
    except Exception as e:
        print(f"Erreur lors de la lecture de la clé publique : {e}")
        sys.exit(1)


def display_help():
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

    valid_commands = ["keygen", "crypt", "decrypt", "help"]
    if command not in valid_commands:
        print(f"Erreur : Commande invalide '{command}'")
        print(f"Commandes valides : {', '.join(valid_commands)}")
        sys.exit(1)

    args = {
        'command': command,
        'key_file': None,
        'text': None,
        'filename': 'monECC',
        'size': 1000, 
        'input_file': False,
        'output_file': None
    }

    if command in ["crypt", "decrypt"]:
        if len(sys.argv) < 4:
            print(f"Erreur : La commande '{command}' nécessite <clé> et <texte>")
            display_help()
            sys.exit(1)

        args['key_file'] = sys.argv[2]
        args['text'] = sys.argv[3]

        i = 4
    else:
        i = 2

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


def cmd_keygen(args):
    print("Génération de la paire de clés ECC...")
    print(f"Courbe : Y² = X³ + {CURVE_A}X + {CURVE_B} (mod {CURVE_P})")
    print(f"Point de base P : {BASE_POINT}")
    print(f"Plage de clé privée : 1 à {args['size']}")

    k, Q = generate_keypair(args['size'])

    print(f"\nClé privée k : {k}")
    print(f"Clé publique Q : {Q}")

    priv_filename = f"{args['filename']}.priv"
    pub_filename = f"{args['filename']}.pub"

    save_private_key(k, priv_filename)
    save_public_key(Q, pub_filename)

    print(f"\n✓ Clé privée sauvegardée dans : {priv_filename}")
    print(f"✓ Clé publique sauvegardée dans : {pub_filename}")


def compute_shared_secret_hash(S):
    """
    Compute SHA256 hash of shared secret point S
    Following the specification: hash both coordinates
    Returns: hex digest of the hash
    """
    x, y = S

    # Convert coordinates to bytes and hash them
    # Hash x coordinate
    hash_x = hashlib.sha256(str(x).encode('utf-8'))
    # Hash y coordinate
    hash_y = hashlib.sha256(str(y).encode('utf-8'))

    # Combine both hashes
    combined = hash_x.digest() + hash_y.digest()
    final_hash = hashlib.sha256(combined)

    return final_hash.hexdigest()


def encrypt_message(message, Qb):
    """
    Encrypt a message using ECC + AES/CBC

    Algorithm:
    1. Generate ephemeral keypair (k_eph, R) where R = k_eph * P
    2. Compute shared secret S = k_eph * Qb
    3. Hash S with SHA256 to get encryption key
    4. Encrypt message with AES/CBC
    5. Return R and ciphertext

    Args:
        message: plaintext message (string)
        Qb: recipient's public key (point)

    Returns:
        (R, ciphertext_b64): ephemeral public point and encrypted message
    """
    # Import crypto library here (lazy loading)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding

    # 1. Generate ephemeral keypair
    k_eph = random.randint(1, 1000)
    R = scalar_multiply(k_eph, BASE_POINT)

    if R is None:
        # Retry if we get point at infinity
        return encrypt_message(message, Qb)

    # 2. Compute shared secret S = k_eph * Qb
    S = scalar_multiply(k_eph, Qb)

    if S is None:
        # Retry if we get point at infinity
        return encrypt_message(message, Qb)

    # 3. Hash the shared secret
    secret_hash = compute_shared_secret_hash(S)

    # 4. Prepare AES key and IV
    # Use first 16 chars as IV, last 16 chars as key
    iv = secret_hash[:16].encode('utf-8')
    key = secret_hash[-16:].encode('utf-8')

    # 5. Pad the message (PKCS7 padding)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode('utf-8'))
    padded_data += padder.finalize()

    # 6. Encrypt with AES/CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # 7. Encode ciphertext in base64
    ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

    return R, ciphertext_b64


def cmd_crypt(args):
    """Execute crypt command - Encrypt message"""
    # Load recipient's public key
    Qb = load_public_key(args['key_file'])

    # Get message (from string or file)
    if args['input_file']:
        try:
            with open(args['text'], 'r') as f:
                message = f.read()
        except FileNotFoundError:
            print(f"Erreur : Fichier '{args['text']}' introuvable")
            sys.exit(1)
    else:
        message = args['text']

    # Encrypt the message
    R, ciphertext_b64 = encrypt_message(message, Qb)

    # Format output: R_x;R_y;ciphertext
    output = f"{R[0]};{R[1]};{ciphertext_b64}"

    # Output result
    if args['output_file']:
        with open(args['output_file'], 'w') as f:
            f.write(output)
        print(f"Message chiffré sauvegardé dans : {args['output_file']}")
    else:
        print(output)

def cmd_decrypt(args):
    """Execute decrypt command - Decrypt message"""
    print("Déchiffrement du message...")
    print(f"Fichier de clé : {args['key_file']}")
    print(f"Texte chiffré : {args['text']}")

def main():
    args = parse_arguments()

    if args['command'] == 'keygen':
        cmd_keygen(args)

    elif args['command'] == 'crypt':
        cmd_crypt(args)

    elif args['command'] == 'decrypt':
        cmd_decrypt(args)


if __name__ == "__main__":
    main()