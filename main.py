import os
import json
from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable

# Génération des clés pour signer et vérifier les jetons
root_key = KeyPair.generate()

# Fichier de stockage des jetons
TOKEN_STORAGE = "jetons.json"

# Définition des fichiers et de leurs permissions initiales
FILES = ["file1", "file2", "file3"]

# Charger les jetons depuis le fichier JSON
def load_tokens():
    if os.path.exists(TOKEN_STORAGE):
        with open(TOKEN_STORAGE, "r") as file:
            return json.load(file)
    return {}

# Sauvegarder les jetons dans le fichier JSON
def save_tokens(tokens):
    with open(TOKEN_STORAGE, "w") as file:
        json.dump(tokens, file, indent=4)

# Créer un jeton et l'associer à un utilisateur
def create_biscuit(username):
    builder = Biscuit.builder(root_key)

    builder.add_authority_fact(f"user(\"{username}\")")
    builder.add_authority_fact("right(\"file1\", \"read\")")
    builder.add_authority_fact("right(\"file1\", \"write\")")
    builder.add_authority_fact("right(\"file2\", \"read\")")
    builder.add_authority_fact("right(\"file3\", \"write\")")

    token = builder.build()
    return token.serialize()

# Atténuation des droits d'un jeton existant
def attenuate_biscuit(token_str):
    token = Biscuit.deserialize(token_str)
    attenuated_token = token.create_block()

    print("\n⚠️ ATTENUATION DES DROITS ⚠️")
    print("Vous pouvez restreindre les permissions de ce jeton.")

    print("Choisissez un fichier à restreindre :")
    for idx, file in enumerate(FILES, start=1):
        print(f"{idx}. {file}")

    choice = input("> ")
    if not choice.isdigit() or int(choice) not in range(1, len(FILES) + 1):
        print("❌ Choix invalide, annulation de l'atténuation.")
        return token_str

    resource = FILES[int(choice) - 1]

    print("\nQuelle action souhaitez-vous retirer ?")
    print("1. Lire (read)")
    print("2. Écrire (write)")
    action_choice = input("> ")

    if action_choice == "1":
        operation = "read"
    elif action_choice == "2":
        operation = "write"
    else:
        print("❌ Action invalide, annulation de l'atténuation.")
        return token_str

    # Ajout du caveat qui interdit l'opération choisie
    attenuated_token.add_caveat(f"revoked_right(\"{resource}\", \"{operation}\")")
    print(f"\n✅ Le droit '{operation}' sur '{resource}' a été supprimé.")

    return token.append(attenuated_token).serialize()

# Vérification des autorisations pour une ressource donnée
def verify_biscuit(token_str, operation, resource):
    token = Biscuit.deserialize(token_str)
    verifier = Verifier(SymbolTable.default())
    verifier.add_fact(f"resource(\"{resource}\")")
    verifier.add_fact(f"operation(\"{operation}\")")

    verifier.allow("right($resource, $operation) <- resource($resource), operation($operation), right($resource, $operation)")
    verifier.deny("revoked_right($resource, $operation) <- resource($resource), operation($operation), revoked_right($resource, $operation)")

    result = token.verify(root_key.public(), verifier)

    return result.is_ok()

# Interface en ligne de commande (CLI)
def cli():
    tokens = load_tokens()

    while True:
        os.system('clear' if os.name == 'posix' else 'cls')  # Efface l'écran

        print("=== 🛡️ Gestion des accès aux fichiers ===")
        print("1. Créer un jeton pour un utilisateur")
        print("2. Vérifier un accès")
        print("3. Atténuer un jeton")
        print("4. Afficher les jetons existants")
        print("5. Partager un jeton atténué avec un autre utilisateur")
        print("6. Quitter")

        choice = input("> ")

        if choice == "1":
            username = input("Entrez le nom de l'utilisateur : ")
            if username in tokens:
                print("❌ Un jeton existe déjà pour cet utilisateur.")
            else:
                tokens[username] = create_biscuit(username)
                save_tokens(tokens)
                print(f"✅ Jeton créé et sauvegardé pour {username}.")

        elif choice == "2":
            username = input("Entrez le nom de l'utilisateur : ")
            if username not in tokens:
                print("❌ Aucun jeton trouvé pour cet utilisateur.")
                input("Appuyez sur Entrée pour continuer...")
                continue

            print("\nFichiers disponibles :")
            for idx, file in enumerate(FILES, start=1):
                print(f"{idx}. {file}")

            file_choice = input("\nChoisissez un fichier : ")
            if not file_choice.isdigit() or int(file_choice) not in range(1, len(FILES) + 1):
                print("❌ Choix invalide.")
                input("Appuyez sur Entrée pour continuer...")
                continue

            resource = FILES[int(file_choice) - 1]

            print("\nActions possibles :")
            print("1. Lire (read)")
            print("2. Écrire (write)")
            action_choice = input("> ")

            if action_choice == "1":
                operation = "read"
            elif action_choice == "2":
                operation = "write"
            else:
                print("❌ Action invalide.")
                input("Appuyez sur Entrée pour continuer...")
                continue

            if verify_biscuit(tokens[username], operation, resource):
                print(f"✅ Autorisation accordée : {username} peut {operation} sur {resource}.")
            else:
                print(f"❌ Accès refusé : {username} ne peut pas {operation} sur {resource}.")
        
        elif choice == "3":
            username = input("Entrez le nom de l'utilisateur : ")
            if username not in tokens:
                print("❌ Aucun jeton trouvé pour cet utilisateur.")
            else:
                tokens[username] = attenuate_biscuit(tokens[username])
                save_tokens(tokens)
                print(f"✅ Jeton atténué et mis à jour pour {username}.")

        elif choice == "4":
            if not tokens:
                print("❌ Aucun jeton enregistré.")
            else:
                print("📜 Liste des utilisateurs avec jetons :")
                for user in tokens.keys():
                    print(f"- {user}")

        elif choice == "5":
            print("=== Partage d’un jeton atténué ===")
            source_user = input("Utilisateur source : ")
            if source_user not in tokens:
                print("❌ Aucun jeton trouvé pour cet utilisateur.")
                input("Appuyez sur Entrée pour continuer...")
                continue

            target_user = input("Nouvel utilisateur (destinataire) : ")
            if target_user in tokens:
                print("⚠️ Cet utilisateur possède déjà un jeton. Il sera écrasé.")
            
            base_token = Biscuit.deserialize(tokens[source_user])
            block = base_token.create_block()

            print("\n🔧 Définir les restrictions pour ce partage :")
            print("Choisissez une ressource à restreindre :")
            for idx, file in enumerate(FILES, 1):
                print(f"{idx}. {file}")
            file_idx = input("> ")
            if not file_idx.isdigit() or int(file_idx) not in range(1, len(FILES)+1):
                print("❌ Choix invalide.")
                continue
            resource = FILES[int(file_idx)-1]

            print("Quelle opération restreindre ?")
            print("1. Lecture (read)")
            print("2. Écriture (write)")
            op_choice = input("> ")
            if op_choice == "1":
                operation = "read"
            elif op_choice == "2":
                operation = "write"
            else:
                print("❌ Choix invalide.")
                continue

            block.add_caveat(f'revoked_right("{resource}", "{operation}")')
            shared_token = base_token.append(block)
            tokens[target_user] = shared_token.serialize()
            save_tokens(tokens)

            print(f"\n✅ Jeton atténué partagé avec {target_user} (restriction sur {operation} de {resource}).")

        elif choice == "6":
            print("À bientôt ! 👋")
            break

        input("\nAppuyez sur Entrée pour continuer...")  # Pause avant de réafficher l'interface

# Exécuter la CLI
if __name__ == "__main__":
    cli()