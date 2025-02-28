import os
from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable

# Génération des clés pour signer et vérifier les jetons
root_key = KeyPair.generate()

# Définition fichiers/permissions
FILES = ["file1", "file2", "file3"]

# Création du jeton avec des permissions spécifiques à chaque fichier
def create_biscuit():
    builder = Biscuit.builder(root_key)

    builder.add_authority_fact("right(\"file1\", \"read\")")
    builder.add_authority_fact("right(\"file1\", \"write\")")
    builder.add_authority_fact("right(\"file2\", \"read\")")
    builder.add_authority_fact("right(\"file3\", \"write\")")

    return builder.build()

# Vérification des autorisations
def verify_biscuit(token, operation, resource):
    verifier = Verifier(SymbolTable.default())
    verifier.add_fact(f"resource(\"{resource}\")")
    verifier.add_fact(f"operation(\"{operation}\")")

    # Définition de la règle de validation des permissions
    verifier.allow("right($resource, $operation) <- resource($resource), operation($operation), right($resource, $operation)")

    result = token.verify(root_key.public(), verifier)

    return result.is_ok()

# Interface en ligne de commande (CLI)
def cli():
    token = create_biscuit()
    
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')  # Efface l'écran pour une meilleure lisibilité
        
        print("=== Gestion des accès aux fichiers ===")
        print("Fichiers disponibles :")
        for idx, file in enumerate(FILES, start=1):
            print(f"{idx}. {file}")

        print("\nChoisissez un fichier (ou 'q' pour quitter) : ")
        choice = input("> ")

        if choice.lower() == 'q':
            print("À bientôt ! 👋")
            break

        if not choice.isdigit() or int(choice) not in range(1, len(FILES) + 1):
            print("❌ Choix invalide, veuillez réessayer.")
            input("Appuyez sur Entrée pour continuer...")
            continue

        resource = FILES[int(choice) - 1]

        print("\nChoisissez une action :")
        print("1. Lire (read)")
        print("2. Écrire (write)")
        action_choice = input("> ")

        if action_choice == "1":
            operation = "read"
        elif action_choice == "2":
            operation = "write"
        else:
            print("❌ Action invalide, veuillez réessayer.")
            input("Appuyez sur Entrée pour continuer...")
            continue

        # Vérification des permissions
        if verify_biscuit(token, operation, resource):
            print(f"✅ Autorisation accordée : Vous pouvez {operation} sur {resource}.")
        else:
            print(f"❌ Accès refusé : Vous ne pouvez pas {operation} sur {resource}.")

        input("\nAppuyez sur Entrée pour continuer...")  # Pause avant de réafficher l'interface

# Exécuter la CLI
if __name__ == "__main__":
    cli()