from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable

# Génération de la clef
root_key = KeyPair.generate()


# Creation du jeton Biscuit avec des autorisations
def create_biscuit():
    # Initialiser le constructeur de jetons Biscuit
    builder = Biscuit.builder(root_key)

    # Ajouter des autorisations (droits) pour lire et écrire un fichier
    builder.add_authority_fact("right(\"file1\", \"read\")")
    builder.add_authority_fact("right(\"file1\", \"write\")")

    # Générer le jeton
    token = builder.build()
    return token


# Verification si l'utilisateur a le droit d'effectuer une opération
def verify_biscuit(token, operation, resource):
    # Initialiser un vérificateur avec une table de symboles par défaut
    verifier = Verifier(SymbolTable.default())

    # Ajouter des faits contextuels (ce que l'utilisateur essaie de faire)
    verifier.add_fact(f"resource(\"{resource}\")")
    verifier.add_fact(f"operation(\"{operation}\")")

    # Définir la règle qui permet de vérifier les droits
    verifier.allow(
        "right($resource, $operation) <- resource($resource), operation($operation), right($resource, $operation)")

    # Vérifier si le jeton permet cette opération
    result = token.verify(root_key.public(), verifier)

    if result.is_ok():
        print(f"Vérification réussie : L'utilisateur peut {operation} sur {resource}")
    else:
        print(f"Vérification échouée : L'utilisateur n'a pas le droit de {operation} sur {resource}")


# Test du système

# Créer le jeton Biscuit
token = create_biscuit()

# Tenter de vérifier les droits de lecture sur "file1"
verify_biscuit(token, "read", "file1")

# Tenter de vérifier les droits d'écriture sur "file1"
verify_biscuit(token, "write", "file1")

# Tenter de vérifier les droits de suppression
verify_biscuit(token, "delete", "file1")