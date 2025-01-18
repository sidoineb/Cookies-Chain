from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable

# Génération de la clef
root_key = KeyPair.generate()


# Creation du jeton Biscuit avec des autorisations
def create_global_biscuit():
    builder = Biscuit.builder(root_key)
    builder.add_authority_fact("right(\"file1\", \"read\")")
    builder.add_authority_fact("right(\"file1\", \"write\")")
    return builder.build()


# Attenuation des droits d'un jeton existant
def attenuate_biscuit(token):
    attenuated_token = token.create_block()
    attenuated_token.add_caveat("right(\"file1\", $operation) <- $operation == \"read\"")
    return token.append(attenuated_token)


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

# Création du jeton global
global_token = create_global_biscuit()
print("Jeton global créé.")

# Vérification initiale avec le jeton global
verify_biscuit(global_token, "read", "file1")
verify_biscuit(global_token, "write", "file1")

# Atténuation du jeton (restreint aux droits de lecture uniquement)
attenuated_token = attenuate_biscuit(global_token)
print("Jeton atténué créé.")

# Vérification avec le jeton atténué
verify_biscuit(attenuated_token, "read", "file1")
verify_biscuit(attenuated_token, "write", "file1")