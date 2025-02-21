from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable

# Génération des clés pour signer et vérifier les jetons
root_key = KeyPair.generate()

# Création d'un jeton avec des permissions spécifiques à plusieurs fichiers
def create_biscuit():
    builder = Biscuit.builder(root_key)
    
    # Ajout des droits spécifiques aux fichiers
    builder.add_authority_fact("right(\"file1\", \"read\")")
    builder.add_authority_fact("right(\"file1\", \"write\")")
    builder.add_authority_fact("right(\"file2\", \"read\")")
    builder.add_authority_fact("right(\"file3\", \"write\")")
    
    return builder.build()

# Vérification des autorisations pour une ressource donnée
def verify_biscuit(token, operation, resource):
    verifier = Verifier(SymbolTable.default())
    verifier.add_fact(f"resource(\"{resource}\")")
    verifier.add_fact(f"operation(\"{operation}\")")
    
    # Définition de la règle pour vérifier les permissions
    verifier.allow("right($resource, $operation) <- resource($resource), operation($operation), right($resource, $operation)")
    
    result = token.verify(root_key.public(), verifier)
    
    if result.is_ok():
        print(f"✅ L'utilisateur peut {operation} sur {resource}")
    else:
        print(f"❌ L'utilisateur n'a pas le droit de {operation} sur {resource}")

# Test du système
token = create_biscuit()

# Vérification des autorisations sur différents fichiers
verify_biscuit(token, "read", "file1")  # ✅ Devrait fonctionner
verify_biscuit(token, "write", "file1") # ✅ Devrait fonctionner
verify_biscuit(token, "read", "file2")  # ✅ Devrait fonctionner
verify_biscuit(token, "write", "file2") # ❌ Devrait échouer
verify_biscuit(token, "write", "file3") # ✅ Devrait fonctionner
verify_biscuit(token, "read", "file3")  # ❌ Devrait échouer
