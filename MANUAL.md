# 🍪 Cookies-Chain

![](Cookies-Chain.png)

**Cookies-Chain** est un système de gestion d'accès moderne et sécurisé basé sur le projet [Biscuit-Sec](https://biscuitsec.org). Il permet de créer, gérer et atténuer des jetons d'autorisation de manière granulaire et sécurisée.

### ✨ Fonctionnalités

- 🔐 **Création et vérification de jetons** : Génération sécurisée de jetons d'accès
- ⚡ **Atténuation des droits** : Restriction progressive des permissions
- 👥 **Gestion multi-utilisateurs** : Support de plusieurs utilisateurs simultanément
- 🤝 **Partage de jetons** : Partage sécurisé avec restrictions
- 🎨 **Interface moderne** : CLI colorée et intuitive avec Rich
- 💾 **Persistance** : Sauvegarde automatique des jetons et clés

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

### Installation rapide

```bash
# Cloner le repository
git clone https://github.com/votre-username/cookies-chain.git
cd cookies-chain

# Installation des dépendances
pip install -r requirements.txt

# Ou installation via setup.py
pip install -e .
```

### Installation via pip (après publication)

```bash
pip install cookies-chain
```

## 🎯 Guide de démarrage rapide

### 1. Première utilisation

```bash
# Lancer en mode interactif
python main.py interactive

# Ou directement si installé via pip
cookies-chain interactive
```

### 2. Utilisation en ligne de commande

```bash
# Créer un utilisateur
python main.py create-user alice

# Vérifier un accès
python main.py verify alice file1 read

# Lister les utilisateurs
python main.py list-users
```

### 3. Exemple d'utilisation complète

```bash
# 1. Créer deux utilisateurs
python main.py create-user alice
python main.py create-user bob

# 2. Vérifier les accès initiaux
python main.py verify alice file1 read    # ✅ Autorisé
python main.py verify alice file1 write   # ✅ Autorisé

# 3. Atténuer les droits (mode interactif recommandé)
python main.py interactive
# Puis choisir l'option 3 pour atténuer

# 4. Partager un jeton avec restrictions
# Utiliser le mode interactif, option 5
```

## 📚 Tutoriel détaillé

### Étape 1: Installation et configuration

1. **Cloner le projet**
   ```bash
   git clone https://github.com/votre-username/cookies-chain.git
   cd cookies-chain
   ```

2. **Créer un environnement virtuel (recommandé)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Sur Windows: venv\Scripts\activate
   ```

3. **Installer les dépendances**
   ```bash
   pip install -r requirements.txt
   ```

### Étape 2: Premier lancement

1. **Lancer en mode interactif**
   ```bash
   python main.py interactive
   ```

2. **Créer votre premier utilisateur**
   - Choisir l'option `1` dans le menu
   - Entrer un nom d'utilisateur (ex: `alice`)
   - Le jeton sera automatiquement créé avec les permissions par défaut

### Étape 3: Gestion des accès

1. **Vérifier les permissions**
   - Option `2` du menu interactif
   - Sélectionner l'utilisateur et la ressource
   - Choisir l'opération (lecture/écriture)

2. **Atténuer les droits**
   - Option `3` du menu interactif
   - Sélectionner l'utilisateur
   - Choisir la ressource et l'opération à supprimer

3. **Partager un jeton**
   - Option `5` du menu interactif
   - Spécifier l'utilisateur source et cible
   - Définir les restrictions à appliquer

### Étape 4: Utilisation avancée

**Fichiers générés :**
- `jetons.json` : Stockage des jetons utilisateurs
- `keys.json` : Clés cryptographiques (⚠️ À protéger !)

**Structure des permissions par défaut :**
- `file1` : lecture + écriture
- `file2` : lecture + écriture  
- `file3` : lecture seule

## 🔧 Commandes CLI

```bash
# Commandes principales
python main.py create-user <username>        # Créer un utilisateur
python main.py verify <user> <file> <op>     # Vérifier un accès
python main.py list-users                    # Lister les utilisateurs
python main.py interactive                   # Mode interactif

# Exemples
python main.py create-user alice
python main.py verify alice file1 read
python main.py verify alice file2 write
```

## 🛡️ Sécurité

- **Clés cryptographiques** : Génération automatique et stockage sécurisé
- **Jetons signés** : Vérification cryptographique des permissions
- **Atténuation** : Impossible de révoquer une restriction
- **Isolation** : Chaque utilisateur a ses propres permissions

## 🐛 Dépannage

### Erreurs communes

1. **`ModuleNotFoundError: No module named 'biscuit_auth'`**
   ```bash
   pip install biscuit-auth
   ```

2. **`FileNotFoundError` lors de la première utilisation**
   - Normal ! Les fichiers `jetons.json` et `keys.json` sont créés automatiquement

3. **Permissions refusées**
   - Vérifier que l'utilisateur existe : `python main.py list-users`
   - Vérifier si des restrictions ont été appliquées

### Réinitialisation

Pour repartir à zéro :
```bash
rm jetons.json keys.json
```

## 📈 Améliorations futures

- [ ] Interface web avec FastAPI
- [ ] Support de ressources personnalisées
- [ ] Audit et logs des accès
- [ ] Intégration avec des bases de données
- [ ] API REST pour intégration
- [ ] Support de rôles et groupes
- [ ] Expiration automatique des jetons
- [ ] Interface graphique desktop

## 🤝 Contribution

Les contributions sont les bienvenues ! 

1. Fork le projet
2. Créer une branche feature (`git checkout -b feature/amélioration`)
3. Commit les changements (`git commit -am 'Ajout de fonctionnalité'`)
4. Push la branche (`git push origin feature/amélioration`)
5. Créer une Pull Request

## 📄 Licence

Ce projet est sous licence GNU GPL v3.0. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 🔗 Liens utiles

- [Biscuit-Sec](https://biscuitsec.org) - Technologie sous-jacente
- [Documentation Biscuit](https://github.com/biscuit-auth/biscuit) - Documentation complète
- [Rich](https://rich.readthedocs.io/) - Bibliothèque pour interface CLI

## 📞 Support

Pour toute question ou problème :
- Ouvrir une [issue](https://github.com/votre-username/cookies-chain/issues)
- Consulter la [documentation](https://github.com/votre-username/cookies-chain/wiki)

