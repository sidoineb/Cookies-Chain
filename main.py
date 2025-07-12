
#!/usr/bin/env python3
"""
Cookies-Chain - Système de gestion d'accès basé sur Biscuit-Sec
"""

import os
import json
import sys
from typing import Dict, List, Optional
from biscuit_auth import Biscuit, KeyPair, Verifier, SymbolTable
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

# Configuration
console = Console()
TOKEN_STORAGE = "jetons.json"
KEYS_STORAGE = "keys.json"
FILES = ["file1", "file2", "file3"]

class CookiesChainError(Exception):
    """Exception personnalisée pour Cookies-Chain"""
    pass

class TokenManager:
    """Gestionnaire des jetons et clés"""
    
    def __init__(self):
        self.root_key = self._load_or_create_root_key()
        self.tokens = self._load_tokens()
    
    def _load_or_create_root_key(self) -> KeyPair:
        """Charge ou crée la clé racine"""
        if os.path.exists(KEYS_STORAGE):
            try:
                with open(KEYS_STORAGE, "r") as file:
                    key_data = json.load(file)
                    return KeyPair.from_private_key_der(bytes.fromhex(key_data["private_key"]))
            except Exception as e:
                console.print(f"[red]Erreur lors du chargement des clés: {e}[/red]")
                console.print("[yellow]Génération d'une nouvelle clé...[/yellow]")
        
        # Génération d'une nouvelle clé
        root_key = KeyPair.generate()
        key_data = {
            "private_key": root_key.private_key_der().hex(),
            "public_key": root_key.public_key_der().hex()
        }
        
        with open(KEYS_STORAGE, "w") as file:
            json.dump(key_data, file, indent=4)
        
        return root_key
    
    def _load_tokens(self) -> Dict[str, str]:
        """Charge les jetons depuis le fichier JSON"""
        if os.path.exists(TOKEN_STORAGE):
            try:
                with open(TOKEN_STORAGE, "r") as file:
                    return json.load(file)
            except Exception as e:
                console.print(f"[red]Erreur lors du chargement des jetons: {e}[/red]")
                return {}
        return {}
    
    def _save_tokens(self):
        """Sauvegarde les jetons dans le fichier JSON"""
        try:
            with open(TOKEN_STORAGE, "w") as file:
                json.dump(self.tokens, file, indent=4)
        except Exception as e:
            raise CookiesChainError(f"Erreur lors de la sauvegarde: {e}")
    
    def create_token(self, username: str) -> str:
        """Crée un jeton pour un utilisateur"""
        if username in self.tokens:
            raise CookiesChainError("Un jeton existe déjà pour cet utilisateur")
        
        try:
            builder = Biscuit.builder(self.root_key)
            builder.add_authority_fact(f'user("{username}")')
            
            # Permissions par défaut
            for file in FILES:
                builder.add_authority_fact(f'right("{file}", "read")')
                if file != "file3":  # file3 en lecture seule par défaut
                    builder.add_authority_fact(f'right("{file}", "write")')
            
            token = builder.build()
            token_str = token.serialize()
            self.tokens[username] = token_str
            self._save_tokens()
            return token_str
            
        except Exception as e:
            raise CookiesChainError(f"Erreur lors de la création du jeton: {e}")
    
    def verify_access(self, username: str, resource: str, operation: str) -> bool:
        """Vérifie l'accès d'un utilisateur à une ressource"""
        if username not in self.tokens:
            return False
        
        try:
            token = Biscuit.deserialize(self.tokens[username])
            verifier = Verifier(SymbolTable.default())
            verifier.add_fact(f'resource("{resource}")')
            verifier.add_fact(f'operation("{operation}")')
            
            verifier.allow(f'right($resource, $operation) <- resource($resource), operation($operation), right($resource, $operation)')
            verifier.deny(f'revoked_right($resource, $operation) <- resource($resource), operation($operation), revoked_right($resource, $operation)')
            
            result = token.verify(self.root_key.public(), verifier)
            return result.is_ok()
            
        except Exception as e:
            console.print(f"[red]Erreur lors de la vérification: {e}[/red]")
            return False
    
    def attenuate_token(self, username: str, resource: str, operation: str) -> str:
        """Atténue un jeton en supprimant une permission"""
        if username not in self.tokens:
            raise CookiesChainError("Aucun jeton trouvé pour cet utilisateur")
        
        try:
            token = Biscuit.deserialize(self.tokens[username])
            block = token.create_block()
            block.add_caveat(f'revoked_right("{resource}", "{operation}")')
            
            attenuated_token = token.append(block)
            token_str = attenuated_token.serialize()
            self.tokens[username] = token_str
            self._save_tokens()
            return token_str
            
        except Exception as e:
            raise CookiesChainError(f"Erreur lors de l'atténuation: {e}")
    
    def share_token(self, source_user: str, target_user: str, resource: str, operation: str):
        """Partage un jeton atténué avec un autre utilisateur"""
        if source_user not in self.tokens:
            raise CookiesChainError("Utilisateur source non trouvé")
        
        try:
            base_token = Biscuit.deserialize(self.tokens[source_user])
            block = base_token.create_block()
            block.add_caveat(f'revoked_right("{resource}", "{operation}")')
            
            shared_token = base_token.append(block)
            self.tokens[target_user] = shared_token.serialize()
            self._save_tokens()
            
        except Exception as e:
            raise CookiesChainError(f"Erreur lors du partage: {e}")

def clear_screen():
    """Efface l'écran de manière cross-platform"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    """Affiche l'en-tête du programme"""
    console.print(Panel.fit(
        "[bold blue]🍪 Cookies-Chain[/bold blue]\n"
        "[dim]Système de gestion d'accès basé sur Biscuit-Sec[/dim]",
        border_style="blue"
    ))

def display_users_table(token_manager: TokenManager):
    """Affiche la liste des utilisateurs sous forme de tableau"""
    if not token_manager.tokens:
        console.print("[yellow]Aucun utilisateur enregistré[/yellow]")
        return
    
    table = Table(title="👥 Utilisateurs")
    table.add_column("Nom d'utilisateur", style="cyan")
    table.add_column("Statut", style="green")
    
    for username in token_manager.tokens.keys():
        table.add_row(username, "✅ Actif")
    
    console.print(table)

def interactive_menu():
    """Menu interactif principal"""
    token_manager = TokenManager()
    
    while True:
        clear_screen()
        display_header()
        
        console.print("\n[bold]Menu principal:[/bold]")
        console.print("1. 👤 Créer un utilisateur")
        console.print("2. 🔍 Vérifier un accès")
        console.print("3. ⚠️  Atténuer un jeton")
        console.print("4. 👥 Afficher les utilisateurs")
        console.print("5. 🤝 Partager un jeton")
        console.print("6. 🚪 Quitter")
        
        choice = Prompt.ask("\nVotre choix", choices=["1", "2", "3", "4", "5", "6"])
        
        try:
            if choice == "1":
                username = Prompt.ask("Nom d'utilisateur")
                if username:
                    token_manager.create_token(username)
                    console.print(f"[green]✅ Utilisateur '{username}' créé avec succès![/green]")
                
            elif choice == "2":
                username = Prompt.ask("Nom d'utilisateur")
                if username not in token_manager.tokens:
                    console.print("[red]❌ Utilisateur non trouvé[/red]")
                else:
                    resource = Prompt.ask("Ressource", choices=FILES)
                    operation = Prompt.ask("Opération", choices=["read", "write"])
                    
                    if token_manager.verify_access(username, resource, operation):
                        console.print(f"[green]✅ Accès autorisé: {username} peut {operation} sur {resource}[/green]")
                    else:
                        console.print(f"[red]❌ Accès refusé: {username} ne peut pas {operation} sur {resource}[/red]")
            
            elif choice == "3":
                username = Prompt.ask("Nom d'utilisateur")
                if username not in token_manager.tokens:
                    console.print("[red]❌ Utilisateur non trouvé[/red]")
                else:
                    resource = Prompt.ask("Ressource à restreindre", choices=FILES)
                    operation = Prompt.ask("Opération à supprimer", choices=["read", "write"])
                    
                    token_manager.attenuate_token(username, resource, operation)
                    console.print(f"[green]✅ Droit '{operation}' supprimé pour {username} sur {resource}[/green]")
            
            elif choice == "4":
                display_users_table(token_manager)
            
            elif choice == "5":
                source_user = Prompt.ask("Utilisateur source")
                target_user = Prompt.ask("Utilisateur cible")
                resource = Prompt.ask("Ressource à restreindre", choices=FILES)
                operation = Prompt.ask("Opération à restreindre", choices=["read", "write"])
                
                token_manager.share_token(source_user, target_user, resource, operation)
                console.print(f"[green]✅ Jeton partagé avec {target_user}[/green]")
            
            elif choice == "6":
                console.print("[blue]👋 Au revoir![/blue]")
                break
                
        except CookiesChainError as e:
            console.print(f"[red]❌ Erreur: {e}[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Opération annulée[/yellow]")
        except Exception as e:
            console.print(f"[red]❌ Erreur inattendue: {e}[/red]")
        
        if choice != "6":
            input("\nAppuyez sur Entrée pour continuer...")

# Interface CLI avec Click
@click.group()
def cli():
    """🍪 Cookies-Chain - Système de gestion d'accès basé sur Biscuit-Sec"""
    pass

@cli.command()
@click.argument('username')
def create_user(username):
    """Crée un nouvel utilisateur"""
    token_manager = TokenManager()
    try:
        token_manager.create_token(username)
        console.print(f"[green]✅ Utilisateur '{username}' créé avec succès![/green]")
    except CookiesChainError as e:
        console.print(f"[red]❌ Erreur: {e}[/red]")

@cli.command()
@click.argument('username')
@click.argument('resource', type=click.Choice(FILES))
@click.argument('operation', type=click.Choice(['read', 'write']))
def verify(username, resource, operation):
    """Vérifie l'accès d'un utilisateur"""
    token_manager = TokenManager()
    if token_manager.verify_access(username, resource, operation):
        console.print(f"[green]✅ Accès autorisé[/green]")
    else:
        console.print(f"[red]❌ Accès refusé[/red]")

@cli.command()
def list_users():
    """Liste tous les utilisateurs"""
    token_manager = TokenManager()
    display_users_table(token_manager)

@cli.command()
def interactive():
    """Lance le mode interactif"""
    interactive_menu()

if __name__ == "__main__":
    cli()