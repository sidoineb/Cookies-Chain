from setuptools import setup, find_packages

setup(
    name="cookies-chain",
    version="1.0.0",
    author="Votre Nom",
    author_email="votre.email@example.com",
    description="Système de gestion d'accès basé sur Biscuit-Sec",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/votre-username/cookies-chain",
    packages=find_packages(),
    install_requires=[
        "biscuit-auth>=2.0.0",
        "click>=8.0.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "cookies-chain=main:cli",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
)