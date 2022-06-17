Démonstrateur de signature de groupes (Français)
===

Le LINC met à disposition un démonstrateur de système de preuve d’âge pour permettre l’accès à certaines catégories de sites sans que ne soient partagées d’autres informations identifiantes. Vous trouverez plus d'information sur son fonctionnement dans l'article associé, disponible à l'adresse suivante :https://linc.cnil.fr/fr/demonstrateur-du-mecanisme-de-verification-de-lage-respectueux-de-la-vie-privee

Ce démonstrateur est publié sous [licence GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) et sous [licence ouverte 2.0](https://www.etalab.gouv.fr/wp-content/uploads/2017/04/ETALAB-Licence-Ouverte-v2.0.pdf) (explicitement compatible avec [CC-BY 4.0 FR](https://creativecommons.org/licenses/by/4.0/deed.fr)). Vous pouvez donc librement contribuer à son enrichissement. Il repose sur la bibliothèque  [Pairing-Based Cryptography](https://crypto.stanford.edu/pbc/)(PBC) publié sous licence [Licence publique générale GNU amoindrie](http://www.gnu.org/licenses/lgpl-3.0.html).

Les primitives cryptographiques de signature de groupe ont été conçues par Olivier Blazy(@Gloupin)du (@LIX_lab/@Polytechnique).

# Comment lancer ce démonstrateur

Le démonstrateur est associé à un fichier DockerFile afin de simplifier son déploiement. Celui-ci est également publié sur DockerHub. Par défaut, il nécessite l'accès au port 9091, 9092 et 9093.

Son lancement depuis la plateforme Docker nécessite l'usage du programme [Docker](https://docs.docker.com/get-docker/) et de s'authentifier à la plateforme.

Le lancement se déroulement depuis la commande suivante sur un terminal :
```bash
docker run -p 9091:9091 -p 9092:9092 -p 9093:9093 cnil/siggroup
```

Les différentes plateformes sont accessibles sur un navigeur aux adresses suivantes : https://localhost:9091/ (tiers de confiances), https://localhost:9092/ (sites à accès restreint), https://localhost:9092/ (autorité certificatrice).

La construction du docker en local nécessite dans un premier temps de construire l'image du docker :
```bash
docker build -t siggroup .
```

Puis de lancer ce docker :
```bash
docker run -p 9091:9091 -p 9092:9092 -p 9093:9093 siggroup
```

Pour lancer localement sans utiliser de docker:
- cp parameters.yaml.example parameters.yaml && $EDITOR parameters.yaml
- python3 initialisation.py
puis :
- python3 site.py
- python3 trust.py
- python3 authority.py

# Fonctionnement

Vous trouverez dans le fichier crypto.c une description complète de la cinématique d'échange des clefs : dans la fonction main, puis en découpe par fonctions pour les différentes entités.

La partie serveur.py contient un exemple d'échange de clef entre un tiers vérification et un site. Ce code dépend de bibliothèques C (libpbc.so.1 et crypto.s) pouvant être générées respectivement depuis le site https://crypto.stanford.edu/pbc/ et depuis le makefile de ce dossier. Le repertoire est également accompagné d'un DockerFile pour simplifier le déploiement.

L'ensemble des échanges de cette bibliothèque nécessite des paramètres d'initialisations communs stockés dans le fichier param.pbc.

L'ensemble des fonctions est conçu pour pouvoir fonctionner indépendamments tant que chaque fonction est associée au fichier de paramétrage initial (param.pbc).

## Contribuer

**Ce démonstrateur est disponible sous license GPLv3 et peut être enrichi par chacun des utilisateurs.** Les plus expérimentés peuvent améliorer cette version initiale de notre outil ou corriger d’éventuels bugs. N'oubliez pas de soumettre vos contributions via des pull-requests.

**Vous avez une idée que vous souhaitez partager avec nous pour améliorer ce projet ?** Contactez l’équipe du laboratoire CNIL par mail - ip(at)cnil.fr - ou via le compte Twitter [@LINCnil](https://twitter.com/LINCnil).

Pour de plus amples informations, voir le fichier ``LICENSE`` inclus.

## Remerciement

Ce démonstrateur est le fruit d'une collaboration entre le [LINC](https://linc.cnil.fr/), le [LIX](https://www.lix.polytechnique.fr) et le [PEReN](https://www.peren.gouv.fr/). 

Nous remercions tous les contributeurs qui nous ont permis de concrétiser ce projet :
Olivier Blazy
Solenn Brunet
Martin Bieri
Jérôme Gorin
Amandine Jambert
Côme Brocas
Vincent Toubiana
Et le Peren (Joris Dugépéroux, Victo Amblard, Lucas Verney)


English
===

LINC provides a proof of age system demonstrator to allow access to certain categories of sites without sharing other identifying information. You will find more information on how it works in the associated article, available at the following address: (link)

This demonstrator is published under GPLv3 license and under open license 2.0 (explicitly compatible with CC-BY 4.0 FR). You can therefore freely contribute to its enrichment.

# How to launch this demonstrator

The demonstrator is associated with a DockerFile to simplify its deployment. This one is also published on DockerHub. By default, it requires access to port 9091, 9092 and 9093.

Its launch from the Docker platform requires the use of the Docker program and authentication to the platform.

The launch takes place from the following command on a terminal:

docker run -p 9091:9091 -p 9092:9092 -p 9093:9093 cnil/siggroup
The various platforms are accessible on a browser at the following addresses: https://localhost:9091/ (trusted third parties), https://localhost:9092/ (restricted access sites), https://localhost:9092/ ( certification authority).

Building the docker locally requires first building the docker image:

docker build -t siggroup .
Then run this docker:

docker run -p 9091:9091 -p 9092:9092 -p 9093:9093 siggroup
To launch locally without using docker:

cp parameters.yaml.example parameters.yaml && $EDITOR parameters.yaml
python3 initialization.py then:
python3 site.py
python3 trust.py
python3 authority.py

# How it works

You will find in the crypto.c file a complete description of the key exchange kinematics: in the main function, then broken down by functions for the different entities.

The server.py part contains an example of key exchange between a third-party verification and a site. This code depends on C libraries (libpbc.so.1 and crypto.s) that can be generated respectively from the site https://crypto.stanford.edu/pbc/ and from the makefile of this folder. The directory also comes with a DockerFile to simplify deployment.

All of the exchanges in this library require common initialization parameters stored in the param.pbc file.

The set of functions is designed to be able to operate independently as long as each function is associated with the initial parameterization file (param.pbc).

# Contribute
This demonstrator is available under the terms of the GPLv3 license and can be enriched by any of its users.** The most experimented can improve this initial version of our tool or correct potential bugs. Don't forget to submit your contributions *via* pull-requests.

**You have an idea you wish to share with us to improve this project ?** Contact the team of the CNIL lab by mail - ip(at)cnil.fr - or *via* the Twitter account [@CNIL](https://twitter.com/CNIL).

For more information, see the `LICENSE` file included.