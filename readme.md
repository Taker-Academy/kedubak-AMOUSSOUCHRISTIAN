[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/85swcNUK)
# KeDuBaK 🛟

![taker academy logo](https://github.com/Taker-Academy/KeDuBak/assets/86067803/e582b3de-3d1e-4ba4-9270-2a8e7f24382a)

## Contexte du projet 🪧

Les gars, c'est la merde...

6 mois se sont écoulés depuis votre première expérience chez KDF !

A la surprise général le projet n'a pas marché ! Cependant le PDG de KDF est un dur à cuire et a déja une nouvelle idée en tête !

Votre projet : KDB, une WebApp révolutionnaire qui va venir transformer la manière dont l'humain imaginait la communication et la sociabilisation sur internet. A ce titre, il sera présentée à la Paris Games Week dans 3 semaines.

Et un immense problème vient d'arriver. Vous faisiez votre bonhomme de chemin et après 6 mois d'absence mystérieuse, Stéphane a posé sa démission et s'est barré avec l'intégralité du code backend du nouveau projet... Vous aviez pourtant déjà terminé tout le front du site en attendant Stéphane, cependant, il ne reviendra jamais !

Vous êtes donc à présent lead, CTO et seul dev de ce projet nouvellement renommé KDB !

Vous êtes un peu con de rester, mais surtout obligé de devoir réaliser ce backend avant le rendez-vous avec les investisseurs dans 3 semaines.

## Objectif du projet 🎯

- Comprendre les bases de l'architecture d'une API
- Comprendre les bases de l'authentification
- Comprendre les bases de la sécurité
- Comprendre les bases de la gestion de base de données
- Comprendre les bases de la gestion de fichiers
- Construire une API RESTful
- Manipuler une base de données NoSQL
- Manipuler un ORM

## Frontend 🖥️

Vous avez déjà réalisé le frontend du site, vous pouvez le retrouver sur DockerHub ! 

Vous pouvez donc le récupérer et le lancer en local avec la commande suivante :

```bash
docker pull izimio/kdb-ui:taker-academy-ui-1.0.0
docker run -p 3000:3000 izimio/kdb-ui:taker-academy-ui-1.0.0
```

Cette commande va lancer le frontend sur le port 3000 de votre machine. Le site sera accessible à l'adresse suivante : `http://localhost:3000`


# Contraintes techniques 🛠️

> ⚠️  Pour communiquer avec le site, votre backend **DOIT** tourner sur le port `8080`

Afin de malgré tout faire honneur à la mémoire de Stéphane, vous allez devoir suivre quelques-unes de ses dernières volontés dans l'entreprise :

- L'API doit être asynchrone (pas de PHP RAW)
- La base de données sera une base de données NoSQL, MongoDB [MongoDB Atlas](https://cloud.mongodb.com/v2#/clusters)
- Le langage est libre : Go, TypeScript, Elixir, Python... Cela doit justement respecter la première règle.

Au fur et à mesure que vous compléterez votre API, vous verrez le site s'améliorer. Voici les critères d'utilisation nécessaires afin de valider le projet :

- Je peux créer un compte sur le site
- Je peux me connecter à mon compte sur le site.
- Je peux voir mes informations sur le site, dans la page "Profile".
- Je peux modifier mes informations sur le site, dans la page "Profile".
- Je peux supprimer mon compte sur le site, dans la page "Profile".
- J'ai accès la liste de tous mes posts dans la section "My Posts" dans la page "Profile".
- Je peux voir la listes des posts triés par ordre de date, le plus récent en premier, dans la page "Forum".
- Je peux up-vote un post dans la limite de 1 par minute.
- Je peux cliquer sur un post pour voir et poster des commentaires sur ce dernier.
- Je peux créer un post (titre + contenu) depuis la page d'accueil
- Je peux supprimer un post dont je suis l'auteur

## Ressources 📚

Dans la poubelle de Stéphane vous avez miraculeusement trouvé un [bout de papier](./doc.md) sur lequel il avait gribouillé l'ensemble de l'architecture des routes du backend !

- [MongoDB Atlas](https://cloud.mongodb.com/v2#/clusters)
- [RESTful API](https://restfulapi.net/)
- [MongoDB](https://docs.mongodb.com/)
- [Mongoose](https://mongoosejs.com/docs/guide.html)
- [JWT](https://jwt.io/)
- [Bcrypt](https://www.npmjs.com/package/bcrypt)
- [CRUD](https://en.wikipedia.org/wiki/Create,_read,_update_and_delete)

## Les livrables attendus 📦

- Votre **repository** avec le code source.

## Deadline ⏳

Vous avez jusqu'au **7 Avril 2024**, 23h42 pour rendre votre projet.


## Bon courage et bon code ! 💪
