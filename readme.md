## Visualiseur de Trames

## Introduction:

  Dans ce projet on se propose de programmer un visualisateur des flux de trafic réseau.
  Le visualisateur prendra en entrée un fichier trace au format texte contenant les octets capturés préalablement sur un réseau Ethernet.
  
  Notre visualisateur permet de visualiser en plus de :
		- Ethernet 
		- IP  
		- TCP 
		- HTTP

  Mais egalement : 
    - ARP 
		- UDP 
		- ICMP 
		- IGMP

  Avec un ensemble de filtre, vous pouvez les voir sur le fichier "howto.txt"

## Structure du Programme:

2 fichiers python : 
		- main_djerfaf_snaoui 
		- utils_djerfaf_snaoui

Nous avons opté pour la programmation fonctionnelle, et non pas la programmation orientée objet avec des classes.

Dans la programmation fonctionnelle, le but c'est de créer des fonctions dans chaque fichier python et l'appeler si nécessaire

Donc, dans le fichier main, vous trouvez toutes les fonctions qui construient l'interface graphique

et dans le fichier utils, vous trouver toutes les fonctions qui analysent les trames.