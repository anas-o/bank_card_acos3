# bank_card_acos3

This project was developed on ACOS3 Microprocessor Card and card reader by ACS Ltd.
![10983-images-acos3](https://user-images.githubusercontent.com/76595864/119166165-d5f84d80-ba4d-11eb-9171-eea32d99db67.png)

Reference manual guide :
[REF_ACOS3-24&64.pdf](https://github.com/anas-o/bank_card_acos3/files/6523759/REF_ACOS3-24.64.pdf)

1. Objectif :

Personnaliser une carte à puce en mettant dessus le titre du propriétaire de la carte (M, Mme, Melle) ainsi son nom prénom, le numéro de la carte et sa date de validité. Ses données seront mises dans un fichier, annexé à un autre fichier qui va contenir la signature (hachage MD5) de ces données cryptées par la clé privé de la banque. La clé publique de la banque est stockée dans un fichier spécifique. Le code PIN de la carte sera mis dans le fichier sécurité "Security File – FF03" de la carte à puce.

2. Structure de Fichier :

![Sans titre](https://user-images.githubusercontent.com/76595864/119165356-ee1b9d00-ba4c-11eb-92f7-bd897749bffa.jpg)
